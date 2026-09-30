// Package frame turns a byte stream into records.
//
// It is the first thing that touches hostile input, and it is deliberately the
// dumbest component in the system: it finds record boundaries and does nothing
// else. It never interprets, trims, re-encodes, validates or repairs what it
// finds. Invalid UTF-8, NULs, control bytes and lone CRs all pass through
// untouched, because the vault's byte-exactness claim starts here.
//
// # The two rules
//
//  1. The terminator is recorded, never stored. A record's bytes are the
//     event's bytes and nothing else.
//  2. Nothing is ever truncated. A record longer than MaxFrameBytes is emitted
//     as consecutive fragments; concatenating their Raw restores it exactly.
//
// # Chunking invariance
//
// A decoder must produce identical output regardless of how the underlying
// reader chops the stream. One byte at a time, a megabyte at a time, or random
// sizes must all give the same frames. This is the property the tests hammer,
// because a framer that only works when reads happen to align is a framer that
// fails in production and passes in development.
package frame

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	types "github.com/dark-14100/sluice/pkg/types"
)

// Defaults. MaxFrameBytes matches limits.max_frame_bytes in the ingest config,
// and testdata/oversize.log pins the behaviour at exactly this boundary.
const (
	DefaultMaxFrameBytes = 1 << 20  // 1 MiB
	DefaultMaxOctetLen   = 16 << 20 // 16 MiB
	DefaultBufferSize    = 64 << 10 // 64 KiB
)

// Mode is a framing strategy.
type Mode string

// The framing modes.
const (
	// ModeLF splits on "\n" only. A lone "\r" is content, not a terminator -
	// which is what makes testdata/malformed.log's bare-CR records meaningful.
	ModeLF Mode = "lf"
	// ModeCRLF splits on "\r\n" only. A lone "\n" is content.
	ModeCRLF Mode = "crlf"
	// ModeLines splits on "\n" and drops one preceding "\r" if present,
	// recording which it was. This is what HTTP `?framing=lines` means.
	ModeLines Mode = "lines"
	// ModeNUL splits on a zero byte.
	ModeNUL Mode = "nul"
	// ModeOctet is RFC 6587 octet counting: "<length> <message>".
	ModeOctet Mode = "octet"
)

// Frame is one record as found in the stream.
//
// Raw is a fresh allocation the caller owns. Framing is not the hot loop -
// the fsync is - and handing out aliased buffers to a batching layer that
// holds up to 256 of them is how use-after-free bugs happen.
type Frame struct {
	Raw  []byte
	Term types.Terminator
	Frag types.Fragment
	// Offset is the position of Raw[0] within the stream, which becomes
	// Origin.Offset and is the de-duplication key for file sources.
	Offset uint64
}

// Options configures a decoder. The zero value uses the defaults above.
type Options struct {
	// MaxFrameBytes is the largest record emitted as a single frame. Longer
	// records are fragmented, never truncated.
	MaxFrameBytes int
	// MaxOctetLen caps the length an octet-counting header may declare.
	// Beyond it the stream is hostile and the connection should be closed.
	MaxOctetLen int
	// BufferSize is the initial read buffer. It grows on demand up to
	// MaxFrameBytes plus the delimiter, so idle connections stay cheap.
	BufferSize int
}

func (o *Options) setDefaults() {
	if o.MaxFrameBytes <= 0 {
		o.MaxFrameBytes = DefaultMaxFrameBytes
	}
	if o.MaxOctetLen <= 0 {
		o.MaxOctetLen = DefaultMaxOctetLen
	}
	if o.BufferSize <= 0 {
		o.BufferSize = DefaultBufferSize
	}
	if o.BufferSize > o.MaxFrameBytes {
		o.BufferSize = o.MaxFrameBytes
	}
}

// Framing errors. Everything here is recoverable by closing the connection;
// none of it should ever take the process down.
var (
	// ErrOctetLength means the declared length was zero or above MaxOctetLen.
	ErrOctetLength = errors.New("frame: octet length out of range")
	// ErrOctetMalformed means the octet-counting header was not digits
	// followed by a space.
	ErrOctetMalformed = errors.New("frame: malformed octet-counting header")
)

// Decoder produces frames from a stream.
type Decoder interface {
	// Next returns the next frame, or io.EOF when the stream is exhausted.
	// A partial record at EOF is returned with Term == TermNone rather than
	// being dropped.
	Next() (Frame, error)
}

// New returns a decoder for the given mode.
func New(mode Mode, r io.Reader, opts Options) (Decoder, error) {
	opts.setDefaults()
	switch mode {
	case ModeLF:
		return newDelim(r, opts, []byte("\n"), types.TermLF, false), nil
	case ModeCRLF:
		return newDelim(r, opts, []byte("\r\n"), types.TermCRLF, false), nil
	case ModeLines:
		return newDelim(r, opts, []byte("\n"), types.TermLF, true), nil
	case ModeNUL:
		return newDelim(r, opts, []byte{0}, types.TermNUL, false), nil
	case ModeOctet:
		return newOctet(r, opts), nil
	}
	return nil, fmt.Errorf("frame: unknown mode %q", mode)
}

// Detect chooses a framing for a syslog connection from its first bytes.
//
// RFC 6587 allows either octet counting or newline framing on the same port,
// so a listener has to guess. A message that starts with 1-6 ASCII digits
// followed by a space is octet counting; anything else is line framing.
//
// This is safe for syslog because a syslog message starts with "<PRI>", never
// a digit. It is NOT safe for arbitrary text - a CSV line beginning "12345 "
// would be misread - so non-syslog TCP sources must set the mode explicitly.
func Detect(peek []byte) Mode {
	for i, b := range peek {
		switch {
		case b >= '0' && b <= '9':
			if i >= 6 {
				return ModeLF // too many digits to be a length prefix
			}
		case b == ' ':
			if i == 0 {
				return ModeLF // a space with no digits before it
			}
			return ModeOctet
		default:
			return ModeLF
		}
	}
	// Ran out of bytes while still reading digits: not enough to decide, and
	// line framing is the safer default because it cannot consume the stream
	// on a wrong guess.
	return ModeLF
}

// ---------------------------------------------------------------- the source

// src is a growable read window over a stream.
type src struct {
	r   io.Reader
	buf []byte
	s   int    // start of the valid window
	e   int    // end of the valid window
	off uint64 // stream offset of buf[s]
	eof bool
	max int // hard cap on the buffer
}

func newSrc(r io.Reader, initial, max int) *src {
	if initial > max {
		initial = max
	}
	return &src{r: r, buf: make([]byte, initial), max: max}
}

func (d *src) window() []byte { return d.buf[d.s:d.e] }
func (d *src) buffered() int  { return d.e - d.s }

// take consumes n bytes from the front of the window and returns a copy.
func (d *src) take(n int) []byte {
	out := make([]byte, n)
	copy(out, d.buf[d.s:d.s+n])
	d.s += n
	d.off += uint64(n)
	return out
}

// skip consumes n bytes without copying them, for terminators.
func (d *src) skip(n int) {
	d.s += n
	d.off += uint64(n)
}

// errFull means the window is at its cap with no delimiter in sight. The
// delimiter decoders treat that as "this record is oversize" rather than as an
// error, which is how fragmentation bounds memory: a gigabyte-long line is
// never buffered.
var errFull = errors.New("frame: buffer full")

// fill reads more bytes, compacting and growing as needed. It returns io.EOF
// only when the stream is exhausted and nothing new was read.
func (d *src) fill() error {
	if d.eof {
		return io.EOF
	}
	if d.s > 0 {
		copy(d.buf, d.buf[d.s:d.e])
		d.e -= d.s
		d.s = 0
	}
	if d.e == len(d.buf) {
		if len(d.buf) >= d.max {
			return errFull
		}
		n := len(d.buf) * 2
		if n > d.max {
			n = d.max
		}
		grown := make([]byte, n)
		copy(grown, d.buf[:d.e])
		d.buf = grown
	}

	n, err := d.r.Read(d.buf[d.e:])
	d.e += n
	switch {
	case err == io.EOF:
		d.eof = true
		if n == 0 {
			return io.EOF
		}
		return nil
	case err != nil:
		return err
	}
	return nil
}

// ------------------------------------------------------------ delimiter mode

type delimDecoder struct {
	src   *src
	delim []byte
	term  types.Terminator
	// stripCR makes a "\r" immediately before the "\n" part of the terminator
	// rather than part of the record. Only ModeLines sets it.
	stripCR bool
	max     int
	// cont is set once a fragment has been emitted for the current record, so
	// the next one is marked FragCont.
	cont bool
}

func newDelim(r io.Reader, o Options, delim []byte, term types.Terminator, stripCR bool) *delimDecoder {
	// The window must hold a full frame plus enough lookahead to see whether
	// a delimiter follows it.
	max := o.MaxFrameBytes + len(delim)
	return &delimDecoder{
		src: newSrc(r, o.BufferSize, max), delim: delim,
		term: term, stripCR: stripCR, max: o.MaxFrameBytes,
	}
}

func (d *delimDecoder) Next() (Frame, error) {
	for {
		w := d.src.window()

		if i := bytes.Index(w, d.delim); i >= 0 {
			if i <= d.max {
				return d.emitTerminated(i), nil
			}
			// The delimiter is beyond the frame limit, so the record is
			// oversize: hand back the first max bytes and come back for the
			// rest.
			return d.emitFragment(), nil
		}

		// No delimiter yet. If the window already covers every index a
		// delimiter could have started at within the limit, the record is
		// oversize and can be fragmented without waiting for more input.
		if d.src.buffered() >= d.max+len(d.delim) {
			return d.emitFragment(), nil
		}

		err := d.src.fill()
		switch {
		case err == nil:
			continue
		case errors.Is(err, errFull):
			// Window at its cap with no delimiter: definitely oversize.
			return d.emitFragment(), nil
		case errors.Is(err, io.EOF):
			return d.emitAtEOF()
		default:
			return Frame{}, err
		}
	}
}

// emitTerminated hands back a record whose delimiter was found at index i.
func (d *delimDecoder) emitTerminated(i int) Frame {
	off := d.src.off
	n, term := i, d.term
	if d.stripCR && n > 0 && d.src.buf[d.src.s+n-1] == '\r' {
		n--
		term = types.TermCRLF
	}

	raw := d.src.take(n)
	// Skip whatever of the terminator remains: the stripped CR is already
	// behind us, the delimiter itself is not.
	d.src.skip(i - n + len(d.delim))

	f := Frame{Raw: raw, Term: term, Offset: off}
	if d.cont {
		f.Frag |= types.FragCont
		d.cont = false
	}
	return f
}

// emitFragment hands back exactly max bytes of a record that is longer.
func (d *delimDecoder) emitFragment() Frame {
	off := d.src.off
	raw := d.src.take(d.max)

	f := Frame{Raw: raw, Term: types.TermNone, Frag: types.FragMore, Offset: off}
	if d.cont {
		f.Frag |= types.FragCont
	}
	d.cont = true
	return f
}

// emitAtEOF deals with whatever is left when the stream ends without a
// terminator. It is never dropped: an unterminated last line is a record with
// Term == TermNone.
func (d *delimDecoder) emitAtEOF() (Frame, error) {
	n := d.src.buffered()
	if n == 0 {
		return Frame{}, io.EOF
	}
	if n > d.max {
		return d.emitFragment(), nil
	}

	off := d.src.off
	raw := d.src.take(n)
	f := Frame{Raw: raw, Term: types.TermNone, Offset: off}
	if d.cont {
		f.Frag |= types.FragCont
		d.cont = false
	}
	return f, nil
}

// ---------------------------------------------------------------- octet mode

type octetDecoder struct {
	src *src
	max int
	// remaining is how much of the current message is still unread, which is
	// what lets an oversize message stream through in fragments instead of
	// being buffered whole.
	remaining int
	cont      bool
	maxOctet  int
}

func newOctet(r io.Reader, o Options) *octetDecoder {
	// The window only ever needs to hold one frame plus a length header.
	return &octetDecoder{
		src: newSrc(r, o.BufferSize, o.MaxFrameBytes+32),
		max: o.MaxFrameBytes, maxOctet: o.MaxOctetLen,
	}
}

func (d *octetDecoder) Next() (Frame, error) {
	if d.remaining == 0 {
		if err := d.readHeader(); err != nil {
			return Frame{}, err
		}
	}

	// Wait for either the rest of the message or a full frame's worth.
	want := d.remaining
	if want > d.max {
		want = d.max
	}
	for d.src.buffered() < want {
		err := d.src.fill()
		if errors.Is(err, errFull) {
			break // the window holds a full frame already
		}
		if errors.Is(err, io.EOF) {
			if d.src.buffered() == 0 {
				return Frame{}, io.ErrUnexpectedEOF
			}
			// A declared length the sender never delivered. Keep what did
			// arrive rather than discarding it, and report the truncation by
			// leaving the fragment flags set.
			break
		}
		if err != nil {
			return Frame{}, err
		}
	}

	n := want
	if got := d.src.buffered(); got < n {
		n = got
	}
	off := d.src.off
	raw := d.src.take(n)
	d.remaining -= n

	// Octet counting has no terminator byte: the length is the delimiter.
	f := Frame{Raw: raw, Term: types.TermNone, Offset: off}
	if d.cont {
		f.Frag |= types.FragCont
	}
	if d.remaining > 0 {
		f.Frag |= types.FragMore
		d.cont = true
	} else {
		d.cont = false
	}
	return f, nil
}

// readHeader consumes "<digits> " and sets remaining.
func (d *octetDecoder) readHeader() error {
	const maxDigits = 10 // enough for any length up to MaxOctetLen

	for {
		w := d.src.window()
		if i := bytes.IndexByte(w, ' '); i >= 0 {
			if i == 0 || i > maxDigits {
				return fmt.Errorf("%w: %d digits before the space", ErrOctetMalformed, i)
			}
			n := 0
			for _, c := range w[:i] {
				if c < '0' || c > '9' {
					return fmt.Errorf("%w: %q is not a length", ErrOctetMalformed, w[:i])
				}
				n = n*10 + int(c-'0')
				if n > d.maxOctet {
					return fmt.Errorf("%w: declared %d, cap is %d", ErrOctetLength, n, d.maxOctet)
				}
			}
			if n == 0 {
				return fmt.Errorf("%w: declared zero", ErrOctetLength)
			}
			d.src.skip(i + 1)
			d.remaining = n
			return nil
		}

		// No space yet. Reject early rather than buffering an unbounded run
		// of digits from a hostile sender.
		if len(w) > maxDigits {
			return fmt.Errorf("%w: no space within %d bytes", ErrOctetMalformed, maxDigits)
		}
		for _, c := range w {
			if c < '0' || c > '9' {
				return fmt.Errorf("%w: %q is not a digit", ErrOctetMalformed, string(c))
			}
		}

		err := d.src.fill()
		if errors.Is(err, io.EOF) {
			if d.src.buffered() == 0 {
				return io.EOF // clean end between messages
			}
			return fmt.Errorf("%w: stream ended inside the length header", ErrOctetMalformed)
		}
		if errors.Is(err, errFull) {
			return fmt.Errorf("%w: no space in the length header", ErrOctetMalformed)
		}
		if err != nil {
			return err
		}
	}
}
