package frame

import (
	"errors"
	"io"
	"regexp"

	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
)

// Multiline groups consecutive lines into one record.
//
// A line matching Start begins a new record; every line that does not match
// appends to the one in progress, **including the previous line's
// terminator**, so the record's bytes are exactly the bytes that were on the
// wire. A stack trace stored as eight separate records is eight events that
// nothing can correlate; stored as one it is a single event whose raw form
// still round-trips.
//
// testdata/multiline.log is generated against this, and gen.MultilineStart is
// the pattern that frames it. The manifest describes each event as one record
// with the internal newlines inside byte_start..byte_end, so a framer that
// split them would fail the round-trip test.
//
// # The timeout is not here
//
// PRD 5.2 also flushes a partial record after a timeout. That is deliberately
// the source's job, not the decoder's: Next blocks on the reader, so a decoder
// cannot notice time passing while it is waiting. The source drives a timer and
// calls Flush.
type Multiline struct {
	inner    Decoder
	start    *regexp.Regexp
	maxLines int
	max      int

	// pending is the record being accumulated.
	pending *Frame
	lines   int
	// held is a line already read from inner that begins the next record.
	held *Frame
	// cont marks that the pending record has already emitted a fragment.
	cont bool
	err  error
}

// MultilineOptions configures grouping.
type MultilineOptions struct {
	// Start matches the first line of a record. RE2 only - it comes from
	// config, but config is not a reason to allow catastrophic backtracking.
	Start *regexp.Regexp
	// MaxLines bounds one record. Zero means 500. Without it, a source whose
	// lines never match Start accumulates forever.
	MaxLines int
	// MaxFrameBytes bounds one record's bytes. Zero means DefaultMaxFrameBytes.
	MaxFrameBytes int
}

// NewMultiline wraps a line decoder with multiline grouping.
func NewMultiline(inner Decoder, o MultilineOptions) (*Multiline, error) {
	if o.Start == nil {
		return nil, errors.New("frame: multiline requires a Start pattern")
	}
	if o.MaxLines <= 0 {
		o.MaxLines = 500
	}
	if o.MaxFrameBytes <= 0 {
		o.MaxFrameBytes = DefaultMaxFrameBytes
	}
	return &Multiline{inner: inner, start: o.Start, maxLines: o.MaxLines, max: o.MaxFrameBytes}, nil
}

// termBytes is the on-the-wire spelling of a terminator, needed because a
// continuation line's predecessor keeps its terminator inside the record.
func termBytes(t types.Terminator) []byte {
	switch t {
	case types.TermLF:
		return []byte{'\n'}
	case types.TermCRLF:
		return []byte{'\r', '\n'}
	case types.TermNUL:
		return []byte{0}
	}
	return nil
}

// Next returns the next grouped record.
func (m *Multiline) Next() (Frame, error) {
	for {
		line, err := m.take()
		if err != nil {
			if errors.Is(err, io.EOF) {
				if f, ok := m.Flush(); ok {
					return f, nil
				}
			}
			return Frame{}, err
		}

		if m.start.Match(line.Raw) {
			if m.pending == nil {
				m.begin(line)
				continue
			}
			// This line opens the next record, so the one in progress is
			// complete. Hold the line and hand back what we have.
			m.held = &line
			f, _ := m.Flush()
			return f, nil
		}

		if m.pending == nil {
			// A continuation with nothing to continue: the stream did not
			// begin at a record boundary, or the pattern does not match this
			// source. Emit it rather than discard it - guessing is how data
			// goes missing silently.
			return line, nil
		}

		// Append, carrying the previous line's terminator into the record.
		m.pending.Raw = append(m.pending.Raw, termBytes(m.pending.Term)...)
		m.pending.Raw = append(m.pending.Raw, line.Raw...)
		m.pending.Term = line.Term
		m.lines++

		if len(m.pending.Raw) >= m.max {
			return m.fragment(), nil
		}
		if m.lines >= m.maxLines {
			f, _ := m.Flush()
			return f, nil
		}
	}
}

// take returns the held line if there is one, otherwise reads from inner.
func (m *Multiline) take() (Frame, error) {
	if m.held != nil {
		f := *m.held
		m.held = nil
		return f, nil
	}
	if m.err != nil {
		return Frame{}, m.err
	}
	f, err := m.inner.Next()
	if err != nil {
		m.err = err
		return Frame{}, err
	}
	return f, nil
}

func (m *Multiline) begin(line Frame) {
	f := line
	f.Raw = append([]byte(nil), line.Raw...)
	m.pending = &f
	m.lines = 1
	m.cont = false
}

// fragment emits max bytes of an over-long record and keeps the remainder.
func (m *Multiline) fragment() Frame {
	p := m.pending
	out := Frame{
		Raw:    p.Raw[:m.max:m.max],
		Term:   types.TermNone,
		Frag:   types.FragMore,
		Offset: p.Offset,
	}
	if m.cont {
		out.Frag |= types.FragCont
	}
	m.cont = true

	p.Raw = append([]byte(nil), p.Raw[m.max:]...)
	p.Offset += uint64(m.max)
	return out
}

// Flush hands back the record in progress, if any.
//
// The source calls this when the multiline timeout expires, so a record whose
// continuation never arrives is still stored rather than held forever. It is
// also how EOF and shutdown release a partial record.
func (m *Multiline) Flush() (Frame, bool) {
	if m.pending == nil {
		return Frame{}, false
	}
	f := *m.pending
	if m.cont {
		f.Frag |= types.FragCont
	}
	m.pending = nil
	m.lines = 0
	m.cont = false
	return f, true
}
