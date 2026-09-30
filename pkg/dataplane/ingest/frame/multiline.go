package frame

import (
	"errors"
	"io"
	"regexp"
	"sync"
	"time"

	types "github.com/blakc-coffee/sluice/pkg/types"
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
// # The timeout lives in the source, and this type is locked so it can
//
// PRD 5.2 flushes a partial record after a timeout. A decoder cannot implement
// that on its own: Next blocks on the reader, so it never notices time passing
// while it waits. The source owns the clock and calls FlushIfOlderThan from a
// separate goroutine, which is why every method here takes the mutex.
//
// Without the timeout, a record whose continuation never arrives is held
// forever: the last event before a source goes quiet is exactly the event
// someone is trying to read during an incident.
type Multiline struct {
	inner    Decoder
	start    *regexp.Regexp
	maxLines int
	max      int

	// now is the clock, replaced in tests.
	now func() time.Time

	mu sync.Mutex
	// pending is the record being accumulated.
	pending *Frame
	// startedAt is when the pending record's first line arrived.
	startedAt time.Time
	lines     int
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
	// Now is the clock used for the timeout. Zero means time.Now.
	Now func() time.Time
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
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Multiline{
		inner: inner, start: o.Start, maxLines: o.MaxLines,
		max: o.MaxFrameBytes, now: o.Now,
	}, nil
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
//
// The inner read happens OUTSIDE the lock, which is not an optimisation: Next
// blocks until a line arrives, and holding the mutex across that wait would
// make FlushIfOlderThan block for exactly as long — so the timeout could never
// fire on a source that has gone quiet, which is the only situation it exists
// for. The lock covers the state mutation and nothing else.
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

		m.mu.Lock()
		f, done := m.consume(line)
		m.mu.Unlock()
		if done {
			return f, nil
		}
	}
}

// consume folds one line into the record in progress. The caller holds m.mu.
// It reports whether a record is now complete.
func (m *Multiline) consume(line Frame) (Frame, bool) {
	if m.start.Match(line.Raw) {
		if m.pending == nil {
			m.begin(line)
			return Frame{}, false
		}
		// This line opens the next record, so the one in progress is
		// complete. Hold the line and hand back what we have.
		m.held = &line
		f, _ := m.flush()
		return f, true
	}

	if m.pending == nil {
		// A continuation with nothing to continue: the stream did not begin
		// at a record boundary, the pattern does not match this source, or a
		// timeout just released the record this line belonged to. Emit it
		// rather than discard it - guessing is how data goes missing.
		return line, true
	}

	// Append, carrying the previous line's terminator into the record.
	m.pending.Raw = append(m.pending.Raw, termBytes(m.pending.Term)...)
	m.pending.Raw = append(m.pending.Raw, line.Raw...)
	m.pending.Term = line.Term
	m.lines++

	if len(m.pending.Raw) >= m.max {
		return m.fragment(), true
	}
	if m.lines >= m.maxLines {
		f, _ := m.flush()
		return f, true
	}
	return Frame{}, false
}

// take returns the held line if there is one, otherwise reads from inner.
// The read is deliberately not under the lock; see Next.
func (m *Multiline) take() (Frame, error) {
	m.mu.Lock()
	if m.held != nil {
		f := *m.held
		m.held = nil
		m.mu.Unlock()
		return f, nil
	}
	err := m.err
	m.mu.Unlock()
	if err != nil {
		return Frame{}, err
	}

	f, innerErr := m.inner.Next()
	if innerErr != nil {
		m.mu.Lock()
		m.err = innerErr
		m.mu.Unlock()
		return Frame{}, innerErr
	}
	return f, nil
}

func (m *Multiline) begin(line Frame) {
	f := line
	f.Raw = append([]byte(nil), line.Raw...)
	m.pending = &f
	m.startedAt = m.now()
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

// Flush hands back the record in progress, if any. It is how shutdown
// releases a partial record.
func (m *Multiline) Flush() (Frame, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flush()
}

// FlushIfOlderThan hands back the record in progress only if its first line
// arrived more than d ago.
//
// This is the timeout the source drives. Checking the age here rather than in
// the source is what makes it correct under concurrency: the age and the
// decision to flush are read under the same lock, so a line arriving in
// between cannot produce a record that is flushed mid-append.
func (m *Multiline) FlushIfOlderThan(d time.Duration) (Frame, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil || m.now().Sub(m.startedAt) < d {
		return Frame{}, false
	}
	return m.flush()
}

// flush is Flush with the lock already held.
func (m *Multiline) flush() (Frame, bool) {
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
