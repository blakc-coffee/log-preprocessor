package gen

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"time"
)

// MaxFrameBytes is the default `limits.max_frame_bytes`. Records longer than
// this are split into fragments by the framer; they are never truncated.
// oversize.log's expected_fragments in the manifest is computed against this
// value, so changing one means regenerating the corpus.
const MaxFrameBytes = 1 << 20 // 1 MiB

// oversizeSizes are the three record lengths, chosen to sit either side of the
// fragmentation boundary: comfortably under, exactly on it, and over.
var oversizeSizes = []int{70 << 10, MaxFrameBytes, MaxFrameBytes + MaxFrameBytes/2}

func oversizeSource() *Source {
	return &Source{
		Name: "oversize.log", IDPrefix: "big", Term: TermLF,
		// Excluded from the sample profile on purpose: the sample set exists so
		// the other workstreams can clone something small and start, and 2.6 MiB
		// of padding would defeat that. The full corpus carries it.
		Full: len(oversizeSizes), Sample: 0, Emit: emitOversize,
	}
}

// expectedFragments is how many fragments a record of n bytes becomes at
// MaxFrameBytes.
//
// A record of exactly MaxFrameBytes is one record, not two. The framer only
// flushes a full buffer once it knows more content follows, so a buffer that
// fills exactly as the terminator arrives is emitted whole. Without that
// one-byte lookahead the boundary case would produce a trailing zero-length
// FragCont fragment, which is a worse thing to have to explain than a byte of
// lookahead.
func expectedFragments(n int) int {
	if n <= MaxFrameBytes {
		return 1
	}
	return (n + MaxFrameBytes - 1) / MaxFrameBytes
}

func emitOversize(w *Writer, rng *rand.Rand, n int) {
	t := BaseTime
	for i := 0; i < n && i < len(oversizeSizes); i++ {
		t = t.Add(time.Duration(1+rng.IntN(3000)) * time.Millisecond)
		ts := t.Truncate(time.Second)

		src, dst := privateIP(rng), publicIP(rng)
		sport, dport := ephemeralPort(rng), servicePort(rng)
		size := oversizeSizes[i]

		// A real oversize line is a normal event with one runaway field, not
		// noise, so the head stays parseable and only the payload is huge.
		head := fmt.Sprintf(
			"<166>%s asa01 : %%ASA-6-106100: access-list outside_access_in permitted tcp outside/%s(%d) -> inside/%s(%d) hit-cnt 1 first hit payload=",
			ts.Format("Jan _2 2006 15:04:05"), dst, dport, src, sport)

		raw := make([]byte, 0, size)
		raw = append(raw, head...)
		raw = append(raw, bytes.Repeat([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"), 1+(size-len(head))/36)...)
		raw = raw[:size]

		w.Emit(raw, "", Expect{
			Expect: "raw_only", Vendor: "cisco_asa", Time: ts,
			SrcIP: dst, SrcPort: dport, DstIP: src, DstPort: sport,
			Proto: "tcp", Action: "permitted",
			Fragments: expectedFragments(size),
		})
	}
}
