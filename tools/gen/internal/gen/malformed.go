package gen

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"time"
)

func malformedSource() *Source {
	return &Source{
		Name: "malformed.log", IDPrefix: "bad", Term: TermLF,
		Full: 100, Sample: 50, Emit: emitMalformed,
	}
}

// Malformed categories and their counts in the full profile. These records
// exist to prove the ingest and vault paths never interpret, repair or
// normalize what they are given: expect is "raw_only" throughout, and the only
// assertion is that the bytes come back identical.
const (
	badTruncated   = iota // a valid ASA line cut off mid-record
	badInvalidUTF8        // 0xFF 0xFE embedded in an otherwise valid ASA line
	badBinary             // non-text bytes
	badTrailingNUL        // a valid line followed by NUL padding
	badEmpty              // a zero-length record
	badBareCR             // bare CR inside an LF-terminated line
	badKinds
)

var badCounts = [badKinds]int{
	badTruncated:   20,
	badInvalidUTF8: 20,
	badBinary:      20,
	badTrailingNUL: 20,
	badEmpty:       10,
	badBareCR:      10,
}

// malformedPlan builds the interleaved category sequence for the full profile.
// The categories are shuffled rather than emitted in blocks so that any prefix
// of the file - in particular the 50-record sample profile - still contains a
// mix of all six. The shuffle draws a fixed number of values regardless of how
// many records are later emitted, which is what keeps the sample a byte-prefix
// of the full file.
func malformedPlan(rng *rand.Rand) []int {
	var plan []int
	for kind, n := range badCounts {
		for i := 0; i < n; i++ {
			plan = append(plan, kind)
		}
	}
	rng.Shuffle(len(plan), func(i, j int) { plan[i], plan[j] = plan[j], plan[i] })
	return plan
}

func emitMalformed(w *Writer, rng *rand.Rand, n int) {
	plan := malformedPlan(rng)
	if n > len(plan) {
		panic(fmt.Sprintf("gen: malformed.log asked for %d records, plan holds %d", n, len(plan)))
	}
	t := BaseTime

	for i := 0; i < n; i++ {
		t = t.Add(time.Duration(1+rng.IntN(3000)) * time.Millisecond)
		ts := t.Truncate(time.Second)
		e := Expect{Expect: "raw_only", Vendor: "unknown"}

		var raw []byte
		switch plan[i] {
		case badTruncated:
			line := asaLikeLine(rng, ts)
			// Cut somewhere inside the message body, never at zero length.
			raw = line[:20+rng.IntN(len(line)-20)]

		case badInvalidUTF8:
			line := asaLikeLine(rng, ts)
			at := 20 + rng.IntN(len(line)-20)
			raw = append(append(append([]byte{}, line[:at]...), 0xFF, 0xFE), line[at:]...)

		case badBinary:
			// Excluded bytes:
			//   0x0A, 0x0D - a framer splits on those, so including them would
			//     make this one record into several and the manifest would be
			//     describing something no reader can reproduce.
			//   0x00 - not for correctness, but so the six categories stay
			//     separable: the NUL-padding category is the only one that is
			//     supposed to contain NULs, and random noise that happened to
			//     roll one made that count non-deterministic to assert.
			raw = make([]byte, 16+rng.IntN(48))
			for j := range raw {
				b := byte(rng.IntN(256))
				for b == '\n' || b == '\r' || b == 0x00 {
					b = byte(rng.IntN(256))
				}
				raw[j] = b
			}

		case badTrailingNUL:
			raw = append(asaLikeLine(rng, ts), bytes.Repeat([]byte{0x00}, 1+rng.IntN(8))...)

		case badEmpty:
			// Zero-length record. Whether to drop these is downstream's call,
			// not ingest's.
			raw = []byte{}

		case badBareCR:
			line := asaLikeLine(rng, ts)
			at := 20 + rng.IntN(len(line)-20)
			raw = append(append(append([]byte{}, line[:at]...), '\r'), line[at:]...)
		}
		w.Emit(raw, "", e)
	}
}

// asaLikeLine returns a well-formed ASA line for the malformed emitters to
// damage, so that what is wrong with each record is exactly one thing.
func asaLikeLine(rng *rand.Rand, ts time.Time) []byte {
	out, in := publicIP(rng), privateIP(rng)
	rport, lport := servicePort(rng), ephemeralPort(rng)
	return []byte(fmt.Sprintf(
		"<166>%s asa01 : %%ASA-6-302013: Built inbound TCP connection %d for outside:%s/%d (%s/%d) to inside:%s/%d (%s/%d)",
		ts.Format("Jan _2 2006 15:04:05"), 1000+rng.IntN(9000),
		out, rport, out, rport, in, lport, in, lport))
}
