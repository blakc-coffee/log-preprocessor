package frame

import (
	"bytes"
	"strings"
	"testing"
)

// Framing benchmarks.
//
// These matter less than the vault's — an fsync is four orders of magnitude
// slower than finding a newline — but they bound what the framer can cost, and
// a regression here would be invisible in an end-to-end number that is
// dominated by disk.

// asaCorpus is a realistic input: ~140-byte syslog lines, which is what the
// fixture corpus averages.
func asaCorpus(lines int) []byte {
	var b bytes.Buffer
	for i := 0; i < lines; i++ {
		b.WriteString("<166>Sep 28 2026 09:00:01 asa01 : %ASA-6-302013: Built inbound TCP connection ")
		b.WriteString("1001 for outside:203.0.113.183/389 to inside:10.2.2.73/43857\n")
	}
	return b.Bytes()
}

func benchDecode(b *testing.B, mode Mode, in []byte) {
	b.ReportAllocs()
	b.SetBytes(int64(len(in)))
	b.ResetTimer()

	records := 0
	for i := 0; i < b.N; i++ {
		d, err := New(mode, bytes.NewReader(in), Options{})
		if err != nil {
			b.Fatal(err)
		}
		for {
			f, err := d.Next()
			if err != nil {
				break
			}
			records++
			_ = f.Raw
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(records)/float64(b.N), "records/op")
}

func BenchmarkFrameLF(b *testing.B)    { benchDecode(b, ModeLF, asaCorpus(1000)) }
func BenchmarkFrameLines(b *testing.B) { benchDecode(b, ModeLines, asaCorpus(1000)) }

func BenchmarkFrameCRLF(b *testing.B) {
	in := bytes.ReplaceAll(asaCorpus(1000), []byte("\n"), []byte("\r\n"))
	benchDecode(b, ModeCRLF, in)
}

func BenchmarkFrameOctet(b *testing.B) {
	var buf bytes.Buffer
	msg := "<166>Sep 28 2026 09:00:01 asa01 : %ASA-6-302013: Built inbound TCP connection 1001"
	for i := 0; i < 1000; i++ {
		buf.WriteString(itoaBench(len(msg)))
		buf.WriteByte(' ')
		buf.WriteString(msg)
	}
	benchDecode(b, ModeOctet, buf.Bytes())
}

func itoaBench(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for n > 0 {
		p--
		b[p] = byte('0' + n%10)
		n /= 10
	}
	return string(b[p:])
}

// BenchmarkFrameFragmenting measures the oversize path, which allocates a
// fresh buffer per fragment and is the one place framing does real work.
func BenchmarkFrameFragmenting(b *testing.B) {
	in := append(bytes.Repeat([]byte("x"), 64<<10), '\n')
	benchDecode(b, ModeLF, in)
}

// BenchmarkFrameOneByteReader is the pathological case: a reader that hands
// over one byte at a time, which is what a slow TCP client looks like. It
// bounds the cost of the compaction and growth logic in the read window.
func BenchmarkFrameOneByteReader(b *testing.B) {
	in := asaCorpus(200)
	b.ReportAllocs()
	b.SetBytes(int64(len(in)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d, err := New(ModeLF, &chunkReader{b: in, n: 1}, Options{})
		if err != nil {
			b.Fatal(err)
		}
		for {
			if _, err := d.Next(); err != nil {
				break
			}
		}
	}
}

var _ = strings.Repeat
