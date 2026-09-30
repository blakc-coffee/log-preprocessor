package store

import (
	"path/filepath"
	"testing"
	"time"
)

func BenchmarkPut(b *testing.B) {
	s, err := Open(filepath.Join(b.TempDir(), "s.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	at := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Put(ev(uint64(i+1), "a", "10.0.0.1", at))
	}
}
