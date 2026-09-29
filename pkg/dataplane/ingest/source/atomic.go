package source

import "sync/atomic"

// atomic64 is a tiny named wrapper so counters read clearly at their call
// sites. It exists only until the Prometheus registry lands at M4.
type atomic64 struct{ v atomic.Int64 }

func (a *atomic64) add(n int64) { a.v.Add(n) }
func (a *atomic64) load() int64 { return a.v.Load() }
