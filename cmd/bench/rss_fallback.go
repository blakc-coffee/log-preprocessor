package main

import "runtime"

func fallbackMemory() (int64, string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.Sys), "runtime.MemStats.Sys (RSS unavailable)"
}
