package main

import "testing"

func TestParseWorkersAndQuantile(t *testing.T) {
	w, err := parseWorkers("1,2,8")
	if err != nil || len(w) != 3 || w[2] != 8 {
		t.Fatalf("workers=%v err=%v", w, err)
	}
	if got := quantile([]int64{9, 1, 5, 3, 7}, .5); got != 5 {
		t.Fatalf("median=%d", got)
	}
}
