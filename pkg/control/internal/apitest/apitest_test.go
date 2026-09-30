package apitest

import (
	"testing"

	"github.com/blakc-coffee/sluice/contracts"
)

// recorder captures a Fatalf instead of stopping the test, so the negative
// cases can assert that the validator really rejects.
type recorder struct {
	testing.TB
	failed bool
}

func (r *recorder) Helper()               {}
func (r *recorder) Fatalf(string, ...any) { r.failed = true; panic(r) }

func rejects(t *testing.T, f func(tb testing.TB)) (failed bool) {
	r := &recorder{TB: t}
	defer func() {
		if p := recover(); p != nil && p != r {
			panic(p)
		}
		failed = r.failed
	}()
	f(r)
	return
}

func TestGoldensPassAndViolationsFail(t *testing.T) {
	k := Load(t)
	tel, _ := contracts.Golden("telemetry")
	k.Response(t, "GET", "/admin/telemetry", 200, tel)

	if !rejects(t, func(tb testing.TB) { k.Response(tb, "GET", "/admin/telemetry", 200, []byte(`{"eps_1m": 1}`)) }) {
		t.Fatal("a telemetry body missing required fields was accepted")
	}
	if !rejects(t, func(tb testing.TB) {
		k.Response(tb, "GET", "/admin/events", 200, []byte(`{"events": [{"event_id": "x"}], "next_cursor": null, "max_seq": 0}`))
	}) {
		t.Fatal("an event list with an invalid event was accepted")
	}
	if !rejects(t, func(tb testing.TB) { k.Response(tb, "GET", "/admin/nope", 200, []byte(`{}`)) }) {
		t.Fatal("a route the contract does not define was accepted")
	}
	notFound, _ := contracts.Golden("error")
	k.Response(t, "GET", "/admin/events/{event_id}", 404, notFound)
}
