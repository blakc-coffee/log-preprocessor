package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// The TUI must render what the control plane reports, switch tabs on keys, and refuse to
// approve anything but a pending proposal.
func TestTUIRendersAndNavigates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/telemetry" {
			_, _ = w.Write([]byte(`{"events_total":7,"quarantine_open":2,"lossless":{"last_verify_ok":true},"sources":[{"id":"asa","records":9,"eps":1.5}],"vault":{"records":9,"segments":1,"chain_head":"abc"}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := &tuiClient{base: srv.URL, http: srv.Client()}
	msg := get[telemetry](c, "/api/telemetry")()
	m := newModel(c)
	next, _ := m.Update(msg)
	m = next.(model)
	if v := m.View(); !strings.Contains(v, "asa") || !strings.Contains(v, "7 events parsed") {
		t.Fatalf("dashboard missing data:\n%s", v)
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("4")})
	m = next.(model)
	m.props = []proposal{{ID: "p1", Status: "approved"}}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	m = next.(model)
	if m.tab != tProps || m.mode == "confirm" {
		t.Fatalf("approve must not start on a non-pending proposal (tab=%d mode=%q)", m.tab, m.mode)
	}
}
