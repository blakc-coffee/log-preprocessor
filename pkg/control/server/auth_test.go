package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCrossSiteWritesRefusedAndLoginCached(t *testing.T) {
	hash, err := HashPassword("alice-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "users")
	if err := os.WriteFile(path, []byte("alice:approver:"+hash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	users, err := LoadUsers(path)
	if err != nil {
		t.Fatal(err)
	}
	h := authMiddleware(users, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	do := func(hdr map[string]string) int {
		r := httptest.NewRequest("POST", "http://ui.example/api/proposals/x/approve", nil)
		r.SetBasicAuth("alice", "alice-passphrase")
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for name, c := range map[string]struct {
		hdr  map[string]string
		code int
	}{
		"no browser headers":    {nil, 200},
		"same origin":           {map[string]string{"Origin": "http://ui.example", "Sec-Fetch-Site": "same-origin"}, 200},
		"cross-site fetch":      {map[string]string{"Sec-Fetch-Site": "cross-site"}, 403},
		"foreign origin":        {map[string]string{"Origin": "http://evil.example"}, 403},
		"repeat (cached login)": {nil, 200},
	} {
		if got := do(c.hdr); got != c.code {
			t.Errorf("%s: status %d, want %d", name, got, c.code)
		}
	}
}

func TestAuth(t *testing.T) {
	hash := func(pw string) string {
		h, err := HashPassword(pw)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	path := filepath.Join(t.TempDir(), "users")
	if err := os.WriteFile(path, []byte("# users\nalice:approver:"+hash("alice-passphrase")+"\nbob:viewer:"+hash("bob-passphrase")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	users, err := LoadUsers(path)
	if err != nil {
		t.Fatal(err)
	}
	var seen string
	s := &Server{}
	h := authMiddleware(users, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = s.actor(r, "typed-name")
	}))
	do := func(method, target, user, pass string) int {
		seen = ""
		r := httptest.NewRequest(method, target, nil)
		if user != "" {
			r.SetBasicAuth(user, pass)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for _, c := range []struct {
		name, method, path, user, pass string
		code                           int
		actor                          string
	}{
		{"no credentials", "GET", "/api/events", "", "", 401, ""},
		{"wrong password", "GET", "/api/events", "alice", "nope", 401, ""},
		{"unknown user", "GET", "/api/events", "mallory", "alice-passphrase", 401, ""},
		{"health probe needs none", "GET", "/healthz", "", "", 200, "typed-name"},
		{"approver reads", "GET", "/api/events", "alice", "alice-passphrase", 200, "alice"},
		{"approver writes as herself, not the typed name", "POST", "/api/proposals/x/approve", "alice", "alice-passphrase", 200, "alice"},
		{"viewer reads", "GET", "/api/events", "bob", "bob-passphrase", 200, "bob"},
		{"viewer cannot write", "POST", "/api/proposals/x/approve", "bob", "bob-passphrase", 403, ""},
	} {
		if got := do(c.method, c.path, c.user, c.pass); got != c.code || seen != c.actor {
			t.Errorf("%s: status %d actor %q, want %d %q", c.name, got, seen, c.code, c.actor)
		}
	}
	if err := os.WriteFile(path, []byte("eve:root:x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadUsers(path); err == nil {
		t.Fatal("an unknown role must be refused")
	}
}
