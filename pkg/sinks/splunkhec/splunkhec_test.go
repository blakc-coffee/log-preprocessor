package splunkhec

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/dark-14100/sluice/pkg/types"
)

func TestStatusClassificationAndTokenFile(t *testing.T) {
	var auth, path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		path = r.URL.Path
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{URL: server.URL, TokenFile: token})
	if err != nil {
		t.Fatal(err)
	}
	err = s.Write(context.Background(), []types.NormalizedEvent{{EventID: "1.p@1"}})
	var he *HTTPError
	if !errors.As(err, &he) || he.Permanent || he.Status != 429 {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth != "Splunk secret" || path != "/services/collector/event" {
		t.Fatalf("auth/path = %q %q", auth, path)
	}
}
