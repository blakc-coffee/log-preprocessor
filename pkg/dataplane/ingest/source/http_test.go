package source_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/source"
	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

func startHTTP(t *testing.T, cfg source.HTTPConfig) (*source.HTTPSource, *harness, string) {
	t.Helper()
	if cfg.ID == "" {
		cfg.ID = "http"
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:0"
	}
	src, err := source.NewHTTP(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := start(t, src)
	return src, h, "http://" + src.Addr().String()
}

func post(t *testing.T, url string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestHTTPLines(t *testing.T) {
	_, h, base := startHTTP(t, source.HTTPConfig{ID: "asa-lab"})

	resp := post(t, base+"/ingest/asa-lab", strings.NewReader("alpha\nbeta\r\ngamma\n"))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var body struct {
		Accepted  int `json:"accepted"`
		Fragments int `json:"fragments"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Accepted != 3 {
		t.Errorf("response says %d accepted, want 3", body.Accepted)
	}

	got := h.waitFor(3)
	if diff := strings.Join(raws(got), ","); diff != "alpha,beta,gamma" {
		t.Errorf("got %q", diff)
	}
	// `lines` framing records which terminator each record actually had.
	if got[0].Term != types.TermLF || got[1].Term != types.TermCRLF {
		t.Errorf("terminators are %d,%d, want LF then CRLF", got[0].Term, got[1].Term)
	}
	for _, ev := range got {
		if ev.Origin.Kind != types.OriginHTTP {
			t.Errorf("record %d has origin kind %d, want HTTP", ev.ID, ev.Origin.Kind)
		}
		if ev.SourceID != "asa-lab" {
			t.Errorf("record %d has source %q", ev.ID, ev.SourceID)
		}
	}
}

// TestHTTPResponseMeansDurable is the contract behind the 202. A client that
// deletes its copy on seeing one must not be able to lose data, so every
// record in the body has to be readable from the vault by the time the
// response is written.
func TestHTTPResponseMeansDurable(t *testing.T) {
	_, h, base := startHTTP(t, source.HTTPConfig{ID: "durable"})

	resp := post(t, base+"/ingest/durable", strings.NewReader("one\ntwo\nthree\n"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d", resp.StatusCode)
	}

	// The response has already been received, so this must hold right now,
	// with no waiting.
	stored := 0
	if err := h.vault.Scan(context.Background(), 1, func(types.RawRecord, types.Receipt) error {
		stored++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if stored != 3 {
		t.Errorf("the 202 was sent with %d of 3 records durable", stored)
	}
}

func TestHTTPWholeBody(t *testing.T) {
	_, h, base := startHTTP(t, source.HTTPConfig{ID: "blob"})

	payload := "line one\nline two\n\x00binary\xff"
	resp := post(t, base+"/ingest/blob?framing=whole", strings.NewReader(payload))
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d", resp.StatusCode)
	}

	got := h.waitFor(1)
	if string(got[0].Raw) != payload {
		t.Errorf("got %q, want %q", got[0].Raw, payload)
	}
	if got[0].Term != types.TermNone {
		t.Errorf("whole-body record has terminator %d, want none", got[0].Term)
	}
}

// TestHTTPChunked: a streamed upload must be framed and vaulted as it arrives,
// not buffered whole. Sending with an unknown length forces chunked encoding.
func TestHTTPChunked(t *testing.T) {
	_, h, base := startHTTP(t, source.HTTPConfig{ID: "chunked"})

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		for i := 0; i < 50; i++ {
			fmt.Fprintf(pw, "chunked line %d\n", i)
		}
	}()

	resp := post(t, base+"/ingest/chunked", pr)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d", resp.StatusCode)
	}

	got := h.waitFor(50)
	for i := 0; i < 50; i++ {
		if want := fmt.Sprintf("chunked line %d", i); string(got[i].Raw) != want {
			t.Fatalf("record %d is %q, want %q", i, got[i].Raw, want)
		}
	}
}

func TestHTTPRejectsBadSourceID(t *testing.T) {
	src, _, base := startHTTP(t, source.HTTPConfig{ID: "ok"})

	for _, id := range []string{
		"has space", "has/slash", "..", strings.Repeat("x", 65), "semi;colon",
	} {
		resp := post(t, base+"/ingest/"+id, strings.NewReader("x\n"))
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusAccepted {
			t.Errorf("source id %q was accepted", id)
		}
		// The rejected value is attacker-controlled and must not be echoed
		// into a log or a browser.
		if bytes.Contains(body, []byte(id)) {
			t.Errorf("the response echoed the rejected source id %q back", id)
		}
	}
	if src.Rejected() == 0 {
		t.Error("rejections were not counted")
	}
}

func TestHTTPUnknownSourceNeedsDynamic(t *testing.T) {
	t.Run("closed by default", func(t *testing.T) {
		_, _, base := startHTTP(t, source.HTTPConfig{ID: "known"})
		resp := post(t, base+"/ingest/unknown", strings.NewReader("x\n"))
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status %d, want 400: an unconfigured source must not be minted silently", resp.StatusCode)
		}
	})

	t.Run("allowed when dynamic", func(t *testing.T) {
		_, h, base := startHTTP(t, source.HTTPConfig{ID: "known", DynamicSources: true})
		resp := post(t, base+"/ingest/brand-new-device", strings.NewReader("x\n"))
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if got := h.waitFor(1); got[0].SourceID != "brand-new-device" {
			t.Errorf("source is %q", got[0].SourceID)
		}
	})

	t.Run("explicit allow list", func(t *testing.T) {
		_, _, base := startHTTP(t, source.HTTPConfig{
			ID: "known", AllowedSources: []string{"site-a-fw"},
		})
		resp := post(t, base+"/ingest/site-a-fw", strings.NewReader("x\n"))
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Errorf("an allow-listed source was refused: %d", resp.StatusCode)
		}
	})
}

func TestHTTPBodyTooLarge(t *testing.T) {
	_, _, base := startHTTP(t, source.HTTPConfig{ID: "small", MaxBody: 64})

	resp := post(t, base+"/ingest/small", strings.NewReader(strings.Repeat("x", 4096)+"\n"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d, want 413", resp.StatusCode)
	}
}

// TestHTTPUnhealthyVault: when the vault is failed, the endpoint must refuse
// rather than accept records it cannot store.
func TestHTTPUnhealthyVault(t *testing.T) {
	healthy := false
	_, _, base := startHTTP(t, source.HTTPConfig{
		ID: "sick", Healthy: func() bool { return healthy },
	})

	resp := post(t, base+"/ingest/sick", strings.NewReader("x\n"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("ingest status %d, want 503", resp.StatusCode)
	}

	hr, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	hr.Body.Close()
	if hr.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("healthz status %d, want 503", hr.StatusCode)
	}

	healthy = true
	hr2, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	hr2.Body.Close()
	if hr2.StatusCode != http.StatusOK {
		t.Errorf("healthz status %d once healthy, want 200", hr2.StatusCode)
	}
}

func TestHTTPRejectsUnknownFraming(t *testing.T) {
	_, _, base := startHTTP(t, source.HTTPConfig{ID: "f"})
	resp := post(t, base+"/ingest/f?framing=telepathy", strings.NewReader("x\n"))
	resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted {
		t.Error("an unknown framing was accepted")
	}
}

func TestHTTPWrongMethodAndPath(t *testing.T) {
	_, _, base := startHTTP(t, source.HTTPConfig{ID: "m"})

	resp, err := http.Get(base + "/ingest/m")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted {
		t.Error("GET was accepted on the ingest endpoint")
	}

	resp2 := post(t, base+"/nope", strings.NewReader("x\n"))
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("unknown path returned %d, want 404", resp2.StatusCode)
	}
}

// TestHTTPRoundTripsAFixture is the end-to-end shape the PRD's manual smoke
// test uses: curl the whole ASA fixture at the endpoint and get every line
// back byte-exact.
func TestHTTPRoundTripsAFixture(t *testing.T) {
	const path = "../../../../testdata/sample/cisco_asa.log"
	body, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Skipf("no corpus: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")

	_, h, base := startHTTP(t, source.HTTPConfig{ID: "asa-lab"})
	resp := post(t, base+"/ingest/asa-lab", bytes.NewReader(body))
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d", resp.StatusCode)
	}

	got := h.waitFor(len(lines))
	if len(got) != len(lines) {
		t.Fatalf("ingested %d records, the file has %d lines", len(got), len(lines))
	}
	for i, line := range lines {
		if string(got[i].Raw) != line {
			t.Fatalf("record %d differs from the source line", i)
		}
	}
}
