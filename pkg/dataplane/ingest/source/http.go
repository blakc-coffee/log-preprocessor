package source

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/frame"
	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
)

// HTTP defaults.
const (
	DefaultHTTPMaxBody          = int64(1) << 30 // 1 GiB
	DefaultReadHeaderTimeout    = 10 * time.Second
	defaultHTTPShutdownDeadline = 5 * time.Second
)

// sourceIDPattern is what a path segment must match before it is used as a
// source_id. It is strict on purpose: the value arrives from the network, and
// although it never builds a filesystem path, it does become a metric label
// and a field on every record it produces.
var sourceIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// HTTPConfig configures the HTTP ingest listener.
type HTTPConfig struct {
	ID     string
	Listen string
	// DynamicSources allows POSTs to source ids that were not configured.
	// Off by default: an open endpoint that mints a new source per request is
	// an unbounded metric-label space and an easy way to pollute the corpus.
	DynamicSources bool
	// AllowedSources restricts which ids are accepted when DynamicSources is
	// false. Empty means only ID itself.
	AllowedSources []string

	MaxBody           int64
	MaxFrameBytes     int
	MaxOctetLen       int
	ReadHeaderTimeout time.Duration

	// Healthy reports whether the vault can still accept writes. /healthz
	// answers 503 when it returns false, which is what a load balancer and
	// `docker healthcheck` need.
	Healthy func() bool

	Now func() time.Time
	Log *slog.Logger
}

// HTTPSource accepts log data over HTTP.
//
//	POST /ingest/{source_id}?framing=lines|whole|octet|nul
//	GET  /healthz
//
// The body is streamed, so a chunked upload is framed and vaulted as it
// arrives rather than being buffered whole. The response is sent only after
// every record in the body is durable, which is what makes a 202 meaningful:
// a client that got one can delete its copy.
type HTTPSource struct {
	cfg     HTTPConfig
	ln      net.Listener
	srv     *http.Server
	allowed map[string]bool

	accepted atomic.Int64
	rejected atomic.Int64
}

var _ ingest.Source = (*HTTPSource)(nil)

// NewHTTP binds the listener immediately so Addr is available before Run.
func NewHTTP(cfg HTTPConfig) (*HTTPSource, error) {
	if cfg.ID == "" {
		return nil, errors.New("source: http source needs an id")
	}
	if cfg.Listen == "" {
		return nil, errors.New("source: http source needs a listen address")
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = DefaultHTTPMaxBody
	}
	if cfg.ReadHeaderTimeout <= 0 {
		cfg.ReadHeaderTimeout = DefaultReadHeaderTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, err
	}

	h := &HTTPSource{cfg: cfg, ln: ln, allowed: map[string]bool{cfg.ID: true}}
	for _, s := range cfg.AllowedSources {
		h.allowed[s] = true
	}
	return h, nil
}

// ID implements ingest.Source.
func (h *HTTPSource) ID() string { return h.cfg.ID }

// Addr is the bound address, useful when Listen asked for port 0.
func (h *HTTPSource) Addr() net.Addr { return h.ln.Addr() }

// Rejected counts requests refused for a bad source id, an oversize body or
// an unhealthy vault.
func (h *HTTPSource) Rejected() int64 { return h.rejected.Load() }

// Run serves until ctx is done.
func (h *HTTPSource) Run(ctx context.Context, sink ingest.Sink) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ingest/{source}", func(w http.ResponseWriter, r *http.Request) {
		h.handleIngest(ctx, sink, w, r)
	})
	mux.HandleFunc("GET /healthz", h.handleHealth)

	h.srv = &http.Server{
		Handler: mux,
		// Without this, a client that opens a connection and never finishes
		// its headers holds it indefinitely. It is the slow-loris defence for
		// the HTTP path, matching the idle timeout on the raw socket path.
		ReadHeaderTimeout: h.cfg.ReadHeaderTimeout,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	errCh := make(chan error, 1)
	go func() {
		err := h.srv.Serve(h.ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	// Let in-flight requests finish: each one may hold records that are
	// durable but whose response has not been sent, and a client that never
	// learns its upload succeeded will send it again.
	shutCtx, cancel := context.WithTimeout(context.Background(), defaultHTTPShutdownDeadline)
	defer cancel()
	_ = h.srv.Shutdown(shutCtx)
	<-errCh
	return nil
}

func (h *HTTPSource) handleHealth(w http.ResponseWriter, _ *http.Request) {
	if h.cfg.Healthy != nil && !h.cfg.Healthy() {
		http.Error(w, "vault unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(w, `{"status":"ok"}`)
}

// ingestResponse is the 202 body.
type ingestResponse struct {
	Accepted  int `json:"accepted"`
	Fragments int `json:"fragments"`
}

func (h *HTTPSource) handleIngest(ctx context.Context, sink ingest.Sink, w http.ResponseWriter, r *http.Request) {
	sourceID := r.PathValue("source")
	if !sourceIDPattern.MatchString(sourceID) {
		h.rejected.Add(1)
		// The rejected value is deliberately not echoed back: it is
		// attacker-controlled and would land in logs and in a browser.
		http.Error(w, "source id must match [A-Za-z0-9._-]{1,64}", http.StatusBadRequest)
		return
	}
	if !h.cfg.DynamicSources && !h.allowed[sourceID] {
		h.rejected.Add(1)
		http.Error(w, "unknown source id", http.StatusBadRequest)
		return
	}
	if h.cfg.Healthy != nil && !h.cfg.Healthy() {
		h.rejected.Add(1)
		http.Error(w, "vault unavailable", http.StatusServiceUnavailable)
		return
	}

	framing := r.URL.Query().Get("framing")
	if framing == "" {
		framing = "lines"
	}

	// MaxBytesReader turns an oversize body into an error at the read, rather
	// than after the whole thing has been accepted into memory.
	body := http.MaxBytesReader(w, r.Body, h.cfg.MaxBody)
	defer body.Close()

	st := sink.NewStream(sourceID)
	defer st.Close()

	n, frags, err := h.consume(ctx, st, sourceID, r.RemoteAddr, framing, body)
	if err != nil {
		h.finishWithError(w, sourceID, n, err)
		return
	}
	// Flush before responding: a 202 must mean durable, or a client that
	// deletes its copy on seeing one has been lied to.
	if err := st.Flush(ctx); err != nil {
		h.finishWithError(w, sourceID, n, err)
		return
	}

	h.accepted.Add(int64(n))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(ingestResponse{Accepted: n, Fragments: frags})
}

// consume frames and submits the body, returning how many records and how many
// of them were fragments.
func (h *HTTPSource) consume(ctx context.Context, st ingest.Stream, sourceID, peer, framing string, body io.Reader) (int, int, error) {
	if framing == "whole" {
		// The entire body is one record. Bounded by MaxBody, which
		// MaxBytesReader is already enforcing.
		raw, err := io.ReadAll(body)
		if err != nil {
			return 0, 0, err
		}
		rec := types.RawRecord{
			SourceID:   sourceID,
			ReceivedAt: h.cfg.Now().UTC(),
			Origin:     types.Origin{Kind: types.OriginHTTP, Addr: peer, Offset: 0},
			Term:       types.TermNone,
			Raw:        raw,
		}
		if err := st.Submit(ctx, rec); err != nil {
			return 0, 0, err
		}
		return 1, 0, nil
	}

	mode, err := httpFraming(framing)
	if err != nil {
		return 0, 0, err
	}
	dec, err := frame.New(mode, body, frame.Options{
		MaxFrameBytes: h.cfg.MaxFrameBytes,
		MaxOctetLen:   h.cfg.MaxOctetLen,
	})
	if err != nil {
		return 0, 0, err
	}

	n, frags := 0, 0
	for {
		fr, err := dec.Next()
		if errors.Is(err, io.EOF) {
			return n, frags, nil
		}
		if err != nil {
			return n, frags, err
		}
		if fr.Frag != types.FragNone {
			frags++
		}
		rec := types.RawRecord{
			SourceID:   sourceID,
			ReceivedAt: h.cfg.Now().UTC(),
			Origin: types.Origin{
				Kind: types.OriginHTTP, Addr: peer,
				// The offset within this body, so a client can correlate a
				// record with what it uploaded.
				Offset: fr.Offset,
			},
			Term: fr.Term,
			Frag: fr.Frag,
			Raw:  fr.Raw,
		}
		if err := st.Submit(ctx, rec); err != nil {
			return n, frags, err
		}
		n++
	}
}

func httpFraming(s string) (frame.Mode, error) {
	switch s {
	case "lines":
		return frame.ModeLines, nil
	case "octet":
		return frame.ModeOctet, nil
	case "nul":
		return frame.ModeNUL, nil
	}
	return "", fmt.Errorf("unknown framing %q: want lines, whole, octet or nul", s)
}

// finishWithError reports a failure part-way through a body.
//
// Records already submitted are durable and stay durable — they are not rolled
// back, because the vault is append-only and a record that was stored is a
// record that was received. The count is reported so a client retrying knows
// it will create duplicates, which Origin.Offset lets a consumer collapse.
func (h *HTTPSource) finishWithError(w http.ResponseWriter, sourceID string, stored int, err error) {
	h.rejected.Add(1)

	var maxErr *http.MaxBytesError
	status := http.StatusBadRequest
	switch {
	case errors.As(err, &maxErr):
		status = http.StatusRequestEntityTooLarge
	case errors.Is(err, types.ErrFailed), errors.Is(err, types.ErrClosed):
		status = http.StatusServiceUnavailable
	case errors.Is(err, context.Canceled):
		status = http.StatusServiceUnavailable
	}

	h.cfg.Log.Warn("ingest request failed",
		"source", sourceID, "stored_before_failure", stored, "status", status, "err", err)
	http.Error(w, http.StatusText(status), status)
}
