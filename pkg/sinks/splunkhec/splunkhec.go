// Package splunkhec sends normalized events to Splunk HTTP Event Collector.
package splunkhec

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dark-14100/sluice/pkg/sinks"
	"github.com/dark-14100/sluice/pkg/sinks/internal/mapping"
	"github.com/dark-14100/sluice/pkg/sinks/spool"
	"github.com/dark-14100/sluice/pkg/types"
)

// Config contains HEC settings. TokenFile is required; inline secrets are not accepted.
type Config struct {
	URL, TokenFile, CAFile, Index string
	MaxBatchBytes                 int
	Client                        *http.Client
	DeadLetterDir                 string
}

// HTTPError classifies an HEC response. Permanent is true for non-429 4xx responses.
type HTTPError struct {
	Status    int
	Permanent bool
	Body      string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("splunkhec: HTTP %d: %s", e.Status, e.Body) }

// Retryable reports whether fan-out should retry this response.
func (e *HTTPError) Retryable() bool { return !e.Permanent }

// Sink is a batched HEC client.
type Sink struct {
	mu                     sync.Mutex
	endpoint, token, index string
	max                    int
	client                 *http.Client
	dead                   *spool.Queue
	closed                 bool
}

// New validates TLS and reads the HEC token from disk.
func New(cfg Config) (*Sink, error) {
	if cfg.URL == "" || cfg.TokenFile == "" {
		return nil, errors.New("splunkhec: URL and TokenFile are required")
	}
	token, err := os.ReadFile(cfg.TokenFile)
	if err != nil {
		return nil, err
	}
	if cfg.MaxBatchBytes <= 0 {
		cfg.MaxBatchBytes = 1 << 20
	}
	client := cfg.Client
	if client == nil {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.CAFile != "" {
			pem, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, err
			}
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("splunkhec: CA file contains no certificates")
			}
			tlsCfg.RootCAs = pool
		}
		client = &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	}
	var dead *spool.Queue
	if cfg.DeadLetterDir != "" {
		dead, err = spool.Open(spool.Config{Dir: cfg.DeadLetterDir})
		if err != nil {
			return nil, err
		}
	}
	return &Sink{endpoint: strings.TrimRight(cfg.URL, "/") + "/services/collector/event", token: strings.TrimSpace(string(token)), index: cfg.Index, max: cfg.MaxBatchBytes, client: client, dead: dead}, nil
}
func (s *Sink) Name() string { return "splunkhec" }
func (s *Sink) Write(ctx context.Context, batch []types.NormalizedEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return sinks.ErrClosed
	}
	var chunk bytes.Buffer
	var events []types.NormalizedEvent
	flush := func() error {
		if chunk.Len() == 0 {
			return nil
		}
		err := s.post(ctx, chunk.Bytes())
		if he := new(HTTPError); errors.As(err, &he) && he.Permanent && s.dead != nil {
			if qerr := s.dead.Enqueue(context.Background(), events); qerr != nil {
				return errors.Join(err, qerr)
			}
			chunk.Reset()
			events = nil
			return err
		}
		chunk.Reset()
		events = nil
		return err
	}
	for _, e := range batch {
		f := mapping.Extract(e)
		envelope := map[string]any{"time": float64(f.EventTime.UnixNano()) / 1e9, "host": f.Host, "source": e.SourceID, "sourcetype": "ulpf:uef", "index": s.index, "event": map[string]any{"event_id": e.EventID, "record_id": e.RecordID, "raw_sha256": e.RawSHA256, "vendor": e.Vendor, "product": e.Product, "parser": e.ParserID, "parser_version": e.ParserVersion, "ocsf": e.OCSF, "unmapped": e.Unmapped}}
		line, err := json.Marshal(envelope)
		if err != nil {
			return err
		}
		if len(line) > s.max {
			return fmt.Errorf("splunkhec: event %s exceeds max_batch_bytes", e.EventID)
		}
		if chunk.Len() > 0 && chunk.Len()+len(line) > s.max {
			if err = flush(); err != nil {
				return err
			}
		}
		chunk.Write(line)
		events = append(events, e)
	}
	return flush()
}
func (s *Sink) post(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Splunk "+s.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return &HTTPError{Status: resp.StatusCode, Permanent: resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests, Body: string(b)}
}
func (s *Sink) Flush(ctx context.Context) error { return ctx.Err() }
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.dead != nil {
		return s.dead.Close()
	}
	return nil
}
