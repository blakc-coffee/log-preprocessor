// Package adminclient calls the data plane's admin API (:9000), either over
// HTTP or in process against an http.Handler (the mock, or
// app.AdminHandler() in the all-in-one binary).
//
// It is deliberately thin: the control plane passes most admin responses
// through unchanged, so the client returns status, headers and body, and
// classifies only the failures the UI must render differently: the admin
// being unreachable and the admin being too slow.
package adminclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"
)

// MaxBody caps how much of an admin response is read. The largest legitimate
// body is a raw record of about 1.5 MiB, base64 encoded.
const MaxBody = 16 << 20

// ErrUnreachable means no HTTP response came back: connection refused, DNS,
// reset. ErrTimeout means the per-call deadline passed first.
var (
	ErrUnreachable = errors.New("admin API unreachable")
	ErrTimeout     = errors.New("admin API timed out")
)

// Response is an admin reply.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// OK reports a 2xx status.
func (r *Response) OK() bool { return r.Status >= 200 && r.Status < 300 }

// Client calls one admin API.
type Client struct {
	base *url.URL
	hc   *http.Client
}

// New returns a client for an admin API at baseURL, for example
// http://127.0.0.1:9000.
func New(baseURL string) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("adminclient: invalid admin URL %q", baseURL)
	}
	// No proxy: the admin API is on loopback or a private network, and an
	// environment proxy must never see its traffic.
	tr := &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 16, IdleConnTimeout: 90 * time.Second}
	return &Client{base: u, hc: &http.Client{Transport: tr}}, nil
}

// NewInProcess returns a client that calls h directly.
func NewInProcess(h http.Handler) *Client {
	u, _ := url.Parse("http://admin.in-process")
	return &Client{base: u, hc: &http.Client{Transport: handlerTransport{h}}}
}

type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		t.h.ServeHTTP(rec, req)
	}()
	select {
	case <-done:
		return rec.Result(), nil
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
}

// Do sends one request. pathAndQuery starts with "/admin" or "/healthz".
// body, when non-nil, is sent as JSON. accept defaults to application/json.
func (c *Client) Do(ctx context.Context, timeout time.Duration, method, pathAndQuery string, body []byte, accept string) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+pathAndQuery, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if accept == "" {
		accept = "application/json"
	}
	req.Header.Set("Accept", accept)
	resp, err := c.hc.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w after %s: %s %s", ErrTimeout, timeout, method, pathAndQuery)
		}
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w after %s reading %s", ErrTimeout, timeout, pathAndQuery)
		}
		return nil, fmt.Errorf("%w: reading body: %v", ErrUnreachable, err)
	}
	if len(b) > MaxBody {
		return nil, fmt.Errorf("adminclient: %s response exceeds %d bytes", pathAndQuery, MaxBody)
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: b}, nil
}
