// Package ocsfjson writes normalized events as idempotent OCSF NDJSON.
package ocsfjson

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/dark-14100/sluice/pkg/sinks"
	"github.com/dark-14100/sluice/pkg/sinks/internal/mapping"
	"github.com/dark-14100/sluice/pkg/types"
)

// RawProvider retrieves sacred vault bytes only when raw export is explicitly enabled.
type RawProvider func(context.Context, types.NormalizedEvent) ([]byte, error)

// Options configures the exporter. Raw export is disabled by default.
type Options struct {
	IncludeRaw  bool
	RawProvider RawProvider
}

// Sink writes one JSON object per line.
type Sink struct {
	mu     sync.Mutex
	w      io.Writer
	opt    Options
	seen   map[string]struct{}
	closed bool
}

// New constructs an OCSF NDJSON sink.
func New(w io.Writer, opt Options) *Sink {
	return &Sink{w: w, opt: opt, seen: make(map[string]struct{})}
}
func (s *Sink) Name() string { return "ocsfjson" }

// Write writes each EventID at most once for this sink instance.
func (s *Sink) Write(ctx context.Context, batch []types.NormalizedEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return sinks.ErrClosed
	}
	var buf bytes.Buffer
	ids := make([]string, 0, len(batch))
	pending := make(map[string]struct{}, len(batch))
	for _, e := range batch {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, ok := s.seen[e.EventID]; ok {
			continue
		}
		if _, ok := pending[e.EventID]; ok {
			continue
		}
		obj := mapping.CloneMap(e.OCSF)
		meta, _ := obj["metadata"].(map[string]any)
		if meta == nil {
			meta = map[string]any{}
		}
		meta["uid"] = e.EventID
		meta["original_time"] = mapping.Extract(e).EventTime.Format("2006-01-02T15:04:05.000000Z07:00")
		obj["metadata"] = meta
		obj["unmapped"] = e.Unmapped
		lineage := map[string]any{"record_id": e.RecordID, "raw_sha256": e.RawSHA256, "parser": e.ParserID, "parser_version": e.ParserVersion, "confidence": e.ParseConfidence, "integrity_flags": e.IntegrityFlags, "entities": e.Entities}
		if s.opt.IncludeRaw {
			if s.opt.RawProvider == nil {
				return fmt.Errorf("ocsfjson: include_raw requires RawProvider")
			}
			raw, err := s.opt.RawProvider(ctx, e)
			if err != nil {
				return err
			}
			obj["raw_data"] = base64.StdEncoding.EncodeToString(raw)
			lineage["raw_encoding"] = "base64"
		}
		obj["ulpf"] = lineage
		line, err := json.Marshal(obj)
		if err != nil {
			return fmt.Errorf("ocsfjson: marshal %s: %w", e.EventID, err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
		ids = append(ids, e.EventID)
		pending[e.EventID] = struct{}{}
	}
	if buf.Len() > 0 {
		if _, err := s.w.Write(buf.Bytes()); err != nil {
			return err
		}
	}
	for _, id := range ids {
		s.seen[id] = struct{}{}
	}
	return nil
}
func (s *Sink) Flush(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return sinks.ErrClosed
	}
	if f, ok := s.w.(interface{ Sync() error }); ok {
		return f.Sync()
	}
	return nil
}
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if c, ok := s.w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
