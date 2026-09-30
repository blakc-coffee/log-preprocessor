// Package ecs exports normalized events using an ECS-compatible NDJSON subset.
package ecs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/blakc-coffee/sluice/pkg/sinks"
	"github.com/blakc-coffee/sluice/pkg/sinks/internal/mapping"
	"github.com/blakc-coffee/sluice/pkg/types"
)

// RawProvider retrieves vault bytes for explicit raw export.
type RawProvider func(context.Context, types.NormalizedEvent) ([]byte, error)

// Options configures ECS output.
type Options struct {
	Bulk        bool
	Index       string
	IncludeRaw  bool
	RawProvider RawProvider
}

// Sink writes ECS documents and optional bulk action lines.
type Sink struct {
	mu     sync.Mutex
	w      io.Writer
	opt    Options
	seen   map[string]struct{}
	closed bool
}

// New constructs an ECS sink.
func New(w io.Writer, opt Options) *Sink { return &Sink{w: w, opt: opt, seen: map[string]struct{}{}} }
func (s *Sink) Name() string             { return "ecs" }
func (s *Sink) Write(ctx context.Context, batch []types.NormalizedEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return sinks.ErrClosed
	}
	var out bytes.Buffer
	var ids []string
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
		f := mapping.Extract(e)
		doc := map[string]any{"@timestamp": f.EventTime, "event": map[string]any{"category": []string{"network"}, "kind": "event", "type": []string{"connection"}, "action": f.Action, "outcome": f.Outcome, "id": e.EventID, "dataset": e.SourceID, "module": "ulpf"}, "source": map[string]any{"ip": f.SrcIP, "port": f.SrcPort}, "destination": map[string]any{"ip": f.DstIP, "port": f.DstPort}, "network": map[string]any{"transport": f.Protocol, "bytes": f.BytesIn + f.BytesOut}, "observer": map[string]any{"vendor": e.Vendor, "product": e.Product}, "user": map[string]any{"name": f.User}, "host": map[string]any{"name": f.Host}, "labels": map[string]any{"ulpf_record_id": e.RecordID, "ulpf_raw_sha256": e.RawSHA256, "ulpf_parser": e.ParserID, "ulpf_parser_version": e.ParserVersion, "ulpf_confidence": e.ParseConfidence}, "tags": e.IntegrityFlags}
		if s.opt.IncludeRaw {
			if s.opt.RawProvider == nil {
				return fmt.Errorf("ecs: include_raw requires RawProvider")
			}
			raw, err := s.opt.RawProvider(ctx, e)
			if err != nil {
				return err
			}
			doc["event"].(map[string]any)["original"] = base64.StdEncoding.EncodeToString(raw)
			doc["labels"].(map[string]any)["ulpf_raw_encoding"] = "base64"
		}
		if s.opt.Bulk {
			idx := s.opt.Index
			if idx == "" {
				idx = "ulpf"
			}
			action, _ := json.Marshal(map[string]any{"index": map[string]any{"_index": idx, "_id": e.EventID}})
			out.Write(action)
			out.WriteByte('\n')
		}
		line, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		out.Write(line)
		out.WriteByte('\n')
		ids = append(ids, e.EventID)
		pending[e.EventID] = struct{}{}
	}
	if out.Len() > 0 {
		if _, err := s.w.Write(out.Bytes()); err != nil {
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
