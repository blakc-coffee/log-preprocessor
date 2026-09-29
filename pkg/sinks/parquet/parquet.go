// Package parquet owns Apache Parquet encoding, lake partitioning, and atomic
// rollover.
package parquet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/sinks"
	"github.com/blakc-coffee/log-preprocessor/pkg/sinks/internal/mapping"
	"github.com/blakc-coffee/log-preprocessor/pkg/types"
	parquetgo "github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/compress/zstd"
)

// Row is the typed, map-free lake schema. ExtrasJSON retains all fields not
// represented by typed columns.
type Row struct {
	EventID         string    `json:"event_id" parquet:"event_id,dict"`
	RecordID        int64     `json:"record_id" parquet:"record_id,delta"`
	Segment         int64     `json:"segment" parquet:"segment,delta"`
	RawSHA256       [32]byte  `json:"raw_sha256" parquet:"raw_sha256"`
	SourceID        string    `json:"source_id" parquet:"source_id,dict"`
	Vendor          string    `json:"vendor" parquet:"vendor,dict"`
	Product         string    `json:"product" parquet:"product,dict"`
	ParserID        string    `json:"parser_id" parquet:"parser_id,dict"`
	ParserVersion   string    `json:"parser_version" parquet:"parser_version,dict"`
	TemplateID      string    `json:"template_id" parquet:"template_id,dict"`
	EventTime       time.Time `json:"event_time" parquet:"event_time,timestamp(microsecond),delta"`
	ReceivedAt      time.Time `json:"received_at" parquet:"received_at,timestamp(microsecond),delta"`
	SeverityID      int32     `json:"severity_id" parquet:"severity_id,dict"`
	ActionID        int32     `json:"action_id" parquet:"action_id,dict"`
	ActivityID      int32     `json:"activity_id" parquet:"activity_id,dict"`
	ClassUID        int32     `json:"class_uid" parquet:"class_uid,dict"`
	SrcIP           string    `json:"src_ip" parquet:"src_ip,dict"`
	DstIP           string    `json:"dst_ip" parquet:"dst_ip,dict"`
	SrcPort         int32     `json:"src_port" parquet:"src_port,dict"`
	DstPort         int32     `json:"dst_port" parquet:"dst_port,dict"`
	Proto           string    `json:"proto" parquet:"proto,dict"`
	BytesIn         int64     `json:"bytes_in" parquet:"bytes_in,delta"`
	BytesOut        int64     `json:"bytes_out" parquet:"bytes_out,delta"`
	User            string    `json:"user" parquet:"user,dict"`
	Host            string    `json:"host" parquet:"host,dict"`
	Confidence      float32   `json:"confidence" parquet:"confidence"`
	IntegrityFlags  []string  `json:"integrity_flags" parquet:"integrity_flags,list"`
	TimeFromReceipt bool      `json:"time_from_receipt" parquet:"time_from_receipt"`
	Current         bool      `json:"current" parquet:"current"`
	ExtrasJSON      string    `json:"extras_json" parquet:"extras_json,json"`
}

// Encoder writes valid Apache Parquet bytes to w. Implementations must return
// only after all rows have been encoded.
type Encoder func(w io.Writer, rows []Row) error

// Config configures lake rollover. Encoder is an optional test/customization
// hook; when nil, the sink writes Apache Parquet with Zstandard compression.
type Config struct {
	Root        string
	RowsPerFile int
	MaxAge      time.Duration
	Encoder     Encoder
}
type partition struct {
	rows   []Row
	first  int64
	opened time.Time
	part   uint64
}

// Sink partitions rows by UTC date and vendor and publishes files atomically.
type Sink struct {
	mu     sync.Mutex
	cfg    Config
	parts  map[string]*partition
	seen   map[string]struct{}
	closed bool
	stop   chan struct{}
	done   chan struct{}
	now    func() time.Time
}

// New creates a lake sink and removes stale temporary files.
func New(cfg Config) (*Sink, error) {
	if cfg.Root == "" {
		return nil, errors.New("parquet: Root is required")
	}
	if cfg.Encoder == nil {
		cfg.Encoder = encodeParquet
	}
	if cfg.RowsPerFile <= 0 {
		cfg.RowsPerFile = 500000
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 60 * time.Second
	}
	if err := os.MkdirAll(cfg.Root, 0o750); err != nil {
		return nil, err
	}
	if err := removeTemps(cfg.Root); err != nil {
		return nil, err
	}
	s := &Sink{cfg: cfg, parts: map[string]*partition{}, seen: map[string]struct{}{}, stop: make(chan struct{}), done: make(chan struct{}), now: time.Now}
	go s.rolloverLoop()
	return s, nil
}

func encodeParquet(w io.Writer, rows []Row) error {
	return parquetgo.Write(w, rows,
		parquetgo.Compression(&zstd.Codec{}),
		parquetgo.MaxRowsPerRowGroup(128000),
	)
}
func (s *Sink) Name() string { return "parquet" }
func (s *Sink) Write(ctx context.Context, batch []types.NormalizedEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return sinks.ErrClosed
	}
	for _, e := range batch {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, ok := s.seen[e.EventID]; ok {
			continue
		}
		row, err := makeRow(e)
		if err != nil {
			return err
		}
		key := row.EventTime.UTC().Format("2006-01-02") + "\x00" + safePartition(e.Vendor)
		p := s.parts[key]
		if p == nil {
			p = &partition{first: int64(e.RecordID), opened: s.now()}
			s.parts[key] = p
		}
		p.rows = append(p.rows, row)
		s.seen[e.EventID] = struct{}{}
		if len(p.rows) >= s.cfg.RowsPerFile {
			if err = s.rollLocked(key, p); err != nil {
				return err
			}
		}
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
	return s.flushLocked()
}
func (s *Sink) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.stop)
	err := s.flushLocked()
	s.mu.Unlock()
	<-s.done
	return err
}
func (s *Sink) rolloverLoop() {
	defer close(s.done)
	period := s.cfg.MaxAge / 2
	if period > time.Second {
		period = time.Second
	}
	if period < 10*time.Millisecond {
		period = 10 * time.Millisecond
	}
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.mu.Lock()
			now := s.now()
			for key, p := range s.parts {
				if len(p.rows) > 0 && now.Sub(p.opened) >= s.cfg.MaxAge {
					_ = s.rollLocked(key, p)
				}
			}
			s.mu.Unlock()
		case <-s.stop:
			return
		}
	}
}
func (s *Sink) flushLocked() error {
	keys := make([]string, 0, len(s.parts))
	for k := range s.parts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := s.rollLocked(k, s.parts[k]); err != nil {
			return err
		}
	}
	return nil
}
func (s *Sink) rollLocked(key string, p *partition) error {
	if len(p.rows) == 0 {
		return nil
	}
	bits := strings.SplitN(key, "\x00", 2)
	dir := filepath.Join(s.cfg.Root, "dt="+bits[0], "vendor="+bits[1])
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	name := fmt.Sprintf("part-%020d-%06d.parquet", p.first, p.part)
	tmp := filepath.Join(dir, name+".tmp")
	final := filepath.Join(dir, name)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err = s.cfg.Encoder(f, p.rows); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, final); err != nil {
		return err
	}
	if err = syncDir(dir); err != nil {
		return err
	}
	ok = true
	p.rows = nil
	p.part++
	p.opened = s.now()
	return nil
}
func makeRow(e types.NormalizedEvent) (Row, error) {
	f := mapping.Extract(e)
	var sum [32]byte
	b, err := hex.DecodeString(e.RawSHA256)
	if err != nil || len(b) != 32 {
		return Row{}, fmt.Errorf("parquet: event %s has invalid raw_sha256", e.EventID)
	}
	copy(sum[:], b)
	extras, err := json.Marshal(map[string]any{"ocsf": e.OCSF, "unmapped": e.Unmapped, "entities": e.Entities, "coverage": e.Coverage, "schema_version": e.SchemaVersion, "identity": e.Identity})
	if err != nil {
		return Row{}, err
	}
	return Row{EventID: e.EventID, RecordID: int64(e.RecordID), Segment: int64(e.Segment), RawSHA256: sum, SourceID: e.SourceID, Vendor: e.Vendor, Product: e.Product, ParserID: e.ParserID, ParserVersion: e.ParserVersion, TemplateID: e.TemplateID, EventTime: f.EventTime, ReceivedAt: e.ReceivedAt.UTC(), SeverityID: f.SeverityID, ActionID: f.ActionID, ActivityID: f.ActivityID, ClassUID: f.ClassUID, SrcIP: f.SrcIP, DstIP: f.DstIP, SrcPort: int32(f.SrcPort), DstPort: int32(f.DstPort), Proto: f.Protocol, BytesIn: f.BytesIn, BytesOut: f.BytesOut, User: f.User, Host: f.Host, Confidence: float32(e.ParseConfidence), IntegrityFlags: append([]string(nil), e.IntegrityFlags...), TimeFromReceipt: e.TimeFromReceipt, Current: e.Current, ExtrasJSON: string(extras)}, nil
}
func removeTemps(root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".tmp") {
			return os.Remove(path)
		}
		return nil
	})
}
func safePartition(s string) string {
	if s == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
func syncDir(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
