// Package cefsyslog exports CEF messages in RFC 5424 syslog envelopes.
package cefsyslog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blakc-coffee/sluice/pkg/sinks"
	"github.com/blakc-coffee/sluice/pkg/sinks/internal/mapping"
	"github.com/blakc-coffee/sluice/pkg/types"
)

// Config controls transport and framing.
type Config struct {
	Network, Address, Hostname, AppName string
	OctetCounted                        bool
	Dialer                              *net.Dialer
}

// Sink writes CEF over UDP or TCP syslog.
type Sink struct {
	mu     sync.Mutex
	cfg    Config
	closed bool
}

// New validates the transport configuration.
func New(cfg Config) (*Sink, error) {
	if cfg.Network != "udp" && cfg.Network != "tcp" {
		return nil, errors.New("cefsyslog: network must be udp or tcp")
	}
	if cfg.Address == "" {
		return nil, errors.New("cefsyslog: address is required")
	}
	if cfg.Hostname == "" {
		cfg.Hostname = "ulpf"
	}
	if cfg.AppName == "" {
		cfg.AppName = "ulpf"
	}
	if cfg.Dialer == nil {
		cfg.Dialer = &net.Dialer{Timeout: 5 * time.Second}
	}
	return &Sink{cfg: cfg}, nil
}
func (s *Sink) Name() string { return "cefsyslog" }
func (s *Sink) Write(ctx context.Context, batch []types.NormalizedEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return sinks.ErrClosed
	}
	conn, err := s.cfg.Dialer.DialContext(ctx, s.cfg.Network, s.cfg.Address)
	if err != nil {
		return err
	}
	defer conn.Close()
	for _, e := range batch {
		if err = ctx.Err(); err != nil {
			return err
		}
		line := s.format(e)
		if s.cfg.Network == "tcp" {
			if s.cfg.OctetCounted {
				line = []byte(strconv.Itoa(len(line)) + " " + string(line))
			} else {
				line = append(line, '\n')
			}
		}
		if _, err = conn.Write(line); err != nil {
			return err
		}
	}
	return nil
}
func (s *Sink) format(e types.NormalizedEvent) []byte {
	f := mapping.Extract(e)
	sev := f.SeverityID
	if sev < 0 {
		sev = 0
	}
	if sev > 10 {
		sev = 10
	}
	name := f.Message
	if name == "" {
		name = f.Action
	}
	ext := []string{"rt=" + strconv.FormatInt(f.EventTime.UnixMilli(), 10), "src=" + escapeExt(f.SrcIP), "dst=" + escapeExt(f.DstIP), "spt=" + strconv.Itoa(f.SrcPort), "dpt=" + strconv.Itoa(f.DstPort), "proto=" + escapeExt(f.Protocol), "act=" + escapeExt(f.Action), "suser=" + escapeExt(f.User), "shost=" + escapeExt(f.Host), "msg=" + escapeExt(f.Message), "externalId=" + escapeExt(e.EventID), "cs1Label=raw_sha256", "cs1=" + escapeExt(e.RawSHA256), "cs2Label=parser", "cs2=" + escapeExt(e.ParserID+"@"+e.ParserVersion)}
	cef := fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|%s", escapeHeader(e.Vendor), escapeHeader(e.Product), escapeHeader(e.ParserVersion), escapeHeader(e.TemplateID), escapeHeader(name), sev, strings.Join(ext, " "))
	header := fmt.Sprintf("<134>1 %s %s %s - - - ", f.EventTime.UTC().Format(time.RFC3339Nano), s.cfg.Hostname, s.cfg.AppName)
	return append([]byte(header), []byte(cef)...)
}
func (s *Sink) Flush(ctx context.Context) error { return ctx.Err() }
func (s *Sink) Close() error                    { s.mu.Lock(); defer s.mu.Unlock(); s.closed = true; return nil }
func escapeHeader(v string) string {
	v = strings.ReplaceAll(v, "\\", "\\\\")
	return strings.ReplaceAll(v, "|", "\\|")
}
func escapeExt(v string) string {
	var b bytes.Buffer
	for _, r := range v {
		switch r {
		case '\\':
			b.WriteString("\\\\")
		case '=':
			b.WriteString("\\=")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Format exposes deterministic CEF formatting for conformance tests.
func Format(e types.NormalizedEvent, hostname, app string) string {
	s := &Sink{cfg: Config{Hostname: hostname, AppName: app}}
	if hostname == "" {
		s.cfg.Hostname = "ulpf"
	}
	if app == "" {
		s.cfg.AppName = "ulpf"
	}
	return string(s.format(e))
}
