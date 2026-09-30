package source

import (
	"fmt"
	"log/slog"
	"regexp"

	"github.com/blakc-coffee/sluice/pkg/dataplane/ingest"
	"github.com/blakc-coffee/sluice/pkg/dataplane/ingest/frame"
)

// Build turns the configuration into live sources. Listeners bind here,
// so a port conflict is a startup error rather than a surprise later.
func Build(cfg *ingest.FileConfig, m *ingest.Metrics, healthy func() bool, log *slog.Logger) ([]ingest.Source, func(), error) {
	peers := make([]PeerMapEntry, len(cfg.PeerMap))
	for i, e := range cfg.PeerMap {
		peers[i] = PeerMapEntry{CIDR: e.CIDR, SourceID: e.SourceID}
	}
	peerMap, err := NewPeerMap(peers)
	if err != nil {
		return nil, nil, err
	}
	if peerMap.Len() > 0 {
		log.Info("peer map loaded", "entries", peerMap.Len())
	}

	var srcs []ingest.Source
	var closers []func()
	closeAll := func() {
		for _, c := range closers {
			c()
		}
	}

	for _, s := range cfg.Sources {
		switch s.Type {
		case "udp":
			u, err := NewUDP(UDPConfig{
				ID: s.ID, Listen: s.Listen, Readers: s.Readers,
				RecvBuffer: int(s.RecvBuffer), PeerMap: peerMap, Metrics: m, Log: log,
			})
			if err != nil {
				closeAll()
				return nil, nil, fmt.Errorf("source %s: %w", s.ID, err)
			}
			srcs = append(srcs, u)

		case "tcp", "tls":
			tc := TCPConfig{
				ID: s.ID, Listen: s.Listen,
				Framing:       framingMode(s.Framing),
				MaxConns:      cfg.Limits.MaxConns,
				IdleTimeout:   cfg.Limits.IdleTimeout.Std(),
				MaxFrameBytes: int(cfg.Limits.MaxFrameBytes),
				MaxOctetLen:   int(cfg.Limits.MaxOctetLen),
				PeerMap:       peerMap,
				Metrics:       m,
				Log:           log,
			}
			if s.Type == "tls" {
				tlsCfg, err := TLSConfig(s.Cert, s.Key, s.ClientCA)
				if err != nil {
					closeAll()
					return nil, nil, fmt.Errorf("source %s: %w", s.ID, err)
				}
				tc.TLS = tlsCfg
			}
			t, err := NewTCP(tc)
			if err != nil {
				closeAll()
				return nil, nil, fmt.Errorf("source %s: %w", s.ID, err)
			}
			srcs = append(srcs, t)

		case "http":
			h, err := NewHTTP(HTTPConfig{
				ID: s.ID, Listen: s.Listen,
				DynamicSources: s.DynamicSources,
				AllowedSources: s.AllowedSources,
				MaxBody:        int64(cfg.Limits.HTTPMaxBody),
				MaxFrameBytes:  int(cfg.Limits.MaxFrameBytes),
				MaxOctetLen:    int(cfg.Limits.MaxOctetLen),
				Healthy:        healthy,
				Metrics:        m,
				Log:            log,
			})
			if err != nil {
				closeAll()
				return nil, nil, fmt.Errorf("source %s: %w", s.ID, err)
			}
			srcs = append(srcs, h)

		case "file":
			fc := FileConfig{
				ID: s.ID, Paths: s.Paths,
				Mode:            FileMode(orDefault(s.Mode, "once")),
				From:            FileFrom(s.From),
				Framing:         framingMode(s.Framing),
				MaxFrameBytes:   int(cfg.Limits.MaxFrameBytes),
				CheckpointDir:   s.CheckpointDir,
				CheckpointEvery: s.CheckpointEvery,
				PollInterval:    s.Poll.Std(),
				Metrics:         m,
				Log:             log,
			}
			if s.Multiline != nil {
				re, err := regexp.Compile(s.Multiline.Start)
				if err != nil {
					closeAll()
					return nil, nil, fmt.Errorf("source %s: multiline.start: %w", s.ID, err)
				}
				fc.Multiline = &MultilineConfig{
					Start: re, MaxLines: s.Multiline.MaxLines,
					Timeout: s.Multiline.Timeout.Std(),
				}
			}
			f, err := NewFile(fc)
			if err != nil {
				closeAll()
				return nil, nil, fmt.Errorf("source %s: %w", s.ID, err)
			}
			srcs = append(srcs, f)
		}
	}
	return srcs, closeAll, nil
}

func framingMode(s string) frame.Mode {
	if s == "auto" {
		return FramingAuto
	}
	if s == "" {
		return frame.ModeLF
	}
	return frame.Mode(s)
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
