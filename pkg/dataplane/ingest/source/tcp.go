package source

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/blakc-coffee/sluice/pkg/dataplane/ingest"
	"github.com/blakc-coffee/sluice/pkg/dataplane/ingest/frame"
	types "github.com/blakc-coffee/sluice/pkg/types"
)

// Defaults for stream listeners.
const (
	DefaultMaxConns    = 1024
	DefaultIdleTimeout = 5 * time.Minute
)

// FramingAuto asks the listener to decide per connection between octet
// counting and line framing, as RFC 6587 allows on a single syslog port.
const FramingAuto frame.Mode = "auto"

// TCPConfig configures a TCP or TLS listener.
type TCPConfig struct {
	// ID is the source_id stamped on records, unless a peer map overrides it.
	ID string
	// Listen is the bind address, e.g. "127.0.0.1:5514".
	Listen string
	// Framing is lf, crlf, lines, nul, octet, or auto. Auto is safe only for
	// syslog: see frame.Detect.
	Framing frame.Mode

	MaxConns      int
	IdleTimeout   time.Duration
	MaxFrameBytes int
	MaxOctetLen   int

	// TLS, when set, wraps every accepted connection. Minimum TLS 1.2.
	TLS *tls.Config

	// PeerMap assigns source_id from the sender's address, so onboarding a
	// device is a config line rather than a new listener. Nil means every
	// record carries this listener's ID.
	PeerMap *PeerMap
	// Metrics is the shared ingest collector set. Nil means no metrics.
	Metrics *ingest.Metrics

	Now func() time.Time
	Log *slog.Logger
}

// TCP is a stream listener. It serves plain TCP, or TLS when Config.TLS is set.
type TCP struct {
	cfg TCPConfig
	ln  net.Listener

	sem chan struct{}

	mu sync.Mutex
	// closing is set the moment shutdown starts. Without it, a connection
	// accepted after closeConns has already walked the map is never closed,
	// and its reader blocks until the idle timeout — five minutes by default,
	// during which shutdown does not finish.
	closing bool
	conns   map[net.Conn]struct{}

	// counters observable without a metrics registry, which arrives at M4.
	frameErrors atomic64
	accepted    atomic64
	rejected    atomic64
}

var _ ingest.Source = (*TCP)(nil)

// NewTCP binds the listener immediately, so a caller can read Addr before Run
// starts accepting. Binding in Run would force every test to poll for
// readiness, and sleep-based synchronisation in tests is how flakes are born.
func NewTCP(cfg TCPConfig) (*TCP, error) {
	if cfg.ID == "" {
		return nil, errors.New("source: tcp source needs an id")
	}
	if cfg.Listen == "" {
		return nil, errors.New("source: tcp source needs a listen address")
	}
	switch cfg.Framing {
	case "":
		cfg.Framing = frame.ModeLF
	case FramingAuto, frame.ModeLF, frame.ModeCRLF, frame.ModeLines, frame.ModeNUL, frame.ModeOctet:
	default:
		return nil, fmt.Errorf("source: unknown framing %q", cfg.Framing)
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
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
	if cfg.TLS != nil {
		if cfg.TLS.MinVersion == 0 {
			cfg.TLS.MinVersion = tls.VersionTLS12
		}
		ln = tls.NewListener(ln, cfg.TLS)
	}

	return &TCP{
		cfg: cfg, ln: ln,
		sem:   make(chan struct{}, cfg.MaxConns),
		conns: map[net.Conn]struct{}{},
	}, nil
}

// ID implements ingest.Source.
func (t *TCP) ID() string { return t.cfg.ID }

// Addr is the bound address, useful when Listen asked for port 0.
func (t *TCP) Addr() net.Addr { return t.ln.Addr() }

// FrameErrors is the number of connections dropped for a framing violation.
func (t *TCP) FrameErrors() int64 { return t.frameErrors.load() }

// Rejected is the number of connections refused because MaxConns was reached.
func (t *TCP) Rejected() int64 { return t.rejected.load() }

// Run accepts connections until ctx is done.
func (t *TCP) Run(ctx context.Context, sink ingest.Sink) error {
	var wg sync.WaitGroup

	// Closing the listener is what unblocks Accept; closing the live
	// connections is what unblocks reads that are mid-flight. Without the
	// second, a shutdown waits for every idle client to disconnect.
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-stopped:
		}
		t.ln.Close()
		t.closeConns()
	}()
	defer close(stopped)

	for {
		conn, err := t.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			wg.Wait()
			return err
		}

		select {
		case t.sem <- struct{}{}:
		default:
			// At the connection cap. Refusing immediately is the honest
			// answer: accepting and then stalling looks to the sender like a
			// working connection that silently loses data.
			t.rejected.add(1)
			t.frameError("max_conns")
			t.cfg.Log.Warn("connection refused, at max_conns",
				"source", t.cfg.ID, "peer", conn.RemoteAddr().String(), "max_conns", t.cfg.MaxConns)
			conn.Close()
			continue
		}

		if ctx.Err() != nil || !t.track(conn) {
			// Shutdown started between Accept returning and here.
			conn.Close()
			<-t.sem
			continue
		}
		t.accepted.add(1)
		t.connGauge(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-t.sem }()
			defer t.connGauge(-1)
			defer t.untrack(conn)
			t.serve(ctx, sink, conn)
		}()
	}

	wg.Wait()
	return nil
}

// track registers a connection so shutdown can close it. It reports false if
// shutdown has already begun, in which case the caller must close it instead.
func (t *TCP) track(c net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closing {
		return false
	}
	t.conns[c] = struct{}{}
	return true
}

func (t *TCP) untrack(c net.Conn) {
	t.mu.Lock()
	delete(t.conns, c)
	t.mu.Unlock()
	c.Close()
}

// closeConns unblocks every in-flight read and makes every later track fail,
// so no connection can slip in behind the shutdown.
func (t *TCP) closeConns() {
	t.mu.Lock()
	t.closing = true
	for c := range t.conns {
		c.Close()
	}
	t.mu.Unlock()
}

// serve reads one connection to its end.
func (t *TCP) serve(ctx context.Context, sink ingest.Sink, conn net.Conn) {
	peer := conn.RemoteAddr().String()
	log := t.cfg.Log.With("source", t.cfg.ID, "peer", peer)

	kind := types.OriginTCP
	if t.cfg.TLS != nil {
		kind = types.OriginTLS
	}

	// Resolved once per connection: the peer cannot change mid-stream.
	sourceID := t.cfg.PeerMap.Lookup(peer, t.cfg.ID)
	if sourceID != t.cfg.ID {
		log = log.With("source_id", sourceID)
	}

	br := bufio.NewReader(&idleConn{Conn: conn, idle: t.cfg.IdleTimeout})

	mode := t.cfg.Framing
	if mode == FramingAuto {
		// Detect needs at most seven bytes: six digits and a space. Peek may
		// return fewer if the client stops early, and Detect handles that by
		// choosing line framing, which cannot run away on a wrong guess.
		head, _ := br.Peek(7)
		mode = frame.Detect(head)
		log = log.With("framing", string(mode))
	}

	dec, err := frame.New(mode, br, frame.Options{
		MaxFrameBytes: t.cfg.MaxFrameBytes,
		MaxOctetLen:   t.cfg.MaxOctetLen,
	})
	if err != nil {
		log.Error("cannot frame connection", "err", err)
		return
	}

	st := sink.NewStream(sourceID)
	defer st.Close()

	for {
		fr, err := dec.Next()
		if err != nil {
			t.reportReadEnd(ctx, log, err)
			return
		}
		rec := types.RawRecord{
			SourceID:   sourceID,
			ReceivedAt: t.cfg.Now().UTC(),
			Origin:     types.Origin{Kind: kind, Addr: peer, Offset: fr.Offset},
			Term:       fr.Term,
			Frag:       fr.Frag,
			Raw:        fr.Raw,
		}
		if err := st.Submit(ctx, rec); err != nil {
			if ctx.Err() == nil {
				log.Error("submit failed", "err", err)
			}
			return
		}
	}
}

// reportReadEnd classifies why a connection stopped producing records. The
// distinction matters operationally: a clean close is routine, an idle timeout
// is configuration, and a framing violation is a sender to go and look at.
func (t *TCP) reportReadEnd(ctx context.Context, log *slog.Logger, err error) {
	switch {
	case errors.Is(err, io.EOF):
		return // the client closed; nothing to say
	case ctx.Err() != nil:
		return // we are shutting down
	case errors.Is(err, frame.ErrOctetLength), errors.Is(err, frame.ErrOctetMalformed):
		// Hostile or broken framing. The connection is already being closed
		// by the deferred Close; count it so it shows up in metrics rather
		// than only in a log nobody reads.
		t.frameErrors.add(1)
		t.frameError(frameErrorReason(err))
		log.Warn("closing connection on a framing error", "err", err)
	case isTimeout(err):
		t.frameError("idle_timeout")
		log.Info("closing idle connection", "idle_timeout", t.cfg.IdleTimeout)
	case errors.Is(err, net.ErrClosed):
		return // our own shutdown
	default:
		log.Warn("connection read failed", "err", err)
	}
}

// connGauge moves the open-connection gauge.
func (t *TCP) connGauge(d float64) {
	if t.cfg.Metrics == nil {
		return
	}
	t.cfg.Metrics.Connections.WithLabelValues(t.cfg.Metrics.Source(t.cfg.ID)).Add(d)
}

// frameError counts a connection closed for a named reason. The reason is a
// metric label, so it comes from a fixed set here and never from the error
// text, which would otherwise be an unbounded label space fed by the network.
func (t *TCP) frameError(reason string) {
	if t.cfg.Metrics == nil {
		return
	}
	t.cfg.Metrics.FrameErrors.WithLabelValues(t.cfg.Metrics.Source(t.cfg.ID), reason).Inc()
}

func frameErrorReason(err error) string {
	switch {
	case errors.Is(err, frame.ErrOctetLength):
		return "octet_len"
	case errors.Is(err, frame.ErrOctetMalformed):
		return "octet_malformed"
	}
	return "framing"
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// idleConn applies a read deadline to every read, so a connection that opens
// and then says nothing cannot hold a slot forever. This is the slow-loris
// defence for the raw socket path.
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleConn) Read(p []byte) (int, error) {
	if c.idle > 0 {
		if err := c.Conn.SetReadDeadline(time.Now().Add(c.idle)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(p)
}
