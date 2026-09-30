package source

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blakc-coffee/sluice/pkg/dataplane/ingest"
	types "github.com/blakc-coffee/sluice/pkg/types"
)

// UDP defaults.
const (
	// DefaultRecvBuffer is deliberately large. UDP has no backpressure: the
	// kernel buffer is the only thing standing between a burst and silent
	// loss, so it is sized for bursts rather than for averages.
	DefaultRecvBuffer = 8 << 20 // 8 MiB
	// udpReadBuffer is the per-read scratch. A datagram larger than this is
	// truncated by the kernel before we ever see it, so it is set well above
	// the 64 KiB IPv4 maximum payload.
	udpReadBuffer = 64 << 10
)

// UDPConfig configures a UDP listener.
type UDPConfig struct {
	ID     string
	Listen string
	// Readers is how many goroutines read the socket. More than one needs
	// SO_REUSEPORT, which is Linux-only, so this is forced to 1 elsewhere.
	Readers int
	// RecvBuffer is the SO_RCVBUF request. The kernel may clamp it to
	// net.core.rmem_max, and the effective value is logged when it does.
	RecvBuffer int
	// PeerMap assigns source_id from the sender's address. Unlike TCP, this
	// is resolved per datagram, because one socket receives from everyone.
	PeerMap *PeerMap
	// Metrics is the shared ingest collector set. Nil means no metrics.
	Metrics *ingest.Metrics
	Now     func() time.Time
	Log     *slog.Logger
}

// UDP receives syslog datagrams.
//
// # What UDP cannot promise
//
// One datagram is one record, and a datagram the kernel dropped never reached
// this process. There is no backpressure to apply and no retransmission to
// wait for: if the receive buffer overflows, those events are gone, and no
// amount of care downstream recovers them. This source therefore makes the
// buffer large, reads it promptly, and exposes the counters it can see. The
// submission says "best-effort" about UDP and means it.
type UDP struct {
	cfg  UDPConfig
	conn *net.UDPConn
	// effectiveBuffer is what the kernel actually granted, which is often
	// less than was asked for.
	effectiveBuffer int

	received atomic.Int64
	bytes    atomic.Int64
}

var _ ingest.Source = (*UDP)(nil)

// NewUDP binds the socket immediately so Addr is available before Run.
func NewUDP(cfg UDPConfig) (*UDP, error) {
	if cfg.ID == "" {
		return nil, errors.New("source: udp source needs an id")
	}
	if cfg.Listen == "" {
		return nil, errors.New("source: udp source needs a listen address")
	}
	if cfg.RecvBuffer <= 0 {
		cfg.RecvBuffer = DefaultRecvBuffer
	}
	if cfg.Readers <= 0 {
		cfg.Readers = 1
	}
	if cfg.Readers > 1 && runtime.GOOS != "linux" {
		// Multiple readers on one socket without SO_REUSEPORT just contend.
		cfg.Readers = 1
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	addr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	u := &UDP{cfg: cfg, conn: conn}
	if err := conn.SetReadBuffer(cfg.RecvBuffer); err != nil {
		cfg.Log.Warn("could not set the UDP receive buffer; bursts will be dropped sooner",
			"source", cfg.ID, "requested", cfg.RecvBuffer, "err", err)
	}
	u.effectiveBuffer = readBufferSize(conn)
	if u.effectiveBuffer > 0 && u.effectiveBuffer < cfg.RecvBuffer {
		// Worth a warning rather than a debug line: silently getting a
		// smaller buffer than asked for is exactly how UDP loss becomes a
		// mystery later.
		cfg.Log.Warn("the kernel clamped the UDP receive buffer",
			"source", cfg.ID, "requested", cfg.RecvBuffer, "effective", u.effectiveBuffer,
			"hint", "raise net.core.rmem_max")
	}
	return u, nil
}

// ID implements ingest.Source.
func (u *UDP) ID() string { return u.cfg.ID }

// Addr is the bound address, useful when Listen asked for port 0.
func (u *UDP) Addr() net.Addr { return u.conn.LocalAddr() }

// Received is the number of datagrams this process read. It is not the number
// sent: see the type documentation.
func (u *UDP) Received() int64 { return u.received.Load() }

// Run reads datagrams until ctx is done.
func (u *UDP) Run(ctx context.Context, sink ingest.Sink) error {
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-stopped:
		}
		u.conn.Close()
	}()
	defer close(stopped)

	// The kernel drop counter is the only visibility there is into datagrams
	// that never reached this process. It is Linux-only and best-effort.
	if u.cfg.Metrics != nil {
		wgDrops := make(chan struct{})
		go func() {
			defer close(wgDrops)
			u.pollKernelDrops(ctx)
		}()
		defer func() { <-wgDrops }()
	}

	var wg sync.WaitGroup
	for i := 0; i < u.cfg.Readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u.read(ctx, sink)
		}()
	}
	wg.Wait()
	return nil
}

func (u *UDP) read(ctx context.Context, sink ingest.Sink) {
	st := sink.NewStream(u.cfg.ID)
	defer st.Close()

	buf := make([]byte, udpReadBuffer)
	for {
		n, peer, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			u.cfg.Log.Warn("udp read failed", "source", u.cfg.ID, "err", err)
			return
		}

		// One datagram is one record, and its bytes are its bytes: a trailing
		// newline is content, not a terminator, because nothing framed this.
		// Copying at exactly n keeps a 40-byte message from holding 64 KiB.
		raw := make([]byte, n)
		copy(raw, buf[:n])

		u.received.Add(1)
		u.bytes.Add(int64(n))

		rec := types.RawRecord{
			// Per datagram: a single UDP socket hears from every device, so
			// unlike a connection there is nothing to resolve once.
			SourceID:   u.cfg.PeerMap.Lookup(peer.String(), u.cfg.ID),
			ReceivedAt: u.cfg.Now().UTC(),
			Origin: types.Origin{
				Kind: types.OriginUDP,
				Addr: peer.String(),
				// A datagram has no position in a stream, so there is no
				// meaningful offset to record.
				Offset: 0,
			},
			Term: types.TermNone,
			Raw:  raw,
		}
		if err := st.Submit(ctx, rec); err != nil {
			if ctx.Err() == nil {
				u.cfg.Log.Error("submit failed", "source", u.cfg.ID, "err", err)
			}
			return
		}
	}
}

// pollKernelDrops publishes the kernel's UDP receive-error counter.
//
// These are datagrams that arrived at the machine and were discarded before
// this process could read them. Nothing here can recover them; the only honest
// response is to make the number visible and say so.
func (u *UDP) pollKernelDrops(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		if n, ok := kernelUDPDrops(); ok {
			u.cfg.Metrics.UDPKernelDrops.Set(float64(n))
		} else {
			// NaN, not zero. A hard zero reads as "no datagrams were
			// dropped" on a platform that cannot tell, which is precisely
			// the quiet false assurance the UDP documentation exists to
			// avoid. Prometheus renders NaN as absent, so a dashboard shows
			// "no data" rather than a reassuring flat line.
			u.cfg.Metrics.UDPKernelDrops.Set(math.NaN())
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// readBufferSize reports the socket's effective SO_RCVBUF, or 0 if it cannot
// be read. It is best-effort by design: knowing the buffer was clamped is
// useful, but failing to start over it would not be.
func readBufferSize(conn *net.UDPConn) int {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0
	}
	var size int
	var innerErr error
	if err := raw.Control(func(fd uintptr) {
		size, innerErr = getRecvBuffer(fd)
	}); err != nil || innerErr != nil {
		return 0
	}
	return size
}
