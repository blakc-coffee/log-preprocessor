package source_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/frame"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/source"
	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault/memvault"
)

// harness runs one source against an in-memory vault and collects the events.
type harness struct {
	t      *testing.T
	vault  *memvault.Vault
	out    chan types.RawEvent
	cancel context.CancelFunc

	mu     sync.Mutex
	events []types.RawEvent

	done chan error

	// runOnce caches the pipeline's exit so both waitRun and stop can see it.
	// A bare channel receive is single-use, and a test that reads it directly
	// leaves stop blocked forever.
	runOnce sync.Once
	runErr  error

	wg sync.WaitGroup
}

// waitRun blocks until the pipeline returns and reports its error. Safe to
// call more than once, and safe to call before stop.
func (h *harness) waitRun() error {
	h.runOnce.Do(func() {
		select {
		case h.runErr = <-h.done:
		case <-time.After(10 * time.Second):
			h.runErr = errors.New("the pipeline did not return")
		}
	})
	return h.runErr
}

func start(t *testing.T, src ingest.Source) *harness {
	t.Helper()

	h := &harness{
		t:     t,
		vault: memvault.New(memvault.Options{SealEvery: 1000}),
		out:   make(chan types.RawEvent, 256),
		done:  make(chan error, 1),
	}
	p, err := ingest.New(ingest.Config{
		OutBuffer:    256,
		BatchRecords: 8,
		BatchDelay:   2 * time.Millisecond,
		Now:          func() time.Time { return time.Unix(1790566200, 0).UTC() },
	}, h.vault, h.out, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.AddSource(src)

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel

	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		for ev := range h.out {
			h.mu.Lock()
			h.events = append(h.events, ev)
			h.mu.Unlock()
		}
	}()
	go func() { h.done <- p.Run(ctx) }()

	t.Cleanup(func() { h.stop() })
	return h
}

// waitFor polls until n events have arrived, or fails. Polling rather than
// sleeping: a fixed sleep is either flaky or slow, and the tests must be
// deterministic.
func (h *harness) waitFor(n int) []types.RawEvent {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		h.mu.Lock()
		got := len(h.events)
		h.mu.Unlock()
		if got >= n {
			break
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("timed out waiting for %d events, got %d", n, got)
		}
		time.Sleep(time.Millisecond)
	}
	return h.collected()
}

func (h *harness) collected() []types.RawEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]types.RawEvent(nil), h.events...)
}

func (h *harness) stop() {
	h.cancel()
	if err := h.waitRun(); err != nil && !errors.Is(err, context.Canceled) {
		// Not a failure by itself: several tests expect the source to fail.
		h.t.Logf("pipeline returned: %v", err)
	}
	h.wg.Wait()
	h.vault.Close()
}

// raws returns the payloads in order.
func raws(events []types.RawEvent) []string {
	out := make([]string, len(events))
	for i, ev := range events {
		out[i] = string(ev.Raw)
	}
	return out
}

// ------------------------------------------------------------------- TCP

func TestTCPLineFraming(t *testing.T) {
	src, err := source.NewTCP(source.TCPConfig{
		ID: "syslog-tcp", Listen: "127.0.0.1:0", Framing: frame.ModeLF,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := start(t, src)

	conn, err := net.Dial("tcp", src.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("alpha\nbeta\ngamma\n")); err != nil {
		t.Fatal(err)
	}
	conn.Close()

	got := h.waitFor(3)
	if diff := strings.Join(raws(got), ","); diff != "alpha,beta,gamma" {
		t.Errorf("got %q", diff)
	}
	for _, ev := range got {
		if ev.Origin.Kind != types.OriginTCP {
			t.Errorf("record %d has origin kind %d, want TCP", ev.ID, ev.Origin.Kind)
		}
		if ev.Origin.Addr == "" {
			t.Errorf("record %d has no peer address", ev.ID)
		}
		if ev.Term != types.TermLF {
			t.Errorf("record %d has terminator %d, want LF", ev.ID, ev.Term)
		}
	}
	// Origin.Offset is the position within the connection.
	if got[0].Origin.Offset != 0 || got[1].Origin.Offset != 6 || got[2].Origin.Offset != 11 {
		t.Errorf("connection offsets are %d,%d,%d, want 0,6,11",
			got[0].Origin.Offset, got[1].Origin.Offset, got[2].Origin.Offset)
	}
}

// TestTCPSlowClient is the realistic case: a record arrives in pieces, with
// pauses. A framer that assumed reads align with records would fail here and
// nowhere else.
func TestTCPSlowClient(t *testing.T) {
	src, err := source.NewTCP(source.TCPConfig{
		ID: "slow", Listen: "127.0.0.1:0", Framing: frame.ModeLF,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := start(t, src)

	conn, err := net.Dial("tcp", src.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	for _, piece := range []string{"<166>Sep 28 ", "2026 09:00:01 asa01", " : msg\nsec", "ond\n"} {
		if _, err := conn.Write([]byte(piece)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	conn.Close()

	got := h.waitFor(2)
	want := []string{"<166>Sep 28 2026 09:00:01 asa01 : msg", "second"}
	if diff := strings.Join(raws(got), "|"); diff != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", diff, want)
	}
}

// TestTCPAutoFraming covers the guess RFC 6587 forces a syslog listener to
// make, on both kinds of input.
func TestTCPAutoFraming(t *testing.T) {
	cases := map[string]struct {
		send string
		want []string
	}{
		"syslog lines": {"<166>one\n<166>two\n", []string{"<166>one", "<166>two"}},
		"octet counted": {
			"30 <134>Sep 28 10:14:02 h app: hi5 alpha",
			[]string{"<134>Sep 28 10:14:02 h app: hi", "alpha"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			src, err := source.NewTCP(source.TCPConfig{
				ID: "auto", Listen: "127.0.0.1:0", Framing: source.FramingAuto,
			})
			if err != nil {
				t.Fatal(err)
			}
			h := start(t, src)

			conn, err := net.Dial("tcp", src.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			conn.Write([]byte(c.send))
			conn.Close()

			got := raws(h.waitFor(len(c.want)))
			if strings.Join(got, "|") != strings.Join(c.want, "|") {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// TestTCPUnterminatedTailIsKept: a client that writes a partial line and then
// closes must not have those bytes discarded.
func TestTCPUnterminatedTailIsKept(t *testing.T) {
	src, err := source.NewTCP(source.TCPConfig{ID: "tail", Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	h := start(t, src)

	conn, _ := net.Dial("tcp", src.Addr().String())
	conn.Write([]byte("complete\npartial"))
	conn.Close()

	got := h.waitFor(2)
	if string(got[1].Raw) != "partial" {
		t.Errorf("the unterminated tail came back as %q", got[1].Raw)
	}
	if got[1].Term != types.TermNone {
		t.Errorf("the unterminated tail has terminator %d, want none", got[1].Term)
	}
}

// TestTCPBinaryIsPreserved: the socket path must not clean up its input either.
func TestTCPBinaryIsPreserved(t *testing.T) {
	src, err := source.NewTCP(source.TCPConfig{ID: "bin", Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	h := start(t, src)

	payload := []byte{0xFF, 0xFE, 0x00, '\r', 'a', 0x7F}
	conn, _ := net.Dial("tcp", src.Addr().String())
	conn.Write(append(append([]byte{}, payload...), '\n'))
	conn.Close()

	got := h.waitFor(1)
	if !bytes.Equal(got[0].Raw, payload) {
		t.Errorf("got %x, want %x", got[0].Raw, payload)
	}
}

func TestTCPConcurrentConnections(t *testing.T) {
	const conns, perConn = 12, 20

	src, err := source.NewTCP(source.TCPConfig{ID: "many", Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	h := start(t, src)

	var wg sync.WaitGroup
	for c := 0; c < conns; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			conn, err := net.Dial("tcp", src.Addr().String())
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			for i := 0; i < perConn; i++ {
				fmt.Fprintf(conn, "conn%d-msg%d\n", c, i)
			}
		}(c)
	}
	wg.Wait()

	got := h.waitFor(conns * perConn)

	// Records interleave across connections but must keep their order within
	// one, because a connection is one stream.
	seen := map[int][]int{}
	for _, ev := range got {
		var c, i int
		if _, err := fmt.Sscanf(string(ev.Raw), "conn%d-msg%d", &c, &i); err != nil {
			t.Fatalf("unexpected payload %q", ev.Raw)
		}
		seen[c] = append(seen[c], i)
	}
	if len(seen) != conns {
		t.Fatalf("saw %d connections, want %d", len(seen), conns)
	}
	for c, msgs := range seen {
		if len(msgs) != perConn {
			t.Errorf("connection %d delivered %d messages, want %d", c, len(msgs), perConn)
		}
		for i, m := range msgs {
			if m != i {
				t.Errorf("connection %d: message %d arrived out of order (%d)", c, i, m)
				break
			}
		}
	}
}

// TestTCPMaxConns: at the cap, a connection is refused immediately. Accepting
// and then stalling would look to the sender like a working connection that
// silently loses data.
func TestTCPMaxConns(t *testing.T) {
	src, err := source.NewTCP(source.TCPConfig{
		ID: "capped", Listen: "127.0.0.1:0", MaxConns: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := start(t, src)

	held, err := net.Dial("tcp", src.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	held.Write([]byte("first\n"))
	h.waitFor(1) // the slot is now occupied

	// The second connection is accepted by the kernel backlog and then closed
	// by us, so the write may succeed but the read must see EOF quickly.
	second, err := net.Dial("tcp", src.Addr().String())
	if err != nil {
		return // refused at the TCP level is also correct
	}
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Error("the connection over the cap was not closed")
	}

	deadline := time.Now().Add(5 * time.Second)
	for src.Rejected() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if src.Rejected() == 0 {
		t.Error("the refused connection was not counted")
	}
}

// TestTCPIdleTimeout: a connection that opens and says nothing must not hold a
// slot forever. This is the slow-loris defence.
func TestTCPIdleTimeout(t *testing.T) {
	src, err := source.NewTCP(source.TCPConfig{
		ID: "idle", Listen: "127.0.0.1:0", IdleTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	start(t, src)

	conn, err := net.Dial("tcp", src.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("an idle connection was not closed")
	}
}

// TestTCPFramingErrorClosesTheConnection: a hostile octet length must not be
// buffered, and the connection must go.
func TestTCPFramingErrorClosesTheConnection(t *testing.T) {
	src, err := source.NewTCP(source.TCPConfig{
		ID: "hostile", Listen: "127.0.0.1:0",
		Framing: frame.ModeOctet, MaxOctetLen: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	start(t, src)

	conn, err := net.Dial("tcp", src.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("999999999 "))

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("the connection survived a hostile octet length")
	}

	deadline := time.Now().Add(5 * time.Second)
	for src.FrameErrors() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if src.FrameErrors() == 0 {
		t.Error("the framing error was not counted")
	}
}

// ------------------------------------------------------------------- UDP

func TestUDPDatagrams(t *testing.T) {
	src, err := source.NewUDP(source.UDPConfig{
		ID: "syslog-udp", Listen: "127.0.0.1:0", RecvBuffer: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := start(t, src)

	conn, err := net.Dial("udp", src.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	msgs := []string{
		"<134>Sep 28 09:00:01 h app: hello",
		"a\nb", // an embedded newline is content: nothing framed this
		"",     // an empty datagram is still a record
	}
	for _, m := range msgs {
		if _, err := conn.Write([]byte(m)); err != nil {
			t.Fatal(err)
		}
	}

	got := h.waitFor(len(msgs))
	for i, m := range msgs {
		if string(got[i].Raw) != m {
			t.Errorf("datagram %d came back as %q, want %q", i, got[i].Raw, m)
		}
		if got[i].Term != types.TermNone {
			t.Errorf("datagram %d has terminator %d; a datagram has no terminator", i, got[i].Term)
		}
		if got[i].Origin.Kind != types.OriginUDP {
			t.Errorf("datagram %d has origin kind %d, want UDP", i, got[i].Origin.Kind)
		}
		if got[i].Origin.Offset != 0 {
			t.Errorf("datagram %d has offset %d; a datagram has no position in a stream",
				i, got[i].Origin.Offset)
		}
	}
}

// TestUDPTrailingNewlineIsContent. A syslog sender that appends "\n" to its
// datagram has sent 34 bytes, not 33 plus a terminator. Stripping it would
// break the byte-exactness claim for every such sender.
func TestUDPTrailingNewlineIsContent(t *testing.T) {
	src, err := source.NewUDP(source.UDPConfig{ID: "udp-nl", Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	h := start(t, src)

	conn, _ := net.Dial("udp", src.Addr().String())
	defer conn.Close()
	conn.Write([]byte("message\n"))

	got := h.waitFor(1)
	if string(got[0].Raw) != "message\n" {
		t.Errorf("got %q, want %q — the trailing newline is part of the datagram", got[0].Raw, "message\n")
	}
}

func TestUDPBinaryIsPreserved(t *testing.T) {
	src, err := source.NewUDP(source.UDPConfig{ID: "udp-bin", Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	h := start(t, src)

	payload := []byte{0x00, 0xFF, 0xFE, '\n', '\r', 0x1b}
	conn, _ := net.Dial("udp", src.Addr().String())
	defer conn.Close()
	conn.Write(payload)

	got := h.waitFor(1)
	if !bytes.Equal(got[0].Raw, payload) {
		t.Errorf("got %x, want %x", got[0].Raw, payload)
	}
}

// ------------------------------------------------------------- shutdown

func TestSourcesShutDownCleanly(t *testing.T) {
	tcp, err := source.NewTCP(source.TCPConfig{ID: "t", Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	udp, err := source.NewUDP(source.UDPConfig{ID: "u", Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}

	v := memvault.New(memvault.Options{SealEvery: 1000})
	defer v.Close()
	out := make(chan types.RawEvent, 64)
	p, err := ingest.New(ingest.Config{OutBuffer: 64}, v, out, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.AddSource(tcp)
	p.AddSource(udp)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	go func() {
		for range out {
		}
	}()

	// Hold a connection open: shutdown must not wait for it to go away on
	// its own, or a single idle client delays every restart.
	conn, err := net.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("shutdown reported %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown blocked on an open connection")
	}
}

func TestSourceConfigValidation(t *testing.T) {
	if _, err := source.NewTCP(source.TCPConfig{Listen: "127.0.0.1:0"}); err == nil {
		t.Error("a tcp source was built with no id")
	}
	if _, err := source.NewTCP(source.TCPConfig{ID: "x"}); err == nil {
		t.Error("a tcp source was built with no listen address")
	}
	if _, err := source.NewTCP(source.TCPConfig{ID: "x", Listen: "127.0.0.1:0", Framing: "nope"}); err == nil {
		t.Error("a tcp source was built with an unknown framing")
	}
	if _, err := source.NewUDP(source.UDPConfig{Listen: "127.0.0.1:0"}); err == nil {
		t.Error("a udp source was built with no id")
	}
}

// TestTCPShutdownWithConnectionsArriving is a regression test.
//
// A connection accepted in the window between shutdown closing the live
// connections and the accept loop registering it was never closed, so its
// reader blocked until the idle timeout — five minutes by default — and Run
// never returned. It surfaced as an intermittent hang, and only under -race,
// where the scheduling window is wide enough to hit.
//
// This dials continuously across the cancellation so the window is hit on
// purpose rather than by luck.
func TestTCPShutdownWithConnectionsArriving(t *testing.T) {
	src, err := source.NewTCP(source.TCPConfig{
		ID: "churn", Listen: "127.0.0.1:0",
		// A long idle timeout is the point: if a connection is leaked, the
		// test hangs rather than quietly waiting it out.
		IdleTimeout: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	v := memvault.New(memvault.Options{SealEvery: 1000})
	defer v.Close()
	out := make(chan types.RawEvent, 64)
	p, err := ingest.New(ingest.Config{OutBuffer: 64}, v, out, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.AddSource(src)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	go func() {
		for range out {
		}
	}()

	stop := make(chan struct{})
	var dialers sync.WaitGroup
	for i := 0; i < 4; i++ {
		dialers.Add(1)
		go func() {
			defer dialers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				conn, err := net.Dial("tcp", src.Addr().String())
				if err != nil {
					return // the listener is gone, which is the expected end
				}
				// Say nothing: a silent connection is the one that would be
				// leaked and then block on its read.
				defer conn.Close()
			}
		}()
	}

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("shutdown reported %v", err)
		}
	case <-time.After(15 * time.Second):
		close(stop)
		dialers.Wait()
		t.Fatal("shutdown leaked a connection accepted during the shutdown window")
	}
	close(stop)
	dialers.Wait()
}
