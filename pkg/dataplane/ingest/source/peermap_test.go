package source_test

import (
	"net"
	"testing"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/source"
)

func mustPeerMap(t *testing.T, entries ...source.PeerMapEntry) *source.PeerMap {
	t.Helper()
	pm, err := source.NewPeerMap(entries)
	if err != nil {
		t.Fatal(err)
	}
	return pm
}

// TestPeerMapLongestPrefixWins is the rule that makes the map useful: a
// specific host can override the subnet it sits in.
func TestPeerMapLongestPrefixWins(t *testing.T) {
	pm := mustPeerMap(t,
		// Deliberately not in most-specific order: the map sorts itself, or
		// the behaviour would depend on how someone wrote their config.
		source.PeerMapEntry{CIDR: "10.1.0.0/16", SourceID: "site-a"},
		source.PeerMapEntry{CIDR: "10.1.4.7/32", SourceID: "site-a-core-fw"},
		source.PeerMapEntry{CIDR: "10.1.4.0/24", SourceID: "site-a-dmz"},
		source.PeerMapEntry{CIDR: "2001:db8::/32", SourceID: "site-b-v6"},
	)

	cases := map[string]string{
		"10.1.4.7:51544":     "site-a-core-fw",
		"10.1.4.8:51544":     "site-a-dmz",
		"10.1.9.1:51544":     "site-a",
		"10.2.0.1:51544":     "listener",
		"[2001:db8::1]:5140": "site-b-v6",
		"[2001:dead::1]:514": "listener",

		// Bare addresses, no port.
		"10.1.4.7": "site-a-core-fw",
		"::1":      "listener",

		// A dual-stack listener reports IPv4 peers as ::ffff:a.b.c.d. Without
		// unmapping, every IPv4 rule would silently miss.
		"[::ffff:10.1.4.7]:51544": "site-a-core-fw",

		// Nonsense must fall back rather than fail.
		"not-an-address": "listener",
		"":               "listener",
	}
	for addr, want := range cases {
		if got := pm.Lookup(addr, "listener"); got != want {
			t.Errorf("Lookup(%q) = %q, want %q", addr, got, want)
		}
	}
}

// TestPeerMapNilIsUsable: an empty configuration must not need special-casing
// at every call site.
func TestPeerMapNilIsUsable(t *testing.T) {
	var pm *source.PeerMap
	if got := pm.Lookup("10.1.4.7:1", "fallback"); got != "fallback" {
		t.Errorf("a nil peer map returned %q", got)
	}
	if pm.Len() != 0 {
		t.Error("a nil peer map reports entries")
	}

	empty, err := source.NewPeerMap(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := empty.Lookup("10.1.4.7:1", "fallback"); got != "fallback" {
		t.Errorf("an empty peer map returned %q", got)
	}
}

// TestPeerMapNormalisesPrefixes. 10.1.4.7/24 is a host address with a network
// mask, which netip.Prefix.Contains rejects outright unless it is masked
// first. Left unmasked it matches nothing, which looks like the feature
// silently not working.
func TestPeerMapNormalisesPrefixes(t *testing.T) {
	pm := mustPeerMap(t, source.PeerMapEntry{CIDR: "10.1.4.7/24", SourceID: "site"})
	for _, addr := range []string{"10.1.4.1:1", "10.1.4.7:1", "10.1.4.250:1"} {
		if got := pm.Lookup(addr, "listener"); got != "site" {
			t.Errorf("Lookup(%q) = %q, want site", addr, got)
		}
	}
}

func TestPeerMapValidation(t *testing.T) {
	bad := [][]source.PeerMapEntry{
		{{CIDR: "not-a-cidr", SourceID: "x"}},
		{{CIDR: "10.1.0.0/16", SourceID: ""}},
		{{CIDR: "10.1.0.0/16", SourceID: "has space"}},
		{{CIDR: "10.1.0.0/16", SourceID: "has/slash"}},
		{{CIDR: "10.1.0.0", SourceID: "x"}}, // a bare address, not a prefix
		{{CIDR: "10.1.0.0/99", SourceID: "x"}},
	}
	for _, entries := range bad {
		if _, err := source.NewPeerMap(entries); err == nil {
			t.Errorf("%+v was accepted", entries)
		}
	}
}

// TestPeerMapOnUDP: a single UDP socket hears from every device, so the id is
// resolved per datagram rather than once.
func TestPeerMapOnUDP(t *testing.T) {
	pm := mustPeerMap(t, source.PeerMapEntry{CIDR: "127.0.0.0/8", SourceID: "loopback-fw"})

	src, err := source.NewUDP(source.UDPConfig{
		ID: "syslog-udp", Listen: "127.0.0.1:0", PeerMap: pm,
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
	conn.Write([]byte("<134>from a mapped peer"))

	got := h.waitFor(1)
	if got[0].SourceID != "loopback-fw" {
		t.Errorf("source is %q, want the peer map's id", got[0].SourceID)
	}
}

// TestPeerMapOnTCP: resolved once per connection, because the peer cannot
// change mid-stream.
func TestPeerMapOnTCP(t *testing.T) {
	pm := mustPeerMap(t, source.PeerMapEntry{CIDR: "127.0.0.1/32", SourceID: "site-a-fw"})

	src, err := source.NewTCP(source.TCPConfig{
		ID: "syslog-tcp", Listen: "127.0.0.1:0", PeerMap: pm,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := start(t, src)

	conn, err := net.Dial("tcp", src.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("one\ntwo\n"))
	conn.Close()

	got := h.waitFor(2)
	for _, ev := range got {
		if ev.SourceID != "site-a-fw" {
			t.Errorf("record %d has source %q, want site-a-fw", ev.ID, ev.SourceID)
		}
	}
}

// TestPeerMapFallsBackRatherThanDropping. A device that starts sending before
// anyone adds its CIDR is still ingested, just under the listener's name.
// Refusing it would drop data over a bookkeeping omission.
func TestPeerMapFallsBackRatherThanDropping(t *testing.T) {
	pm := mustPeerMap(t, source.PeerMapEntry{CIDR: "192.0.2.0/24", SourceID: "somewhere-else"})

	src, err := source.NewTCP(source.TCPConfig{
		ID: "syslog-tcp", Listen: "127.0.0.1:0", PeerMap: pm,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := start(t, src)

	conn, err := net.Dial("tcp", src.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("unmapped but not lost\n"))
	conn.Close()

	got := h.waitFor(1)
	if got[0].SourceID != "syslog-tcp" {
		t.Errorf("source is %q, want the listener's own id", got[0].SourceID)
	}
	if string(got[0].Raw) != "unmapped but not lost" {
		t.Errorf("payload is %q", got[0].Raw)
	}
}

func BenchmarkPeerMapLookup(b *testing.B) {
	var entries []source.PeerMapEntry
	for i := 0; i < 64; i++ {
		entries = append(entries, source.PeerMapEntry{
			CIDR:     net.IPv4(10, byte(i), 0, 0).String() + "/16",
			SourceID: "site",
		})
	}
	pm, err := source.NewPeerMap(entries)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pm.Lookup("10.63.4.7:51544", "listener")
	}
}

var _ = time.Second
