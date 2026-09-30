package enrich

import (
	"testing"

	types "github.com/dark-14100/sluice/pkg/types"
)

// A VPN exit line names only the peer. It must release the address that same
// peer Learned, and be dropped when the peer was never seen.
func TestVPNExitReleasesLearnedAddress(t *testing.T) {
	e := New(nil, nil)
	learn := types.IdentityFact{Kind: "vpn", Action: "bind", IP: "10.8.0.5", User: "carol", Host: "203.0.113.9"}
	if !e.completeVPN(&learn) {
		t.Fatal("a Learn with an address must be usable")
	}
	exit := types.IdentityFact{Kind: "vpn", Action: "release", User: "carol", Host: "203.0.113.9"}
	if !e.completeVPN(&exit) || exit.IP != "10.8.0.5" {
		t.Fatalf("exit should release 10.8.0.5, got %+v", exit)
	}
	again := types.IdentityFact{Kind: "vpn", Action: "release", User: "carol", Host: "203.0.113.9"}
	if e.completeVPN(&again) {
		t.Fatal("a second exit has nothing to release")
	}
	other := types.IdentityFact{Kind: "vpn", Action: "release", User: "dave", Host: "203.0.113.9"}
	if e.completeVPN(&other) {
		t.Fatal("a different user's exit must not release carol's address")
	}
	dhcp := types.IdentityFact{Kind: "dhcp", Action: "release", IP: "10.1.4.9"}
	if !e.completeVPN(&dhcp) {
		t.Fatal("non-VPN facts pass through untouched")
	}
}
