package gen

import (
	"fmt"
	"math/rand/v2"
)

// Address pools. Everything is drawn from ranges reserved for documentation
// (RFC 5737) or private use (RFC 1918), so no fixture can be mistaken for real
// traffic and nothing in the corpus routes anywhere.

// privateIP returns an inside address. 10.1.4.0/24 is the subnet the identity
// scenario reassigns addresses in, so it is drawn more often than the others.
func privateIP(rng *rand.Rand) string {
	if rng.IntN(2) == 0 {
		return fmt.Sprintf("10.1.4.%d", 1+rng.IntN(60))
	}
	return fmt.Sprintf("10.%d.%d.%d", 1+rng.IntN(4), rng.IntN(16), 1+rng.IntN(254))
}

// publicIP returns an outside address from the documentation ranges.
func publicIP(rng *rand.Rand) string {
	switch rng.IntN(3) {
	case 0:
		return fmt.Sprintf("203.0.113.%d", 1+rng.IntN(254))
	case 1:
		return fmt.Sprintf("198.51.100.%d", 1+rng.IntN(254))
	default:
		return fmt.Sprintf("192.0.2.%d", 1+rng.IntN(254))
	}
}

// ephemeralPort returns a client-side source port.
func ephemeralPort(rng *rand.Rand) int { return 32768 + rng.IntN(28232) }

// servicePorts are the destination ports a perimeter device sees most.
var servicePorts = []int{22, 25, 53, 80, 110, 143, 389, 443, 445, 3306, 3389, 5432, 8080, 8443}

// servicePort returns a well-known destination port.
func servicePort(rng *rand.Rand) int { return servicePorts[rng.IntN(len(servicePorts))] }

// identityUsers is the invented user roster shared by every fixture that names
// a person: the multiline VPN gateway events, the RADIUS and OpenVPN identity
// logs, and identity_truth.json. Keeping one roster is what lets the identity
// scenario cross-reference them.
var identityUsers = []string{"alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy"}
