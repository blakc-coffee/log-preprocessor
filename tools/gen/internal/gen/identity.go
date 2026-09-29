package gen

import (
	"fmt"
	"hash/fnv"
	"sort"
	"time"
)

// The identity scenario is the ground truth behind requirement (h): perimeter
// logs carry an IP and nothing else, so who was behind 10.1.4.7 at 09:30 can
// only be answered from DHCP, RADIUS and VPN evidence, and the answer changes
// when the address is reassigned.
//
// Every IP in the scenario is leased twice with a gap between the tenancies,
// so a resolver that ignores time gets the second tenant wrong, and one that
// ignores the gap invents a user for traffic seen inside it. Both are the
// mistakes this corpus exists to catch.
//
// The scenario is built from the run seed alone, so all four identity files
// agree without sharing any mutable state between their emitters.

// identityIPs are the addresses that get reassigned. 10.1.4.7 is the worked
// example from the PRD; the rest vary the gap length from 45 seconds to 30
// minutes.
var identityIPs = []string{
	"10.1.4.7", "10.1.4.8", "10.1.4.9", "10.1.4.10", "10.1.4.11",
	"10.1.4.12", "10.1.4.13", "10.1.4.14", "10.1.4.15",
}

// identityGaps is the unleased interval between the two tenancies of each IP,
// index-aligned with identityIPs. Short gaps are the hard cases: a resolver
// that rounds or pads its intervals will bridge them and answer with the wrong
// user.
var identityGaps = []time.Duration{
	5*time.Minute + 18*time.Second, // 10.1.4.7, the worked example
	1 * time.Minute,
	30 * time.Minute,
	2 * time.Minute,
	12 * time.Minute,
	45 * time.Second, // shortest gap
	8 * time.Minute,
	20 * time.Minute,
	3 * time.Minute,
}

// Tenancy is one (ip, user, host, mac) binding over a closed or open time
// interval. It is the unit identity_truth.json records.
type Tenancy struct {
	IP   string
	User string
	Host string
	MAC  string

	// Ack is the DHCPACK: the first moment the address is bound.
	Ack time.Time
	// RadiusStart and RadiusStop bracket the accounting session. A tenancy
	// with no stop is still open when the corpus ends.
	RadiusStart time.Time
	RadiusStop  time.Time
	HasStop     bool
	// Release is the DHCPRELEASE that ends the tenancy. Without one the
	// interval is open-ended.
	Release    time.Time
	HasRelease bool
	// VPNPeer, when set, adds OpenVPN evidence overlapping the RADIUS session
	// for the same user, so the resolver has to merge two evidence kinds for
	// one binding rather than emit the entity twice.
	VPNPeer string
}

// From is the start of the tenancy's truth interval.
func (t Tenancy) From() time.Time { return t.Ack }

// To is the end of the truth interval, or the zero time when still open.
func (t Tenancy) To() time.Time {
	if t.HasRelease {
		return t.Release
	}
	if t.HasStop {
		return t.RadiusStop
	}
	return time.Time{}
}

// Covers reports whether the tenancy answers for the address at t. The
// interval is half-open: the address is bound from the ACK up to, but not
// including, the release.
func (t Tenancy) Covers(at time.Time) bool {
	if at.Before(t.Ack) {
		return false
	}
	to := t.To()
	return to.IsZero() || at.Before(to)
}

// ResolutionCase is one "who was on this address at this instant" question and
// its answer. An empty User means the correct answer is "nobody": the address
// was unleased. These are what B7's resolver is scored against.
type ResolutionCase struct {
	IP   string
	At   time.Time
	User string
}

// Scenario is the whole identity ground truth for one seed.
type Scenario struct {
	Tenancies []Tenancy
	Cases     []ResolutionCase
}

// hostFor names the machine a user is on. The same user on two addresses uses
// two different devices, which is what makes that case realistic rather than a
// contradiction.
func hostFor(user, device string) string { return device + "-" + user }

func macFor(host string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(host))
	s := h.Sum32()
	// aa:bb:cc is a locally administered prefix, so no fixture MAC can collide
	// with a real vendor OUI.
	return fmt.Sprintf("aa:bb:cc:%02x:%02x:%02x", byte(s>>16), byte(s>>8), byte(s))
}

// dashMAC is the Calling-Station-Id spelling RADIUS uses.
func dashMAC(mac string) string {
	out := []byte(mac)
	for i := range out {
		if out[i] == ':' {
			out[i] = '-'
		}
	}
	return string(out)
}

// buildScenario derives the whole identity ground truth from the run seed.
// It is a pure function: every identity emitter calls it and gets the same
// answer, which is what keeps dhcp.log, radius.log, openvpn.log and
// identity_firewall.log consistent with identity_truth.json.
func buildScenario(seed uint64) Scenario {
	rng := rngFor(seed, "identity-scenario")
	var sc Scenario

	for i, ip := range identityIPs {
		// Tenancy A opens a few minutes into the corpus and runs for 40 to 70
		// minutes.
		ackA := BaseTime.Add(time.Duration(i) * 37 * time.Second)
		if ip == "10.1.4.7" {
			ackA = BaseTime // the worked example starts exactly at 09:00:00
		}
		sessionA := time.Duration(40+rng.IntN(30)) * time.Minute
		stopA := ackA.Add(sessionA)
		releaseA := stopA.Add(time.Duration(30+rng.IntN(150)) * time.Second)
		ackB := releaseA.Add(identityGaps[i])

		userA := identityUsers[i]

		// One user on two addresses at once: alice holds 10.1.4.7 on her
		// laptop and 10.1.4.12 on her phone over overlapping intervals. A
		// resolver keyed only on user, rather than on (ip, time), gets this
		// wrong.
		device := "laptop"
		if ip == "10.1.4.12" {
			userA, device = "alice", "phone"
		}

		// The second tenant must be somebody else, or the address is never
		// really reassigned and the whole point of the fixture is lost. The
		// alice override above collides with the default choice on
		// 10.1.4.12, so walk forward until the users differ.
		userB := identityUsers[(i+5)%len(identityUsers)]
		for step := 1; userB == userA; step++ {
			userB = identityUsers[(i+5+step)%len(identityUsers)]
		}

		hostA := hostFor(userA, device)
		hostB := hostFor(userB, "laptop")

		a := Tenancy{
			IP: ip, User: userA, Host: hostA, MAC: macFor(hostA),
			Ack:         ackA,
			RadiusStart: ackA.Add(time.Duration(3+rng.IntN(20)) * time.Second),
			RadiusStop:  stopA, HasStop: true,
			Release: releaseA, HasRelease: true,
		}
		// Overlapping RADIUS and VPN evidence for one address: the same user
		// is attested by two independent sources over overlapping windows.
		if ip == "10.1.4.9" {
			a.VPNPeer = fmt.Sprintf("203.0.113.%d:%d", 40+i, ephemeralPort(rng))
		}

		b := Tenancy{
			IP: ip, User: userB, Host: hostB, MAC: macFor(hostB),
			Ack:         ackB,
			RadiusStart: ackB.Add(time.Duration(3+rng.IntN(20)) * time.Second),
			// Tenancy B is still open when the corpus ends: no stop, no
			// release. Its truth interval is open-ended.
		}
		sc.Tenancies = append(sc.Tenancies, a, b)

		// Five questions per address: two inside tenancy A, one inside the
		// gap where the answer must be "nobody", and two inside tenancy B.
		gapMid := releaseA.Add(identityGaps[i] / 2)
		sc.Cases = append(sc.Cases,
			ResolutionCase{ip, ackA.Add(sessionA / 4), userA},
			ResolutionCase{ip, ackA.Add(sessionA / 2), userA},
			ResolutionCase{ip, gapMid, ""},
			ResolutionCase{ip, ackB.Add(7 * time.Minute), userB},
			ResolutionCase{ip, ackB.Add(25 * time.Minute), userB},
		)
	}

	sort.SliceStable(sc.Cases, func(i, j int) bool { return sc.Cases[i].At.Before(sc.Cases[j].At) })
	return sc
}

// event is one line waiting to be written, with the time it sorts by. Emitters
// build the scenario lines and the background lines separately and then merge
// them by time, which is how a real collector would have received them.
type event struct {
	at   time.Time
	seq  int // tie-break, so equal timestamps keep a stable order
	line string
	exp  Expect
}

func writeMerged(w *Writer, evs []event, n int) {
	sort.SliceStable(evs, func(i, j int) bool {
		if evs[i].at.Equal(evs[j].at) {
			return evs[i].seq < evs[j].seq
		}
		return evs[i].at.Before(evs[j].at)
	})
	for i, e := range evs {
		if i >= n {
			break
		}
		w.EmitString(e.line, "", e.exp)
	}
}

// syslogHead is the classic RFC 3164 timestamp-host-tag prefix these daemons
// write. It carries no zone, so IST is declared in the manifest instead.
func syslogHead(at time.Time, host, tag string, pid int) string {
	return fmt.Sprintf("%s %s %s[%d]: ", at.Format("Jan _2 15:04:05"), host, tag, pid)
}
