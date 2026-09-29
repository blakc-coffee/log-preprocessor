package gen

import (
	"fmt"
	"math/rand/v2"
	"time"
)

// The four identity-scenario files. Each builds its scenario lines from
// buildScenario(seed), then merges background traffic in by time, so the
// scenario is never the only thing in the file and a parser cannot pass by
// special-casing it.

func dhcpSource() *Source {
	return &Source{
		Name: "dhcp.log", IDPrefix: "dhcp", Term: TermLF,
		// The identity files are small and are the Contracts workstream's
		// hand-off, so the sample profile carries the complete scenario
		// rather than a slice of it.
		Full: 200, Sample: 200, Emit: emitDHCP,
	}
}

func radiusSource() *Source {
	return &Source{
		Name: "radius.log", IDPrefix: "rad", Term: TermLF,
		Full: 100, Sample: 100, Emit: emitRADIUS,
	}
}

func openvpnSource() *Source {
	return &Source{
		Name: "openvpn.log", IDPrefix: "ovpn", Term: TermLF,
		Full: 60, Sample: 60, Emit: emitOpenVPN,
	}
}

func identityFirewallSource() *Source {
	return &Source{
		Name: "identity_firewall.log", IDPrefix: "idfw", Term: TermLF,
		Full: identityCases, Sample: identityCases, Emit: emitIdentityFirewall,
	}
}

// casesPerIP is how many resolution questions each address poses: two inside
// tenancy A, one inside the unleased gap, two inside tenancy B.
const casesPerIP = 5

// identityCases is the total number of firewall records in the scenario.
var identityCases = len(identityIPs) * casesPerIP

// ---------------------------------------------------------------- dhcp.log

func emitDHCP(w *Writer, rng *rand.Rand, n int) {
	sc := buildScenario(w.seed)
	var evs []event
	seq := 0
	add := func(at time.Time, line string, e Expect) {
		evs = append(evs, event{at: at, seq: seq, line: line, exp: e})
		seq++
	}

	for _, t := range sc.Tenancies {
		e := Expect{Expect: "parse", Vendor: "isc_dhcpd", SrcIP: t.IP, User: t.User}
		// The REQUEST precedes the ACK by a second; the ACK is the binding.
		req := t.Ack.Add(-1 * time.Second)
		add(req, syslogHead(req, "dhcp01", "dhcpd", 1123)+
			fmt.Sprintf("DHCPREQUEST for %s from %s (%s) via eth1", t.IP, t.MAC, t.Host),
			withTime(e, req))
		add(t.Ack, syslogHead(t.Ack, "dhcp01", "dhcpd", 1123)+
			fmt.Sprintf("DHCPACK on %s to %s (%s) via eth1", t.IP, t.MAC, t.Host),
			withTime(e, t.Ack))
		if t.HasRelease {
			add(t.Release, syslogHead(t.Release, "dhcp01", "dhcpd", 1123)+
				fmt.Sprintf("DHCPRELEASE of %s from %s (%s) via eth1 (found)", t.IP, t.MAC, t.Host),
				withTime(e, t.Release))
		}
	}

	// Background: other subnets, other machines, the full message mix.
	for at := BaseTime; len(evs) < n; at = at.Add(time.Duration(1+rng.IntN(45)) * time.Second) {
		ip := fmt.Sprintf("10.%d.%d.%d", 1+rng.IntN(4), 5+rng.IntN(20), 2+rng.IntN(250))
		host := fmt.Sprintf("host-%03d", rng.IntN(400))
		mac := macFor(host)
		var line string
		switch rng.IntN(5) {
		case 0:
			line = fmt.Sprintf("DHCPDISCOVER from %s via eth1", mac)
		case 1:
			line = fmt.Sprintf("DHCPOFFER on %s to %s (%s) via eth1", ip, mac, host)
		case 2:
			line = fmt.Sprintf("DHCPREQUEST for %s from %s (%s) via eth1", ip, mac, host)
		case 3:
			line = fmt.Sprintf("DHCPACK on %s to %s (%s) via eth1", ip, mac, host)
		default:
			line = fmt.Sprintf("DHCPRELEASE of %s from %s (%s) via eth1 (found)", ip, mac, host)
		}
		add(at, syslogHead(at, "dhcp01", "dhcpd", 1123)+line,
			Expect{Expect: "parse", Vendor: "isc_dhcpd", SrcIP: ip, Time: at})
	}
	writeMerged(w, evs, n)
}

// -------------------------------------------------------------- radius.log

func emitRADIUS(w *Writer, rng *rand.Rand, n int) {
	sc := buildScenario(w.seed)
	var evs []event
	seq := 0
	add := func(at time.Time, line string, e Expect) {
		evs = append(evs, event{at: at, seq: seq, line: line, exp: e})
		seq++
	}

	for i, t := range sc.Tenancies {
		sid := fmt.Sprintf("%08X", 0xA1B20000+i)
		e := Expect{Expect: "parse", Vendor: "freeradius", SrcIP: t.IP, User: t.User}
		add(t.RadiusStart, syslogHead(t.RadiusStart, "radius01", "radiusd", 2201)+
			fmt.Sprintf("Acct-Status-Type=Start User-Name=%q Framed-IP-Address=%s Calling-Station-Id=%q "+
				"NAS-IP-Address=10.1.0.1 NAS-Port-Type=Ethernet Acct-Session-Id=%q",
				t.User, t.IP, dashMAC(t.MAC), sid),
			withTime(e, t.RadiusStart))
		if t.HasStop {
			add(t.RadiusStop, syslogHead(t.RadiusStop, "radius01", "radiusd", 2201)+
				fmt.Sprintf("Acct-Status-Type=Stop User-Name=%q Framed-IP-Address=%s Calling-Station-Id=%q "+
					"NAS-IP-Address=10.1.0.1 NAS-Port-Type=Ethernet Acct-Session-Id=%q "+
					"Acct-Session-Time=%d Acct-Terminate-Cause=User-Request",
					t.User, t.IP, dashMAC(t.MAC), sid, int(t.RadiusStop.Sub(t.RadiusStart).Seconds())),
				withTime(e, t.RadiusStop))
		}
	}

	for at := BaseTime; len(evs) < n; at = at.Add(time.Duration(1+rng.IntN(90)) * time.Second) {
		user := fmt.Sprintf("svc-%02d", rng.IntN(40))
		ip := fmt.Sprintf("10.%d.%d.%d", 1+rng.IntN(4), 5+rng.IntN(20), 2+rng.IntN(250))
		host := "host-" + user
		kind := "Start"
		extra := ""
		if rng.IntN(2) == 0 {
			kind = "Stop"
			extra = fmt.Sprintf(" Acct-Session-Time=%d Acct-Terminate-Cause=User-Request", 60+rng.IntN(7200))
		}
		add(at, syslogHead(at, "radius01", "radiusd", 2201)+
			fmt.Sprintf("Acct-Status-Type=%s User-Name=%q Framed-IP-Address=%s Calling-Station-Id=%q "+
				"NAS-IP-Address=10.1.0.1 NAS-Port-Type=Ethernet Acct-Session-Id=%q%s",
				kind, user, ip, dashMAC(macFor(host)), fmt.Sprintf("%08X", rng.Uint32()), extra),
			Expect{Expect: "parse", Vendor: "freeradius", SrcIP: ip, User: user, Time: at})
	}
	writeMerged(w, evs, n)
}

// ------------------------------------------------------------- openvpn.log

func emitOpenVPN(w *Writer, rng *rand.Rand, n int) {
	sc := buildScenario(w.seed)
	var evs []event
	seq := 0
	add := func(at time.Time, line string, e Expect) {
		evs = append(evs, event{at: at, seq: seq, line: line, exp: e})
		seq++
	}

	for _, t := range sc.Tenancies {
		if t.VPNPeer == "" {
			continue
		}
		// VPN evidence that overlaps the RADIUS session for the same address
		// and user: two independent sources attesting one binding.
		peer := t.User + "/" + t.VPNPeer
		start := t.RadiusStart.Add(2 * time.Minute)
		end := t.RadiusStop.Add(-3 * time.Minute)
		e := Expect{Expect: "parse", Vendor: "openvpn", SrcIP: t.IP, User: t.User}
		add(start, syslogHead(start, "vpn01", "openvpn", 3301)+
			fmt.Sprintf("%s [%s] Peer Connection Initiated with [AF_INET]%s", peer, t.User, t.VPNPeer),
			withTime(e, start))
		add(start.Add(time.Second), syslogHead(start.Add(time.Second), "vpn01", "openvpn", 3301)+
			fmt.Sprintf("%s MULTI: Learn: %s -> %s", peer, t.IP, peer),
			withTime(e, start.Add(time.Second)))
		add(end, syslogHead(end, "vpn01", "openvpn", 3301)+
			fmt.Sprintf("%s SIGTERM[soft,remote-exit] received, client-instance exiting", peer),
			withTime(e, end))
	}

	// Background VPN users live on the 10.8.0.0/24 tunnel subnet, which is
	// what OpenVPN normally hands out.
	for at := BaseTime; len(evs) < n; at = at.Add(time.Duration(10+rng.IntN(180)) * time.Second) {
		user := identityUsers[rng.IntN(len(identityUsers))]
		peer := fmt.Sprintf("%s/203.0.113.%d:%d", user, 100+rng.IntN(150), ephemeralPort(rng))
		tun := fmt.Sprintf("10.8.0.%d", 2+rng.IntN(250))
		e := Expect{Expect: "parse", Vendor: "openvpn", SrcIP: tun, User: user, Time: at}
		var line string
		switch rng.IntN(3) {
		case 0:
			line = fmt.Sprintf("%s [%s] Peer Connection Initiated with [AF_INET]%s",
				peer, user, peer[len(user)+1:])
		case 1:
			line = fmt.Sprintf("%s MULTI: Learn: %s -> %s", peer, tun, peer)
		default:
			line = fmt.Sprintf("%s SIGTERM[soft,remote-exit] received, client-instance exiting", peer)
		}
		add(at, syslogHead(at, "vpn01", "openvpn", 3301)+line, e)
	}
	writeMerged(w, evs, n)
}

// --------------------------------------------------- identity_firewall.log

// emitIdentityFirewall writes one ASA connection event per resolution case.
// These are the records requirement (h) is actually scored on: each carries
// only an IP, and the manifest's expected_user is the answer a correct
// resolver must produce for that address at that instant - including the
// records inside a lease gap, where the correct answer is no user at all.
//
// They live in their own file rather than inside cisco_asa.log so the identity
// test can ingest exactly the records it reasons about, and so cisco_asa.log
// stays a plain vendor-format fixture.
func emitIdentityFirewall(w *Writer, rng *rand.Rand, n int) {
	sc := buildScenario(w.seed)
	connID := 5000

	for i, c := range sc.Cases {
		if i >= n {
			break
		}
		connID++
		ts := c.At.Truncate(time.Second)
		dst := publicIP(rng)
		sport := ephemeralPort(rng)
		dport := servicePort(rng)

		line := fmt.Sprintf(
			"<166>%s asa01 : %%ASA-6-302013: Built outbound TCP connection %d for inside:%s/%d (%s/%d) to outside:%s/%d (%s/%d)",
			ts.Format("Jan _2 2006 15:04:05"), connID,
			c.IP, sport, c.IP, sport, dst, dport, dst, dport)

		w.EmitString(line, "", Expect{
			Expect: "parse", Vendor: "cisco_asa", Time: ts,
			SrcIP: c.IP, SrcPort: sport, DstIP: dst, DstPort: dport,
			Proto: "tcp", Action: "Built",
			// Empty means the address was unleased: expected_user is null and
			// a resolver that names somebody is wrong.
			User: c.User,
		})
	}
}

// withTime copies e with the event time set, so the shared per-tenancy Expect
// can be reused across lines that happen at different instants.
func withTime(e Expect, at time.Time) Expect {
	e.Time = at
	return e
}
