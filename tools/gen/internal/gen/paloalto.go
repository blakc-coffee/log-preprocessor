package gen

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"time"
)

func paloAltoSource() *Source {
	return &Source{
		Name: "palo_alto_unknown.log", IDPrefix: "pan", Term: TermLF,
		Full: 500, Sample: 50, Emit: emitPaloAlto,
	}
}

// PAN-OS TRAFFIC logs are positional CSV with no header line and several
// FUTURE_USE placeholders, so a column's meaning cannot be read off a key
// name. That is the point of this fixture: it ships with no parser, drives
// quarantine and replay, and is the corpus the semantic typing classifier has
// to work out from value shapes alone.
//
// Field order is the documented PAN-OS traffic layout, 47 columns:
//
//	1 future_use, 2 receive_time, 3 serial, 4 type, 5 subtype, 6 future_use,
//	7 generated_time, 8 src, 9 dst, 10 natsrc, 11 natdst, 12 rule,
//	13 srcuser, 14 dstuser, 15 app, 16 vsys, 17 from_zone, 18 to_zone,
//	19 inbound_if, 20 outbound_if, 21 logset, 22 future_use, 23 sessionid,
//	24 repeatcnt, 25 sport, 26 dport, 27 natsport, 28 natdport, 29 flags,
//	30 proto, 31 action, 32 bytes, 33 bytes_sent, 34 bytes_received,
//	35 packets, 36 start, 37 elapsed, 38 category, 39 future_use,
//	40 seqno, 41 actionflags, 42 srcloc, 43 dstloc, 44 future_use,
//	45 pkts_sent, 46 pkts_received, 47 session_end_reason
const panColumns = 47

var panApps = []string{"web-browsing", "ssl", "dns", "ssh", "smtp", "ms-rdp", "ldap", "mysql"}
var panCategories = []string{"any", "business-and-economy", "computer-and-internet-info", "unknown", "web-advertisements"}
var panEndReasons = []string{"tcp-fin", "tcp-rst-from-client", "tcp-rst-from-server", "aged-out", "policy-deny", "threat"}
var panUsers = []string{"", "corp\\alice", "corp\\bob", "corp\\carol", "corp\\dave"}

func emitPaloAlto(w *Writer, rng *rand.Rand, n int) {
	t := BaseTime
	for i := 0; i < n; i++ {
		t = t.Add(time.Duration(1+rng.IntN(3000)) * time.Millisecond)
		ts := t.Truncate(time.Second)

		src := privateIP(rng)
		dst := publicIP(rng)
		sport := ephemeralPort(rng)
		dport := servicePort(rng)
		natsrc := fmt.Sprintf("198.51.100.%d", 1+rng.IntN(254))
		natsport := 1024 + rng.IntN(64511)

		// PAN-OS writes the protocol by name, not by number.
		proto := "tcp"
		if rng.IntN(5) == 0 {
			proto = "udp"
		}
		action := []string{"allow", "allow", "allow", "deny", "drop"}[rng.IntN(5)]
		subtype := "end"
		if action != "allow" {
			subtype = action
		}
		elapsed := rng.IntN(600)
		sent, recv := rng.IntN(1<<20), rng.IntN(1<<20)
		pktsSent, pktsRecv := 1+rng.IntN(500), 1+rng.IntN(500)
		user := panUsers[rng.IntN(len(panUsers))]

		f := make([]string, 0, panColumns)
		add := func(v ...string) { f = append(f, v...) }
		addf := func(format string, a ...any) { f = append(f, fmt.Sprintf(format, a...)) }

		add("")                                          // 1  future_use
		add(ts.Format("2006/01/02 15:04:05"))            // 2  receive_time
		add("001801010001")                              // 3  serial
		add("TRAFFIC")                                   // 4  type
		add(subtype)                                     // 5  subtype
		add("2049")                                      // 6  future_use
		add(ts.Format("2006/01/02 15:04:05"))            // 7  generated_time
		add(src, dst, natsrc, "0.0.0.0")                 // 8-11 addresses
		add("allow-outbound")                            // 12 rule
		add(user, "")                                    // 13-14 users
		add(panApps[rng.IntN(len(panApps))])             // 15 app
		add("vsys1", "trust", "untrust")                 // 16-18 vsys and zones
		add("ethernet1/2", "ethernet1/1")                // 19-20 interfaces
		add("default-logging", "")                       // 21-22 logset, future_use
		addf("%d", 100000+rng.IntN(900000))              // 23 sessionid
		add("1")                                         // 24 repeatcnt
		addf("%d", sport)                                // 25 sport
		addf("%d", dport)                                // 26 dport
		addf("%d", natsport)                             // 27 natsport
		addf("%d", dport)                                // 28 natdport
		addf("0x%x", 0x400000+rng.IntN(0xffff))          // 29 flags
		add(proto, action)                               // 30-31
		addf("%d", sent+recv)                            // 32 bytes
		addf("%d", sent)                                 // 33 bytes_sent
		addf("%d", recv)                                 // 34 bytes_received
		addf("%d", pktsSent+pktsRecv)                    // 35 packets
		add(ts.Format("2006/01/02 15:04:05"))            // 36 start
		addf("%d", elapsed)                              // 37 elapsed
		add(panCategories[rng.IntN(len(panCategories))]) // 38 category
		add("")                                          // 39 future_use
		addf("%d", 7000000000+rng.IntN(1<<20))           // 40 seqno
		add("0x0")                                       // 41 actionflags
		add("10.0.0.0-10.255.255.255", "US")             // 42-43 locations
		add("")                                          // 44 future_use
		addf("%d", pktsSent)                             // 45
		addf("%d", pktsRecv)                             // 46
		add(panEndReasons[rng.IntN(len(panEndReasons))]) // 47

		if len(f) != panColumns {
			panic(fmt.Sprintf("gen: palo alto row has %d columns, want %d", len(f), panColumns))
		}

		e := Expect{
			// No parser exists for this format at first: it is what drives
			// quarantine, the drift/typing sidecar, and replay from the vault
			// once a parser is approved. The ground truth is still recorded so
			// the replayed result can be checked.
			Expect: "unknown_format", Vendor: "palo_alto", Time: ts,
			SrcIP: src, SrcPort: sport, DstIP: dst, DstPort: dport,
			Proto: proto, Action: action,
		}
		if user != "" {
			e.User = user
		}
		w.EmitString(strings.Join(f, ","), "", e)
	}
}
