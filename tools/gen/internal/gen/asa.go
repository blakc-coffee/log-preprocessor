package gen

import (
	"fmt"
	"math/rand/v2"
	"time"
)

// asaMsgIDs is exactly the set of ASA message IDs the corpus contains. The
// Cisco ASA parser is written against this list, so it must not grow without a
// matching change on the parsing side.
//
//	302013 Built inbound/outbound TCP connection
//	302014 Teardown TCP connection
//	302015 Built UDP connection
//	302016 Teardown UDP connection
//	106023 Deny by access-group
//	106100 access-list permitted/denied, with hit count
//	305011 Built dynamic translation (NAT)
var asaMsgIDs = []int{302013, 302014, 302015, 302016, 106023, 106100, 305011}

// asaSeverity is the syslog severity ASA stamps on each message id. It appears
// twice in the line: inside the PRI, and in the %ASA-<sev>- prefix.
var asaSeverity = map[int]int{
	302013: 6, 302014: 6, 302015: 6, 302016: 6,
	106023: 4, 106100: 6, 305011: 6,
}

// asaFacility is local4, so PRI = 20*8 + severity.
const asaFacility = 20

func asaSource() *Source {
	return &Source{
		Name: "cisco_asa.log", IDPrefix: "asa", Term: TermLF,
		Full: 2000, Sample: 50, Emit: emitASA,
	}
}

func emitASA(w *Writer, rng *rand.Rand, n int) {
	t := BaseTime
	connID := 1000
	for i := 0; i < n; i++ {
		t = t.Add(time.Duration(1+rng.IntN(3000)) * time.Millisecond)
		msg := asaMsgIDs[rng.IntN(len(asaMsgIDs))]
		connID++

		inside := privateIP(rng)
		outside := publicIP(rng)
		lport := ephemeralPort(rng)
		rport := servicePort(rng)
		sev := asaSeverity[msg]
		pri := asaFacility*8 + sev
		// ASA renders whole seconds only; the manifest's expected_time matches.
		ts := t.Truncate(time.Second)
		head := fmt.Sprintf("<%d>%s asa01 : %%ASA-%d-%d: ", pri, ts.Format("Jan _2 2006 15:04:05"), sev, msg)

		var body string
		e := Expect{Expect: "parse", Vendor: "cisco_asa", Time: ts}

		switch msg {
		case 302013:
			body = fmt.Sprintf("Built inbound TCP connection %d for outside:%s/%d (%s/%d) to inside:%s/%d (%s/%d)",
				connID, outside, rport, outside, rport, inside, lport, inside, lport)
			e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.Proto, e.Action = outside, rport, inside, lport, "tcp", "Built"
		case 302014:
			body = fmt.Sprintf("Teardown TCP connection %d for outside:%s/%d to inside:%s/%d duration 0:%02d:%02d bytes %d TCP FINs",
				connID, outside, rport, inside, lport, rng.IntN(60), rng.IntN(60), 64+rng.IntN(1<<16))
			e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.Proto, e.Action = outside, rport, inside, lport, "tcp", "Teardown"
		case 302015:
			body = fmt.Sprintf("Built outbound UDP connection %d for outside:%s/%d (%s/%d) to inside:%s/%d (%s/%d)",
				connID, outside, 53, outside, 53, inside, lport, inside, lport)
			e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.Proto, e.Action = inside, lport, outside, 53, "udp", "Built"
		case 302016:
			body = fmt.Sprintf("Teardown UDP connection %d for outside:%s/%d to inside:%s/%d duration 0:00:%02d bytes %d",
				connID, outside, 53, inside, lport, rng.IntN(60), 64+rng.IntN(4096))
			e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.Proto, e.Action = inside, lport, outside, 53, "udp", "Teardown"
		case 106023:
			proto := []string{"tcp", "udp", "icmp"}[rng.IntN(3)]
			body = fmt.Sprintf("Deny %s src outside:%s/%d dst inside:%s/%d by access-group \"outside_access_in\" [0x0, 0x0]",
				proto, outside, ephemeralPort(rng), inside, rport)
			e.SrcIP, e.DstIP, e.DstPort, e.Proto, e.Action = outside, inside, rport, proto, "Deny"
		case 106100:
			body = fmt.Sprintf("access-list outside_access_in permitted tcp outside/%s(%d) -> inside/%s(%d) hit-cnt %d first hit [0x%08x, 0x0]",
				outside, rport, inside, lport, 1+rng.IntN(99), rng.Uint32())
			e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.Proto, e.Action = outside, rport, inside, lport, "tcp", "permitted"
		case 305011:
			nat := fmt.Sprintf("198.51.100.%d", 1+rng.IntN(254))
			body = fmt.Sprintf("Built dynamic TCP translation from inside:%s/%d to outside:%s/%d",
				inside, lport, nat, 1024+rng.IntN(64511))
			e.SrcIP, e.SrcPort, e.DstIP, e.Proto, e.Action = inside, lport, nat, "tcp", "Built"
		}
		w.EmitString(head+body, "", e)
	}
}
