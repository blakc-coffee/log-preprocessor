package gen

import (
	"fmt"
	"math/rand/v2"
	"time"
)

func fortinetDriftSource() *Source {
	return &Source{
		Name: "fortinet_drift.log", IDPrefix: "fgtd", Term: TermLF,
		Full: 500, Sample: 50, Emit: emitFortinetDrift,
	}
}

// emitFortinetDrift is fortinet.log after a notional firmware upgrade. It is
// the same device emitting the same facts through a changed layout, which is
// exactly the failure the self-healing path exists for: the existing parser
// stops matching, the records quarantine, and the sidecar has to notice the
// structure moved rather than the traffic changing.
//
// Four drift signals, each independently detectable:
//
//  1. keys renamed:   srcip->src, dstip->dst, srcport->sport, dstport->dport
//  2. time replaced:  date=/time= gone, epoch eventtime= in their place
//  3. values changed: action=blocked / action=passed, and unquoted
//  4. layout moved:   field order reshuffled, new keys (srcmac, dstcountry,
//     utmaction, craction) appear
func emitFortinetDrift(w *Writer, rng *rand.Rand, n int) {
	t := BaseTime
	for i := 0; i < n; i++ {
		t = t.Add(time.Duration(1+rng.IntN(3000)) * time.Millisecond)
		ts := t.Truncate(time.Second)

		src := privateIP(rng)
		dst := publicIP(rng)
		sport := ephemeralPort(rng)
		dport := servicePort(rng)
		pnum := []int{6, 6, 6, 17, 1}[rng.IntN(5)]
		proto := fortiProto[pnum]

		// "blocked"/"passed" replace the old quoted "deny"/"accept".
		action := "passed"
		if rng.IntN(3) == 0 {
			action = "blocked"
		}
		level := "notice"
		if action == "blocked" {
			level = "warning"
		}
		svc := fortiServices[dport]
		if pnum == 1 {
			svc, dport = "PING", 0
		}

		line := fmt.Sprintf(
			"eventtime=%d tz=+0530 devname=FG-01 devid=FG100E0000000001 logid=0000000013 "+
				"type=traffic subtype=forward level=%s vd=root "+
				"srcmac=%s src=%s sport=%d srcintf=port1 srcintfrole=lan "+
				"dst=%s dport=%d dstintf=port2 dstintfrole=wan dstcountry=\"United States\" "+
				"proto=%d service=%s action=%s utmaction=%s craction=%d "+
				"policyid=%d sessionid=%d duration=%d "+
				"sentbyte=%d rcvdbyte=%d sentpkt=%d rcvdpkt=%d appcat=unscanned",
			ts.UnixNano(), level,
			randMAC(rng), src, sport,
			dst, dport,
			pnum, svc, action, map[string]string{"passed": "allow", "blocked": "block"}[action],
			[]int{0, 131072, 262144}[rng.IntN(3)],
			1+rng.IntN(20), 100000+rng.IntN(900000), rng.IntN(600),
			rng.IntN(1<<20), rng.IntN(1<<20), rng.IntN(500), rng.IntN(500),
		)

		e := Expect{
			// The drift corpus is ground truth for the proposal's dry run: the
			// sidecar's generated parser has to reproduce these.
			Expect: "unknown_format", Vendor: "fortinet", Time: ts,
			SrcIP: src, SrcPort: sport, DstIP: dst, Proto: proto, Action: action,
		}
		if dport != 0 {
			e.DstPort = dport
		}
		w.EmitString(line, "", e)
	}
}

// randMAC returns a locally administered MAC, so no fixture can collide with a
// real vendor OUI.
func randMAC(rng *rand.Rand) string {
	return fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x",
		rng.IntN(256), rng.IntN(256), rng.IntN(256), rng.IntN(256), rng.IntN(256))
}
