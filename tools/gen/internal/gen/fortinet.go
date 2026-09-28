package gen

import (
	"fmt"
	"math/rand/v2"
	"time"
)

func fortinetSource() *Source {
	return &Source{
		Name: "fortinet.log", IDPrefix: "fgt", Term: TermLF,
		Full: 2000, Sample: 50, Emit: emitFortinet,
	}
}

// fortiProto maps the numeric proto field FortiOS emits to the name the
// normalizer is expected to produce.
var fortiProto = map[int]string{6: "tcp", 17: "udp", 1: "icmp"}

var fortiServices = map[int]string{
	22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
	389: "LDAP", 443: "HTTPS", 445: "SMB", 3306: "MYSQL", 3389: "RDP",
	5432: "POSTGRES", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
}

// emitFortinet writes FortiOS traffic logs in the pre-drift key layout:
// `date=`/`time=` separate fields, `srcip`/`dstip` key names, quoted
// `action="deny"`. fortinet_drift.log is the same source after a notional
// firmware upgrade renames and reshapes these, which is what makes the drift
// detectable. Deliberately no `eventtime=` here: that key only appears after
// the drift.
func emitFortinet(w *Writer, rng *rand.Rand, n int) {
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
		action := []string{"accept", "accept", "deny", "close"}[rng.IntN(4)]
		level := "notice"
		if action == "deny" {
			level = "warning"
		}
		svc := fortiServices[dport]
		if pnum == 1 {
			svc, dport = "PING", 0
		}

		line := fmt.Sprintf(
			"date=%s time=%s devname=\"FG-01\" devid=\"FG100E0000000001\" logid=\"0000000013\" "+
				"type=\"traffic\" subtype=\"forward\" level=\"%s\" vd=\"root\" tz=\"+0530\" "+
				"srcip=%s srcport=%d srcintf=\"port1\" srcintfrole=\"lan\" "+
				"dstip=%s dstport=%d dstintf=\"port2\" dstintfrole=\"wan\" "+
				"sessionid=%d proto=%d action=\"%s\" policyid=%d policytype=\"policy\" "+
				"service=\"%s\" trandisp=\"snat\" transip=198.51.100.7 transport=%d "+
				"duration=%d sentbyte=%d rcvdbyte=%d sentpkt=%d rcvdpkt=%d appcat=\"unscanned\"",
			ts.Format("2006-01-02"), ts.Format("15:04:05"), level,
			src, sport, dst, dport,
			100000+rng.IntN(900000), pnum, action, 1+rng.IntN(20),
			svc, ephemeralPort(rng),
			rng.IntN(600), rng.IntN(1<<20), rng.IntN(1<<20), rng.IntN(500), rng.IntN(500),
		)

		e := Expect{
			Expect: "parse", Vendor: "fortinet", Time: ts,
			SrcIP: src, SrcPort: sport, DstIP: dst, Proto: proto, Action: action,
		}
		if dport != 0 {
			e.DstPort = dport
		}
		w.EmitString(line, "", e)
	}
}

func crlfSource() *Source {
	return &Source{
		Name: "crlf.log", IDPrefix: "crlf", Term: TermCRLF,
		Full: 50, Sample: 50, Emit: emitFortinet,
	}
}
