package gen

import (
	"bytes"
	"encoding/json"
	"math/rand/v2"
	"strings"
	"time"
)

func suricataSource() *Source {
	return &Source{
		Name: "suricata.json", IDPrefix: "eve", Term: TermLF,
		Full: 2000, Sample: 50, Emit: emitSuricata,
	}
}

// eveTimeFormat is Suricata's EVE timestamp: microseconds, numeric zone with
// no colon.
const eveTimeFormat = "2006-01-02T15:04:05.000000-0700"

// eveEvent is one EVE JSON line. Key order comes from the struct field order,
// which is what keeps the output byte-identical across runs; a map would not.
type eveEvent struct {
	Timestamp string    `json:"timestamp"`
	FlowID    uint64    `json:"flow_id"`
	InIface   string    `json:"in_iface"`
	EventType string    `json:"event_type"`
	SrcIP     string    `json:"src_ip"`
	SrcPort   int       `json:"src_port,omitempty"`
	DestIP    string    `json:"dest_ip"`
	DestPort  int       `json:"dest_port,omitempty"`
	Proto     string    `json:"proto"`
	Alert     *eveAlert `json:"alert,omitempty"`
	DNS       *eveDNS   `json:"dns,omitempty"`
	HTTP      *eveHTTP  `json:"http,omitempty"`
	Flow      *eveFlow  `json:"flow,omitempty"`
}

type eveAlert struct {
	Action      string `json:"action"`
	GID         int    `json:"gid"`
	SignatureID int    `json:"signature_id"`
	Rev         int    `json:"rev"`
	Signature   string `json:"signature"`
	Category    string `json:"category"`
	Severity    int    `json:"severity"`
}

type eveDNS struct {
	Type   string `json:"type"`
	ID     int    `json:"id"`
	RRName string `json:"rrname"`
	RRType string `json:"rrtype"`
	TxID   int    `json:"tx_id"`
}

type eveHTTP struct {
	Hostname string `json:"hostname"`
	URL      string `json:"url"`
	UA       string `json:"http_user_agent"`
	Method   string `json:"http_method"`
	Protocol string `json:"protocol"`
	Status   int    `json:"status"`
	Length   int    `json:"length"`
}

type eveFlow struct {
	PktsToServer  int    `json:"pkts_toserver"`
	PktsToClient  int    `json:"pkts_toclient"`
	BytesToServer int    `json:"bytes_toserver"`
	BytesToClient int    `json:"bytes_toclient"`
	Start         string `json:"start"`
	End           string `json:"end"`
	Age           int    `json:"age"`
	State         string `json:"state"`
	Reason        string `json:"reason"`
	Alerted       bool   `json:"alerted"`
}

type eveSig struct {
	id       int
	rev      int
	name     string
	category string
	severity int
}

var eveSigs = []eveSig{
	{2001219, 20, "ET SCAN Potential SSH Scan", "Attempted Information Leak", 2},
	{2013028, 5, "ET POLICY curl User-Agent Outbound", "Attempted Information Leak", 3},
	{2019401, 7, "ET POLICY Possible External IP Lookup", "Device Retrieving External IP Address", 3},
	{2100498, 8, "GPL ATTACK_RESPONSE id check returned root", "Potentially Bad Traffic", 2},
	{2024897, 3, "ET EXPLOIT Possible CVE-2021-44228 Attempt", "Attempted Administrator Privilege Gain", 1},
}

var eveHosts = []string{"updates.example.net", "api.example.com", "cdn.example.org", "mail.example.net"}
var eveUAs = []string{
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
	"curl/8.4.0",
	"python-requests/2.31.0",
}

func emitSuricata(w *Writer, rng *rand.Rand, n int) {
	t := BaseTime
	for i := 0; i < n; i++ {
		t = t.Add(time.Duration(1+rng.IntN(3000)) * time.Millisecond)

		src := publicIP(rng)
		dst := privateIP(rng)
		sport := ephemeralPort(rng)
		dport := servicePort(rng)
		proto := "TCP"

		ev := eveEvent{
			Timestamp: t.Format(eveTimeFormat),
			FlowID:    rng.Uint64N(1 << 52),
			InIface:   "eth0",
			SrcIP:     src, SrcPort: sport,
			DestIP: dst, DestPort: dport,
			Proto: proto,
		}
		e := Expect{
			Expect: "parse", Vendor: "suricata", Time: t,
			SrcIP: src, SrcPort: sport, DstIP: dst, DstPort: dport, Proto: "tcp",
		}

		switch rng.IntN(4) {
		case 0:
			sig := eveSigs[rng.IntN(len(eveSigs))]
			action := "allowed"
			if rng.IntN(3) == 0 {
				action = "blocked"
			}
			ev.EventType = "alert"
			ev.Alert = &eveAlert{
				Action: action, GID: 1, SignatureID: sig.id, Rev: sig.rev,
				Signature: sig.name, Category: sig.category, Severity: sig.severity,
			}
			e.Action = action
		case 1:
			ev.EventType = "dns"
			ev.Proto, e.Proto = "UDP", "udp"
			ev.DestPort, e.DstPort = 53, 53
			ev.DNS = &eveDNS{
				Type: "query", ID: rng.IntN(65536),
				RRName: eveHosts[rng.IntN(len(eveHosts))],
				RRType: []string{"A", "AAAA", "CNAME", "TXT"}[rng.IntN(4)],
			}
		case 2:
			ev.EventType = "http"
			ev.DestPort, e.DstPort = 80, 80
			ev.HTTP = &eveHTTP{
				Hostname: eveHosts[rng.IntN(len(eveHosts))],
				URL:      []string{"/", "/index.html", "/api/v1/status", "/download/pkg.tar.gz"}[rng.IntN(4)],
				UA:       eveUAs[rng.IntN(len(eveUAs))],
				Method:   []string{"GET", "GET", "POST", "HEAD"}[rng.IntN(4)],
				Protocol: "HTTP/1.1",
				Status:   []int{200, 200, 301, 404, 500}[rng.IntN(5)],
				Length:   rng.IntN(1 << 18),
			}
		default:
			age := 1 + rng.IntN(600)
			ev.EventType = "flow"
			ev.Flow = &eveFlow{
				PktsToServer:  1 + rng.IntN(500),
				PktsToClient:  1 + rng.IntN(500),
				BytesToServer: rng.IntN(1 << 20),
				BytesToClient: rng.IntN(1 << 20),
				Start:         t.Format(eveTimeFormat),
				End:           t.Add(time.Duration(age) * time.Second).Format(eveTimeFormat),
				Age:           age,
				State:         []string{"new", "established", "closed"}[rng.IntN(3)],
				Reason:        []string{"timeout", "shutdown", "forced"}[rng.IntN(3)],
			}
		}
		w.EmitString(marshalEVE(ev), "", e)
	}
}

// marshalEVE encodes one EVE line with HTML escaping disabled, so user agents
// and URLs stay byte-faithful to what Suricata would actually write.
func marshalEVE(ev eveEvent) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(ev); err != nil {
		panic("gen: encoding EVE event: " + err.Error())
	}
	return strings.TrimRight(b.String(), "\n")
}
