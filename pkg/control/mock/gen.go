package mock

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	types "github.com/blakc-coffee/sluice/pkg/types"
)

// A draft is a raw line together with the normalized event a parser would
// produce from it. The mock writes the raw bytes into its vault and keeps the
// draft so that live ingest, quarantine and replay all describe the same
// record. Nothing here parses: the generator knows the fields because it
// chose them.
type draft struct {
	sourceID string
	raw      []byte
	origin   types.Origin
	term     types.Terminator
	at       time.Time // event time; received_at is at plus a small delay

	// parserID is the parser that accepts the line today. Empty means no
	// active parser matches it, so it goes to quarantine with stage and err.
	parserID string
	stage    string
	err      string

	// laterParser is the parser that will accept a quarantined line once a
	// proposal for it is approved (palo_alto_traffic, or fortinet after drift).
	laterParser string

	vendor, product, extractor string
	activityID, severityID     int
	actionID, dispositionID    int
	proto                      string
	srcIP, dstIP               string
	srcPort, dstPort           int
	bytesIn, bytesOut          int
	message                    string
	unmapped                   map[string]any
	applicable                 bool // render-back applies (regex and kv)
	mappedFields               int
	identity                   *types.IdentityFact
	class                      int
}

var protoNum = map[string]int{"tcp": 6, "udp": 17, "icmp": 1}

var (
	internalHosts = []string{"10.1.4.7", "10.1.4.9", "10.1.4.12", "10.1.4.25", "10.1.4.50", "10.1.7.195", "10.1.11.225", "10.3.0.75"}
	externalHosts = []string{"203.0.113.9", "203.0.113.125", "198.51.100.232", "198.51.100.5", "192.0.2.179", "198.51.100.82", "203.0.113.44", "192.0.2.155"}
	servicePorts  = []int{22, 53, 80, 110, 143, 443, 3306, 5432, 8443}
)

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.IntN(len(xs))] }

func ephemeral(r *rand.Rand) int { return 32768 + r.IntN(28000) }

// asaTime renders the ASA/syslog timestamp. Fixtures carry IST without a zone
// in the line; the parser's timezone supplies it.
func asaTime(t time.Time) string { return t.In(ist).Format("Jan _2 2006 15:04:05") }

var ist = time.FixedZone("IST", 5*3600+30*60)

func genASA(r *rand.Rand, at time.Time, conn int) draft {
	d := draft{sourceID: "cisco_asa", parserID: "cisco_asa", vendor: "cisco", product: "asa", at: at,
		origin: types.Origin{Kind: types.OriginUDP, Addr: "192.0.2.10:514"}, applicable: true, class: 4001}
	d.proto = "tcp"
	if r.IntN(4) == 0 {
		d.proto = "udp"
	}
	if r.IntN(5) == 0 {
		// 106023: an ACL deny, inbound.
		d.srcIP, d.srcPort = pick(r, externalHosts), ephemeral(r)
		d.dstIP, d.dstPort = pick(r, internalHosts), pick(r, servicePorts)
		d.extractor, d.activityID, d.severityID, d.actionID, d.dispositionID = "asa_106023", 5, 3, 2, 2
		d.raw = fmt.Appendf(nil, "<164>%s asa01 : %%ASA-4-106023: Deny %s src outside:%s/%d dst inside:%s/%d by access-group \"outside_access_in\" [0x0, 0x0]",
			asaTime(at), d.proto, d.srcIP, d.srcPort, d.dstIP, d.dstPort)
		d.unmapped = map[string]any{"acl": "outside_access_in", "dst_if": "inside", "hit1": "0x0", "hit2": "0x0", "host": "asa01", "pri": "<164>", "src_if": "outside"}
		d.mappedFields = 11
		return d
	}
	// 302013/302015: a connection is built. Outbound connections start inside.
	dir := "outbound"
	src, dst := pick(r, internalHosts), pick(r, externalHosts)
	if r.IntN(3) == 0 {
		dir = "inbound"
		src, dst = pick(r, externalHosts), pick(r, internalHosts)
	}
	return asaBuilt(d, dir, src, ephemeral(r), dst, pick(r, servicePorts), conn)
}

// asaBuilt renders a 302013 (TCP) or 302015 (UDP) "Built" line. The side
// named after "for" initiated the connection and is the source.
func asaBuilt(d draft, dir, src string, sport int, dst string, dport, conn int) draft {
	id, verb := "302013", "TCP"
	if d.proto == "udp" {
		id, verb = "302015", "UDP"
	}
	srcIf, dstIf := "inside", "outside"
	if dir == "inbound" {
		srcIf, dstIf = "outside", "inside"
	}
	d.srcIP, d.srcPort, d.dstIP, d.dstPort = src, sport, dst, dport
	d.extractor, d.activityID, d.severityID, d.actionID, d.dispositionID = "asa_"+id, 1, 1, 1, 1
	at := d.at
	d.raw = fmt.Appendf(nil, "<166>%s asa01 : %%ASA-6-%s: Built %s %s connection %d for %s:%s/%d (%s/%d) to %s:%s/%d (%s/%d)",
		asaTime(at), id, dir, verb, conn, srcIf, d.srcIP, d.srcPort, d.srcIP, d.srcPort, dstIf, d.dstIP, d.dstPort, d.dstIP, d.dstPort)
	d.unmapped = map[string]any{"conn": fmt.Sprint(conn), "dir": dir, "dst_if": dstIf, "host": "asa01", "pri": "<166>", "src_if": srcIf,
		"src_nat_ip": d.srcIP, "src_nat_port": fmt.Sprint(d.srcPort), "dst_nat_ip": d.dstIP, "dst_nat_port": fmt.Sprint(d.dstPort)}
	d.mappedFields = 11
	return d
}

var fgtActions = []struct {
	word           string
	action, dispos int
}{{"accept", 1, 1}, {"close", 1, 1}, {"deny", 2, 2}, {"timeout", 1, 1}}

// genFortinet emits a FortiOS traffic line. drifted switches to the
// post-"firmware update" layout of fortinet_drift.log: renamed keys, epoch
// eventtime, unquoted action words, new keys. The active fortinet 1.0.0
// parser cannot read it, so it is quarantined.
func genFortinet(r *rand.Rand, at time.Time, session int, drifted bool) draft {
	d := draft{sourceID: "fortinet", parserID: "fortinet", vendor: "fortinet", product: "fortigate", at: at,
		origin: types.Origin{Kind: types.OriginTCP, Addr: "192.0.2.20:40412"}, applicable: true, extractor: "fgt_traffic",
		activityID: 6, severityID: 2, class: 4001}
	d.proto = "tcp"
	if r.IntN(4) == 0 {
		d.proto = "udp"
	}
	a := pick(r, fgtActions)
	d.actionID, d.dispositionID = a.action, a.dispos
	d.srcIP, d.srcPort = pick(r, internalHosts), ephemeral(r)
	d.dstIP, d.dstPort = pick(r, externalHosts), pick(r, servicePorts)
	d.bytesOut, d.bytesIn = 1000+r.IntN(900000), 1000+r.IntN(900000)
	dur := 1 + r.IntN(600)
	local := at.In(ist)
	if !drifted {
		d.raw = fmt.Appendf(nil, `date=%s time=%s devname="FG-01" devid="FG100E0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" tz="+0530" srcip=%s srcport=%d srcintf="port1" srcintfrole="lan" dstip=%s dstport=%d dstintf="port2" dstintfrole="wan" sessionid=%d proto=%d action="%s" policyid=2 policytype="policy" service="HTTPS" duration=%d sentbyte=%d rcvdbyte=%d sentpkt=%d rcvdpkt=%d appcat="unscanned"`,
			local.Format("2006-01-02"), local.Format("15:04:05"), d.srcIP, d.srcPort, d.dstIP, d.dstPort, session, protoNum[d.proto], a.word, dur, d.bytesOut, d.bytesIn, d.bytesOut/1400+1, d.bytesIn/1400+1)
		d.unmapped = map[string]any{"appcat": "unscanned", "devid": "FG100E0000000001", "devname": "FG-01", "dstintf": "port2", "dstintfrole": "wan",
			"logid": "0000000013", "policyid": "2", "policytype": "policy", "service": "HTTPS", "sessionid": fmt.Sprint(session),
			"srcintf": "port1", "srcintfrole": "lan", "subtype": "forward", "type": "traffic", "tz": "+0530", "vd": "root"}
		d.mappedFields = 16
		return d
	}
	word := map[string]string{"accept": "passed", "close": "passed", "deny": "blocked", "timeout": "passed"}[a.word]
	d.raw = fmt.Appendf(nil, `eventtime=%d tz=+0530 devname=FG-01 devid=FG100E0000000001 logid=0000000013 type=traffic subtype=forward level=notice vd=root srcmac=02:5c:c4:%02x:%02x:%02x src=%s sport=%d srcintf=port1 srcintfrole=lan dst=%s dport=%d dstintf=port2 dstintfrole=wan dstcountry="United States" proto=%d service=HTTPS action=%s utmaction=allow craction=0 policyid=1 sessionid=%d duration=%d sentbyte=%d rcvdbyte=%d sentpkt=%d rcvdpkt=%d appcat=unscanned`,
		at.UnixNano(), r.IntN(256), r.IntN(256), r.IntN(256), d.srcIP, d.srcPort, d.dstIP, d.dstPort, protoNum[d.proto], word, session, dur, d.bytesOut, d.bytesIn, d.bytesOut/1400+1, d.bytesIn/1400+1)
	d.parserID, d.laterParser = "", "fortinet"
	d.stage, d.err = "extract", "extractor fgt_traffic: pattern did not match (missing key srcip)"
	d.unmapped = map[string]any{"appcat": "unscanned", "craction": "0", "devid": "FG100E0000000001", "devname": "FG-01", "dstcountry": "United States",
		"dstintf": "port2", "dstintfrole": "wan", "logid": "0000000013", "policyid": "1", "service": "HTTPS", "sessionid": fmt.Sprint(session),
		"srcintf": "port1", "srcintfrole": "lan", "subtype": "forward", "type": "traffic", "tz": "+0530", "utmaction": "allow", "vd": "root"}
	d.mappedFields = 16
	return d
}

var suricataSigs = []struct {
	sid      int
	sig, cat string
	sev      int
}{
	{2001219, "ET SCAN Potential SSH Scan", "Attempted Information Leak", 2},
	{2013028, "ET POLICY curl User-Agent Outbound", "Attempted Information Leak", 3},
	{2210044, "SURICATA STREAM Packet with invalid timestamp", "Generic Protocol Command Decode", 3},
	{2024897, "ET USER_AGENTS Go HTTP Client User-Agent", "Misc activity", 3},
}

type eveAlert struct {
	Timestamp string `json:"timestamp"`
	FlowID    int64  `json:"flow_id"`
	InIface   string `json:"in_iface"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	Alert     struct {
		Action      string `json:"action"`
		GID         int    `json:"gid"`
		SignatureID int    `json:"signature_id"`
		Rev         int    `json:"rev"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	} `json:"alert"`
}

func genSuricata(r *rand.Rand, at time.Time) draft {
	d := draft{sourceID: "suricata", parserID: "suricata_eve", vendor: "oisf", product: "suricata", at: at, extractor: "eve_alert",
		origin: types.Origin{Kind: types.OriginFile, Addr: "/var/log/suricata/eve.json"}, activityID: 6, actionID: 1, dispositionID: 15,
		proto: "tcp", class: 4001}
	s := pick(r, suricataSigs)
	d.srcIP, d.srcPort = pick(r, externalHosts), ephemeral(r)
	d.dstIP, d.dstPort = pick(r, internalHosts), pick(r, servicePorts)
	d.severityID = map[int]int{1: 4, 2: 3, 3: 2}[s.sev]
	d.message = s.sig
	var e eveAlert
	e.Timestamp = at.In(ist).Format("2006-01-02T15:04:05.000000-0700")
	e.FlowID = r.Int64N(1 << 52)
	e.InIface, e.EventType, e.SrcIP, e.SrcPort, e.DestIP, e.DestPort, e.Proto = "eth0", "alert", d.srcIP, d.srcPort, d.dstIP, d.dstPort, "TCP"
	e.Alert.Action, e.Alert.GID, e.Alert.SignatureID, e.Alert.Rev, e.Alert.Signature, e.Alert.Category, e.Alert.Severity = "allowed", 1, s.sid, 1+r.IntN(20), s.sig, s.cat, s.sev
	raw, _ := json.Marshal(e) // struct field order is fixed, so the line is deterministic
	d.raw = raw
	d.unmapped = map[string]any{"alert": map[string]any{"category": s.cat, "gid": 1, "rev": e.Alert.Rev, "signature_id": s.sid},
		"event_type": "alert", "flow_id": e.FlowID, "in_iface": "eth0"}
	d.mappedFields = 12
	return d
}

// genPaloAlto emits a headerless PAN-OS TRAFFIC CSV row. No parser accepts it
// until the palo_alto_traffic proposal is approved.
func genPaloAlto(r *rand.Rand, at time.Time, users []string) draft {
	d := draft{sourceID: "palo_alto", vendor: "palo_alto", product: "pan-os", at: at, extractor: "pan_traffic", laterParser: "palo_alto_traffic",
		origin: types.Origin{Kind: types.OriginUDP, Addr: "192.0.2.30:514"}, activityID: 6, severityID: 1, class: 4001,
		stage: "detect", err: "no parser matched"}
	d.proto = "tcp"
	if r.IntN(4) == 0 {
		d.proto = "udp"
	}
	word, act, dis := "allow", 1, 1
	if r.IntN(4) == 0 {
		word, act, dis = "drop", 2, 6
	}
	d.actionID, d.dispositionID = act, dis
	d.srcIP, d.srcPort = pick(r, internalHosts), ephemeral(r)
	d.dstIP, d.dstPort = pick(r, externalHosts), pick(r, servicePorts)
	d.bytesOut, d.bytesIn = 500+r.IntN(90000), 500+r.IntN(900000)
	ts := at.In(ist).Format("2006/01/02 15:04:05")
	user := pick(r, users)
	cols := []string{"", ts, "001801010001", "TRAFFIC", "end", "2049", ts, d.srcIP, d.dstIP, "198.51.100.65", "0.0.0.0", "allow-outbound",
		`corp\` + user, "", "ssl", "vsys1", "trust", "untrust", "ethernet1/2", "ethernet1/1", "default-logging", "", fmt.Sprint(900000 + r.IntN(99999)),
		"1", fmt.Sprint(d.srcPort), fmt.Sprint(d.dstPort), fmt.Sprint(ephemeral(r)), fmt.Sprint(d.dstPort), "0x408d76", d.proto, word,
		// Columns 31 and 32 are what palo_alto_traffic maps to bytes_out and bytes_in.
		fmt.Sprint(d.bytesOut), fmt.Sprint(d.bytesIn), fmt.Sprint(d.bytesIn + d.bytesOut), fmt.Sprint(10 + r.IntN(900)), ts, fmt.Sprint(r.IntN(600)),
		"business-and-economy", "", fmt.Sprint(7000000000 + r.IntN(99999999)), "0x0", "10.0.0.0-10.255.255.255", "US", "", fmt.Sprint(r.IntN(500)),
		fmt.Sprint(r.IntN(500)), "tcp-fin"}
	d.raw = []byte(strings.Join(cols, ","))
	d.unmapped = map[string]any{"col_2": "001801010001", "col_4": "end", "col_11": "allow-outbound", "src_user": `corp\` + user, "col_15": "vsys1"}
	d.mappedFields = 11
	return d
}

// ocsf builds the OCSF 4001 (or 4004) object the parser would emit.
func (d *draft) ocsf() map[string]any {
	o := map[string]any{
		"class_uid": d.class, "category_uid": 4, "activity_id": d.activityID, "type_uid": d.class*100 + d.activityID,
		"time": d.at.UnixMilli(), "severity_id": d.severityID,
		"metadata": map[string]any{"version": "1.1.0", "product": map[string]any{"vendor_name": d.vendor, "name": d.product}},
	}
	if d.class == 4004 {
		o["src_endpoint"] = map[string]any{"ip": d.identity.IP, "mac": d.identity.MAC, "hostname": d.identity.Host}
		return o
	}
	o["action_id"], o["disposition_id"] = d.actionID, d.dispositionID
	o["src_endpoint"] = map[string]any{"ip": d.srcIP, "port": d.srcPort}
	o["dst_endpoint"] = map[string]any{"ip": d.dstIP, "port": d.dstPort}
	o["connection_info"] = map[string]any{"protocol_name": d.proto, "protocol_num": protoNum[d.proto]}
	if d.bytesIn+d.bytesOut > 0 {
		o["traffic"] = map[string]any{"bytes_in": d.bytesIn, "bytes_out": d.bytesOut}
	}
	if d.message != "" {
		o["message"] = d.message
	}
	return o
}

// coverage splits the raw length into mapped, unmapped and constant bytes.
// The split is illustrative (the mock does not run an extractor) but always
// sums to the raw length and leaves nothing uncovered, as an anchored parser
// would.
func (d *draft) coverage() types.Coverage {
	n := len(d.raw)
	mapped := n * 30 / 100
	unmapped := n * 35 / 100
	c := types.Coverage{Applicable: d.applicable, MappedBytes: mapped, UnmappedBytes: unmapped, ConstantBytes: n - mapped - unmapped,
		MappedFields: d.mappedFields, UnmappedFields: len(d.unmapped)}
	if d.applicable {
		ok := true
		c.RenderBackOK = &ok
	}
	return c
}
