package mock

import (
	"fmt"
	"sort"
	"time"

	types "github.com/dark-14100/sluice/pkg/types"
)

// claim is one time-bounded binding of an IP, the same model the identity
// resolver uses: a bind opens it, a release closes it, and nothing outside
// [from, to) is ever answered.
type claim struct {
	ip, kind       string // kind is dhcp or radius
	user, host     string
	mac            string
	from           time.Time
	to             *time.Time
	evidenceRecord types.RecordID // set once the bind line is in the vault
}

func (c *claim) covers(t time.Time) bool {
	return !t.Before(c.from) && (c.to == nil || t.Before(*c.to))
}

// identityPlan is the scenario, relative to the start of the backlog. The
// address 10.1.4.7 is leased to alice, released, left empty for six minutes,
// then leased to bob: events on either side must resolve to different people
// and events in the gap to nobody.
type identityStep struct {
	offset              time.Duration
	kind, action        string
	ip, user, host, mac string
}

var identityPlan = []identityStep{
	{1 * time.Minute, "dhcp", "bind", "10.1.4.9", "", "laptop-carol", "aa:bb:cc:8a:06:2d"},
	{1*time.Minute + 20*time.Second, "radius", "bind", "10.1.4.9", "carol", "", "aa:bb:cc:8a:06:2d"},
	{2 * time.Minute, "dhcp", "bind", "10.1.4.7", "", "laptop-alice", "aa:bb:cc:cd:79:68"},
	{2*time.Minute + 10*time.Second, "radius", "bind", "10.1.4.7", "alice", "", "aa:bb:cc:cd:79:68"},
	{3 * time.Minute, "dhcp", "bind", "10.1.4.25", "", "laptop-erin", "aa:bb:cc:44:19:0e"},
	{3*time.Minute + 30*time.Second, "radius", "bind", "10.1.4.25", "erin", "", "aa:bb:cc:44:19:0e"},
	{4 * time.Minute, "dhcp", "bind", "10.1.4.50", "", "db01", "aa:bb:cc:00:50:01"},
	{5 * time.Minute, "dhcp", "bind", "10.1.4.12", "", "laptop-dave", "aa:bb:cc:12:7f:31"},
	{5*time.Minute + 5*time.Second, "radius", "bind", "10.1.4.12", "dave", "", "aa:bb:cc:12:7f:31"},
	{29 * time.Minute, "radius", "release", "10.1.4.7", "alice", "", "aa:bb:cc:cd:79:68"},
	{30 * time.Minute, "dhcp", "release", "10.1.4.7", "", "laptop-alice", "aa:bb:cc:cd:79:68"},
	{36 * time.Minute, "dhcp", "bind", "10.1.4.7", "", "laptop-bob", "aa:bb:cc:10:20:30"},
	{36*time.Minute + 20*time.Second, "radius", "bind", "10.1.4.7", "bob", "", "aa:bb:cc:10:20:30"},
}

// identityDraft renders one plan step as a DHCP or RADIUS line.
func identityDraft(s identityStep, at time.Time, session int) draft {
	local := at.In(ist).Format("Jan _2 15:04:05")
	d := draft{at: at, applicable: true, class: 4004, activityID: 5, severityID: 1,
		identity: &types.IdentityFact{Kind: s.kind, Action: s.action, IP: s.ip, MAC: s.mac, Host: s.host, User: s.user, At: at}}
	switch s.kind {
	case "dhcp":
		d.sourceID, d.parserID, d.vendor, d.product, d.extractor = "dhcp", "isc_dhcpd", "isc", "dhcpd", "dhcp_lease"
		d.origin = types.Origin{Kind: types.OriginFile, Addr: "/var/log/dhcpd.log"}
		if s.action == "bind" {
			d.raw = fmt.Appendf(nil, "%s dhcp01 dhcpd[1123]: DHCPACK on %s to %s (%s) via eth1", local, s.ip, s.mac, s.host)
			d.unmapped = map[string]any{"host": "dhcp01", "iface": "eth1", "of": "on", "pid": "1123", "prep": "to"}
		} else {
			d.activityID = 7
			d.raw = fmt.Appendf(nil, "%s dhcp01 dhcpd[1123]: DHCPRELEASE of %s from %s (%s) via eth1", local, s.ip, s.mac, s.host)
			d.unmapped = map[string]any{"host": "dhcp01", "iface": "eth1", "of": "of", "pid": "1123", "prep": "from"}
		}
		d.mappedFields = 6
	default:
		d.sourceID, d.parserID, d.vendor, d.product, d.extractor = "radius", "radius_acct", "freeradius", "radiusd", "acct"
		d.origin = types.Origin{Kind: types.OriginFile, Addr: "/var/log/radius/radius.log"}
		d.class, d.activityID = 3002, 1
		status := "Start"
		if s.action == "release" {
			status, d.activityID = "Stop", 2
		}
		mac := []byte(s.mac)
		for i := range mac {
			if mac[i] == ':' {
				mac[i] = '-'
			}
		}
		d.raw = fmt.Appendf(nil, `%s radius01 radiusd[2201]: Acct-Status-Type=%s User-Name="%s" Framed-IP-Address=%s Calling-Station-Id="%s" NAS-IP-Address=10.1.0.1 NAS-Port-Type=Ethernet Acct-Session-Id="%08X"`,
			local, status, s.user, s.ip, mac, session)
		d.unmapped = map[string]any{"NAS-IP-Address": "10.1.0.1", "NAS-Port-Type": "Ethernet", "Acct-Session-Id": fmt.Sprintf("%08X", session)}
		d.mappedFields = 5
	}
	return d
}

// observe folds a stored identity fact into the claim list, closing the open
// claim of the same kind on the same address when a release or a new bind
// arrives.
func (m *Mock) observe(f types.IdentityFact) {
	for _, c := range m.claims {
		if c.ip == f.IP && c.kind == f.Kind && c.to == nil {
			at := f.At
			c.to = &at
		}
	}
	if f.Action == "bind" {
		m.claims = append(m.claims, &claim{ip: f.IP, kind: f.Kind, user: f.User, host: f.Host, mac: f.MAC, from: f.At, evidenceRecord: f.RecordID})
	}
}

// resolve returns the entities valid for ip at t, one per type, and nothing
// when no claim covers t.
func (m *Mock) resolve(ip string, t time.Time, role string) []types.Entity {
	var out []types.Entity
	for _, c := range m.claims {
		if c.ip != ip || !c.covers(t) {
			continue
		}
		from := c.from
		ev := []types.EvidenceRef{{RecordID: c.evidenceRecord, Kind: c.kind}}
		add := func(typ, id string) {
			if id != "" {
				out = append(out, types.Entity{Type: typ, ID: id, Role: role, ValidFrom: &from, ValidTo: c.to, Confidence: 1, Evidence: ev})
			}
		}
		if c.kind == "radius" {
			add("user", c.user)
		} else {
			add("host", c.host)
			add("mac", c.mac)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return entityOrder[out[i].Type] < entityOrder[out[j].Type] })
	return out
}

var entityOrder = map[string]int{"ip": 0, "user": 1, "host": 2, "mac": 3}

func isInternal(ip string) bool {
	return len(ip) > 3 && (ip[:3] == "10." || (len(ip) > 8 && ip[:8] == "192.168."))
}
