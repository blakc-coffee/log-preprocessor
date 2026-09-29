package gen

import "time"

// Truth is identity_truth.json: the answer key for requirement (h).
//
// Intervals say who held an address and when. ResolutionCases pose the
// questions the firewall records in identity_firewall.log ask, each with its
// correct answer, including the ones inside a lease gap whose correct answer
// is no user at all. The cases are duplicated here rather than left only in
// the manifest so that B7's resolver can be unit-tested without ingesting
// anything.
type Truth struct {
	Generator Generator       `json:"generator"`
	Intervals []TruthInterval `json:"intervals"`
	Cases     []TruthCase     `json:"resolution_cases"`
	Notes     TruthNotes      `json:"notes"`
}

// TruthInterval is one binding over a half-open time range: the address is
// bound from `from` up to, but not including, `to`. A null `to` is still open
// when the corpus ends.
type TruthInterval struct {
	IP   string  `json:"ip"`
	User string  `json:"user"`
	Host string  `json:"host"`
	MAC  string  `json:"mac"`
	From string  `json:"from"`
	To   *string `json:"to"`
}

// TruthCase is one "who was on this address at this instant" question. A null
// user means the address was unleased and the only correct answer is none.
type TruthCase struct {
	IP   string  `json:"ip"`
	At   string  `json:"at"`
	User *string `json:"expected_user"`
}

// TruthNotes points at the deliberately awkward cases, so a reader can find
// them without reverse-engineering the timestamps.
type TruthNotes struct {
	Synthetic          bool     `json:"synthetic"`
	IntervalsHalfOpen  bool     `json:"intervals_half_open"`
	ShortestGapSeconds float64  `json:"shortest_gap_seconds"`
	SameUserTwoIPs     []string `json:"same_user_two_ips"`
	OverlappingVPN     []string `json:"overlapping_radius_vpn_evidence"`
	Description        string   `json:"description"`
}

// buildTruth renders the scenario as the JSON answer key.
func buildTruth(seed uint64) Truth {
	sc := buildScenario(seed)

	t := Truth{
		Generator: Generator{
			Version:   Version,
			Seed:      seed,
			Go:        GoVersion,
			BaseTime:  BaseTime.Format(time.RFC3339),
			Synthetic: true,
		},
		Notes: TruthNotes{
			Synthetic:         true,
			IntervalsHalfOpen: true,
			Description: "Every address is leased twice with an unleased gap between tenancies. " +
				"A resolver that ignores time answers the second tenancy with the first tenant; " +
				"one that pads or rounds its intervals invents a user for traffic inside the gap. " +
				"The firewall records in identity_firewall.log carry only an IP, and the manifest's " +
				"expected_user on each is the same answer as resolution_cases here.",
		},
	}

	shortest := identityGaps[0]
	for _, g := range identityGaps {
		if g < shortest {
			shortest = g
		}
	}
	t.Notes.ShortestGapSeconds = shortest.Seconds()

	seenUser := map[string][]string{}
	for _, ten := range sc.Tenancies {
		iv := TruthInterval{
			IP: ten.IP, User: ten.User, Host: ten.Host, MAC: ten.MAC,
			From: ten.From().Format(time.RFC3339),
		}
		if to := ten.To(); !to.IsZero() {
			s := to.Format(time.RFC3339)
			iv.To = &s
		}
		t.Intervals = append(t.Intervals, iv)

		if !contains(seenUser[ten.User], ten.IP) {
			seenUser[ten.User] = append(seenUser[ten.User], ten.IP)
		}
		if ten.VPNPeer != "" && !contains(t.Notes.OverlappingVPN, ten.IP) {
			t.Notes.OverlappingVPN = append(t.Notes.OverlappingVPN, ten.IP)
		}
	}

	// Report the multi-address users in tenancy order, not map order.
	for _, ten := range sc.Tenancies {
		ips := seenUser[ten.User]
		if len(ips) > 1 && !contains(t.Notes.SameUserTwoIPs, ten.User) {
			t.Notes.SameUserTwoIPs = append(t.Notes.SameUserTwoIPs, ten.User)
		}
	}

	for _, c := range sc.Cases {
		tc := TruthCase{IP: c.IP, At: c.At.Format(time.RFC3339)}
		if c.User != "" {
			u := c.User
			tc.User = &u
		}
		t.Cases = append(t.Cases, tc)
	}
	return t
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
