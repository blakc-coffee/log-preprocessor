package integration

import (
	"fmt"
	"strings"
	"time"

	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

// Step2Options describes the unknown-format source of step 2.
type Step2Options struct {
	Files      []string // manifest files of the source, all expect=unknown_format (palo_alto_unknown.log)
	Source     string   // its source_id as the data plane knows it
	ParserYAML string   // the reference parser to approve
	Sleep      func(time.Duration)
	MaxPolls   int
}

func (o *Step2Options) defaults() {
	if o.Sleep == nil {
		o.Sleep = time.Sleep
	}
	if o.MaxPolls == 0 {
		o.MaxPolls = 600
	}
}

func wait(api API, id string, o Step2Options) (ReplayJob, error) {
	for i := 0; i < o.MaxPolls; i++ {
		j, err := api.Replay(id)
		if err != nil || (j.State != "queued" && j.State != "running") {
			return j, err
		}
		o.Sleep(100 * time.Millisecond)
	}
	return ReplayJob{}, fmt.Errorf("replay %s still running after %d polls", id, o.MaxPolls)
}

func countByHash(api API, hashes map[string]bool, parser string) (n int, err error) {
	evs, err := api.Events()
	if err != nil {
		return 0, err
	}
	for _, ev := range evs {
		if !hashes[ev.RawSHA256] {
			continue
		}
		if ev.Current && (parser == "" || ev.ParserID == parser) {
			n++
		}
	}
	return n, nil
}

// Step2 is "quarantine -> approve -> replay" (step 2).
func Step2(api API, man Manifest, opt Step2Options) Report {
	opt.defaults()
	r := Report{Step: "step 2: quarantine, approve, replay"}
	recs := man.In(opt.Files...)
	hashes := map[string]bool{}
	for _, m := range recs {
		hashes[m.SHA256] = true
	}

	qs, err := api.Quarantined()
	if err != nil {
		r.gate("quarantine", false, "%v", err)
		return r
	}
	inQ := 0
	for _, s := range qs {
		if hashes[sha(s.Raw)] {
			inQ++
		}
	}
	r.gate("before: every record of the unknown source is quarantined", inQ == len(recs), "%d of %d quarantined", inQ, len(recs))

	dry, err := api.DryRun(opt.ParserYAML, opt.Source)
	r.gate("dry-run of the reference parser meets the thresholds", err == nil && dry.MatchRate >= 0.95 && dry.MeanCoverage >= 0.9,
		"match_rate %.3f, mean_coverage %.3f, err=%v", dry.MatchRate, dry.MeanCoverage, err)

	act, err := api.Approve(opt.ParserYAML, "integration", true)
	if err != nil || act.ReplayJobID == nil {
		r.gate("approve with replay returns a replay job", false, "err=%v activation=%+v", err, act)
		return r
	}
	r.gate("approve with replay returns a replay job", true, "%s@%s, job %s", act.ParserID, act.Version, *act.ReplayJobID)
	job, err := wait(api, *act.ReplayJobID, opt)
	r.gate("the replay finishes with no failures", err == nil && job.State == "done" && job.Failed == 0, "state %q processed %d failed %d err=%v", job.State, job.Processed, job.Failed, err)

	qs, _ = api.Quarantined()
	left := 0
	for _, s := range qs {
		if hashes[sha(s.Raw)] {
			left++
		}
	}
	r.gate("the quarantine drains", left == 0, "%d of the source's records are still quarantined", left)
	n, err := countByHash(api, hashes, act.ParserID)
	r.gate("their events exist, current, from the approved parser", err == nil && n == len(recs), "%d of %d events with parser_id %s", n, len(recs), act.ParserID)

	j2, err := api.StartReplay("source", opt.Source)
	if err == nil {
		j2, err = wait(api, j2.JobID, opt)
	}
	n2, _ := countByHash(api, hashes, "")
	r.gate("replaying again is idempotent (no duplicate events)", err == nil && j2.State == "done" && n2 == n, "events %d then %d, second replay %q err=%v", n, n2, j2.State, err)
	return r
}

// Step4Options describes the drifted source of step 4.
type Step4Options struct {
	Source      string   // fortinet
	RenamePairs []string // signals that must be named, default srcip->src
	Settle      func()   // wait a couple of poll intervals, so a duplicate would have appeared
}

// Step4 is "intelligence sidecar on live quarantine" (step 4). The sidecar is running; this reads what it did.
func Step4(api API, man Manifest, opt Step4Options) Report {
	r := Report{Step: "step 4: intelligence sidecar on live quarantine"}
	if len(opt.RenamePairs) == 0 {
		opt.RenamePairs = []string{"srcip->src"}
	}
	mine := func() (alerts []types.DriftAlert, props []types.Proposal, err error) {
		as, err := api.DriftAlerts()
		if err != nil {
			return
		}
		ps, err := api.Proposals()
		if err != nil {
			return
		}
		for _, a := range as {
			if a.SourceID == opt.Source {
				alerts = append(alerts, a)
			}
		}
		for _, p := range ps {
			if p.SourceID == opt.Source && (p.Status == "pending" || p.Status == "approved") {
				props = append(props, p)
			}
		}
		return
	}
	alerts, props, err := mine()
	if err != nil {
		r.gate("alerts and proposals readable", false, "%v", err)
		return r
	}
	r.gate("exactly one drift alert", len(alerts) == 1, "%d alerts for %s", len(alerts), opt.Source)
	if len(alerts) == 1 {
		a := alerts[0]
		r.gate("its score is at least 0.6", a.Score >= 0.6, "score %.3f, quarantine rate %.2f", a.Score, a.QuarantineRate)
		sig := strings.Join(a.Signals, " | ")
		var missing []string
		for _, p := range opt.RenamePairs {
			if !strings.Contains(sig, p) {
				missing = append(missing, p)
			}
		}
		r.gate("its signals name the renamed keys", len(missing) == 0, "missing %v in: %.200s", missing, sig)
	}
	r.gate("exactly one proposal", len(props) == 1, "%d pending or approved proposals", len(props))
	if len(props) == 1 {
		p := props[0]
		ps, _ := api.Parsers()
		active := ""
		for _, x := range ps {
			if x.ID == p.ParserID {
				active = x.ActiveVersion
			}
		}
		r.gate("it is a patch of the active version", p.Kind == "patch" && p.BaseVersion != "" && (active == "" || p.BaseVersion == active), "kind %q base_version %q active %q", p.Kind, p.BaseVersion, active)
		ok := p.DryRun != nil && p.DryRun.MatchRate >= 0.95
		mr := 0.0
		if p.DryRun != nil {
			mr = p.DryRun.MatchRate
		}
		r.gate("its dry-run passed the acceptance thresholds", ok, "match_rate %.3f", mr)
	}
	if opt.Settle != nil {
		opt.Settle()
		a2, p2, _ := mine()
		r.gate("waiting changes nothing: no duplicate alert or proposal", len(a2) == len(alerts) && len(p2) == len(props), "alerts %d->%d, proposals %d->%d", len(alerts), len(a2), len(props), len(p2))
	}
	return r
}
