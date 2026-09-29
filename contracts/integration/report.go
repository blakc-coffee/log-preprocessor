package integration

import (
	"fmt"
	"strings"
)

// Gate is one pass/fail condition of a step, with the evidence.
type Gate struct {
	Name   string
	Pass   bool
	Detail string
}

// Report is the outcome of one step.
type Report struct {
	Step  string
	Gates []Gate
}

func (r *Report) gate(name string, ok bool, format string, a ...any) {
	r.Gates = append(r.Gates, Gate{name, ok, fmt.Sprintf(format, a...)})
}

// Passed reports whether every gate passed and there was at least one.
func (r Report) Passed() bool {
	for _, g := range r.Gates {
		if !g.Pass {
			return false
		}
	}
	return len(r.Gates) > 0
}

// Failed lists the gates that did not pass.
func (r Report) Failed() []Gate {
	var out []Gate
	for _, g := range r.Gates {
		if !g.Pass {
			out = append(out, g)
		}
	}
	return out
}

func (r Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n", r.Step, map[bool]string{true: "PASS", false: "FAIL"}[r.Passed()])
	for _, g := range r.Gates {
		fmt.Fprintf(&b, "  [%s] %s: %s\n", map[bool]string{true: "ok", false: "FAIL"}[g.Pass], g.Name, g.Detail)
	}
	return b.String()
}
