package parsers

import (
	"testing"
	"time"

	"github.com/blakc-coffee/sluice/contracts/conformance"
)

type adapter struct{ engine *Engine }

func (a adapter) Load(src []byte) (conformance.Parser, error) {
	p, err := a.engine.Load(src)
	if err != nil {
		return nil, err
	}
	return parserAdapter{p}, nil
}

type parserAdapter struct{ parser *Parser }

func (a parserAdapter) Parse(raw []byte, receivedAt time.Time) (*conformance.Result, error) {
	r, err := a.parser.Parse(raw, receivedAt)
	if err != nil || r == nil {
		return nil, err
	}
	return &conformance.Result{ExtractorID: r.ExtractorID, OCSF: r.OCSF, Unmapped: r.Unmapped, Flags: r.Flags, Coverage: r.Coverage, RenderBackOK: r.RenderBackOK, Identity: r.Identity}, nil
}

func TestDSLConformance(t *testing.T) { conformance.Run(t, adapter{New()}, conformance.Options{}) }
