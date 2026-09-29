// Package normalizer builds the canonical event envelope around parser output.
package normalizer

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/parsers"
	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

const SchemaVersion = "ulpf-uef/1"

func Build(raw types.RawEvent, parser *parsers.Parser, result *parsers.Result) types.NormalizedEvent {
	eventTime, fromReceipt := eventTime(result.OCSF, raw.ReceivedAt)
	if _, ok := result.OCSF["time"]; !ok {
		result.OCSF["time"] = eventTime.UnixMilli()
	}
	result.OCSF["metadata"] = map[string]any{
		"version": "1.1.0",
		"product": map[string]any{"vendor_name": parser.Vendor(), "name": parser.Product()},
	}
	identity := result.Identity
	if identity != nil {
		copy := *identity
		copy.RecordID, copy.SourceID = raw.ID, raw.SourceID
		identity = &copy
	}
	return types.NormalizedEvent{
		EventID:         fmt.Sprintf("%d.%s@%s", raw.ID, parser.ID(), parser.Version()),
		RecordID:        raw.ID,
		Segment:         raw.Segment,
		RawSHA256:       hex.EncodeToString(raw.RawSHA256[:]),
		SourceID:        raw.SourceID,
		Vendor:          parser.Vendor(),
		Product:         parser.Product(),
		ParserID:        parser.ID(),
		ParserVersion:   parser.Version(),
		TemplateID:      parser.ID() + "/" + result.ExtractorID,
		SchemaVersion:   SchemaVersion,
		ReceivedAt:      raw.ReceivedAt.UTC(),
		EventTime:       eventTime,
		TimeFromReceipt: fromReceipt,
		ParseConfidence: confidence(result),
		IntegrityFlags:  append([]string{}, result.Flags...),
		OCSF:            result.OCSF,
		Unmapped:        result.Unmapped,
		Entities:        []types.Entity{},
		Identity:        identity,
		Coverage:        result.Coverage,
		Current:         true,
	}
}

func eventTime(ocsf map[string]any, receipt time.Time) (*time.Time, bool) {
	if value, ok := ocsf["time"]; ok {
		var ms int64
		switch value := value.(type) {
		case int64:
			ms = value
		case uint64:
			ms = int64(value)
		case int:
			ms = int64(value)
		case float64:
			ms = int64(value)
		}
		if ms != 0 {
			t := time.UnixMilli(ms).UTC()
			return &t, false
		}
	}
	t := receipt.UTC()
	return &t, true
}

func confidence(result *parsers.Result) float64 {
	if result.Coverage.RenderBackOK != nil && !*result.Coverage.RenderBackOK {
		return 0.8
	}
	for _, flag := range result.Flags {
		if flag == types.FlagTimeUnparseable || flag == types.FlagLowConfidence {
			return 0.8
		}
	}
	return 1
}
