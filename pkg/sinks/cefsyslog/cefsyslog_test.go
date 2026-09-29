package cefsyslog

import (
	"strings"
	"testing"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/types"
)

func TestFormatEscapesCEFFields(t *testing.T) {
	now := time.Date(2026, 9, 29, 1, 2, 3, 0, time.UTC)
	e := types.NormalizedEvent{EventID: "1.p@1", RawSHA256: strings.Repeat("a", 64), Vendor: `V|x`, Product: `P\x`, ParserVersion: "1", TemplateID: "p/e", EventTime: &now, OCSF: map[string]any{"severity_id": 12, "message": "a=b\nc", "src_endpoint": map[string]any{"ip": "10.0.0.1", "port": 42}}}
	got := Format(e, "host", "app")
	for _, want := range []string{`V\|x`, `P\\x`, `msg=a\=b\nc`, `src=10.0.0.1`, `spt=42`, `|10|`} {
		if !strings.Contains(got, want) {
			t.Fatalf("formatted CEF missing %q: %s", want, got)
		}
	}
}
