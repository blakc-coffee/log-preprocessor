// Package parsers implements the deterministic ULPF parser DSL.
package parsers

import (
	"regexp"
	"time"

	types "github.com/dark-14100/sluice/pkg/types"
)

type Document struct {
	ID           string         `yaml:"id"`
	Version      string         `yaml:"version"`
	BaseVersion  string         `yaml:"base_version,omitempty"`
	Vendor       string         `yaml:"vendor"`
	Product      string         `yaml:"product"`
	Timezone     string         `yaml:"timezone"`
	Match        Match          `yaml:"match"`
	OCSFDefaults map[string]any `yaml:"ocsf_defaults"`
	Extractors   []Extractor    `yaml:"extractors"`
	Identity     *Identity      `yaml:"identity,omitempty"`
}

type Match struct {
	Signature string   `yaml:"signature"`
	Hints     []string `yaml:"hints,omitempty"`
}

type Extractor struct {
	ID         string     `yaml:"id"`
	Kind       string     `yaml:"kind"`
	Pattern    string     `yaml:"pattern,omitempty"`
	SkipPrefix string     `yaml:"skip_prefix,omitempty"`
	PairSep    string     `yaml:"pair_sep,omitempty"`
	KVSep      string     `yaml:"kv_sep,omitempty"`
	Quote      string     `yaml:"quote,omitempty"`
	Sep        string     `yaml:"sep,omitempty"`
	MinColumns int        `yaml:"min_columns,omitempty"`
	Columns    []string   `yaml:"columns,omitempty"`
	When       *When      `yaml:"when,omitempty"`
	Map        []MapEntry `yaml:"map"`
	Render     any        `yaml:"render,omitempty"`
	Tests      []any      `yaml:"tests,omitempty"`
	re         *regexp.Regexp
	skipRE     *regexp.Regexp
}

type When struct {
	Path   string `yaml:"path,omitempty"`
	Column *int   `yaml:"column,omitempty"`
	Equals any    `yaml:"equals,omitempty"`
	In     []any  `yaml:"in,omitempty"`
}

type MapEntry struct {
	From     any            `yaml:"from,omitempty"`
	Const    any            `yaml:"const,omitempty"`
	To       string         `yaml:"to"`
	Type     string         `yaml:"type,omitempty"`
	Layout   string         `yaml:"layout,omitempty"`
	Unit     string         `yaml:"unit,omitempty"`
	Lower    bool           `yaml:"lower,omitempty"`
	Optional bool           `yaml:"optional,omitempty"`
	Enum     map[string]any `yaml:"enum,omitempty"`
	Default  any            `yaml:"default,omitempty"`
	hasConst bool
	hasDef   bool
}

type Identity struct {
	Kind   string         `yaml:"kind"`
	When   IdentityWhen   `yaml:"when"`
	Action IdentityAction `yaml:"action"`
	IP     string         `yaml:"ip"`
	MAC    string         `yaml:"mac,omitempty"`
	Host   string         `yaml:"host,omitempty"`
	User   string         `yaml:"user,omitempty"`
	At     string         `yaml:"at"`
}

type IdentityWhen struct {
	Field  string `yaml:"field"`
	Equals any    `yaml:"equals,omitempty"`
	In     []any  `yaml:"in,omitempty"`
}

type IdentityAction struct {
	Field string         `yaml:"field,omitempty"`
	Enum  map[string]any `yaml:"enum,omitempty"`
}

type Parser struct {
	doc       Document
	signature *regexp.Regexp
	zone      *time.Location
}

type Result struct {
	ExtractorID  string
	OCSF         map[string]any
	Unmapped     map[string]any
	Flags        []string
	Coverage     types.Coverage
	RenderBackOK *bool
	Identity     *types.IdentityFact
}

func (p *Parser) ID() string         { return p.doc.ID }
func (p *Parser) Version() string    { return p.doc.Version }
func (p *Parser) Vendor() string     { return p.doc.Vendor }
func (p *Parser) Product() string    { return p.doc.Product }
func (p *Parser) Document() Document { return p.doc }

// EngineVersion identifies the parsing behaviour: the same parser YAML run on the same bytes gives
// the same OCSF for any build with the same EngineVersion. Bump it in any change that alters that
// output (new field handling, time parsing, type conversion), so evidence bundles, which re-run the
// parser to prove an event derives from its raw record, can tell an engine change from a forgery.
const EngineVersion = "1"
