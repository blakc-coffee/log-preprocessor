// Package builtin embeds the built-in parser documents (PRD_PARSING section 5).
// cmd/dataplane activates them on first start; approved replacements live in
// data/parsers.d and win over these.
package builtin

import "embed"

// FS holds one YAML document per parser.
//
//go:embed *.yaml
var FS embed.FS
