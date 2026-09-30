// Package sniff guesses a record's format.
//
// # It is advisory and nothing more
//
// The hint never affects Raw, never affects what is stored, and never decides
// whether a record is kept. A parser is free to ignore it, and must still be
// correct when it is wrong — which it will sometimes be, because this is a
// heuristic run on 256 bytes of attacker-controlled input. Its only job is to
// save a parser registry from trying every extractor in turn, and to give the
// onboarding flow a starting guess for a vendor nobody has written a parser
// for yet.
//
// Because it is advisory, it is also deliberately cheap: a single pass over at
// most 256 bytes, no regular expressions, no allocation. It runs on every
// record on the hot path, and a sniffer that cost real time would be paid for
// by every event whether anything used the answer or not.
package sniff

import (
	types "github.com/dark-14100/sluice/pkg/types"
)

// Window is how much of a record is examined. Everything past it is ignored,
// so a megabyte-long line costs the same as a short one.
const Window = 256

// Thresholds for the shape-based rules. They are low enough to catch a short
// line and high enough that ordinary prose does not trip them.
const (
	minKVPairs = 3
	minCommas  = 5
	// cefSearchWindow is how far past a syslog header to look for a CEF or
	// LEEF marker. A syslog header is well under this.
	cefSearchWindow = 200
)

// Detect returns a format hint for a record.
//
// The rules are tried in order, and the order matters: a syslog-framed CEF
// message is CEF, not syslog, because the payload is the part a parser has to
// understand.
//
//  1. <PRI> header      -> syslog5424 if followed by "1 ", else syslog3164,
//     then overridden by CEF: or LEEF: inside the header's
//     first 200 bytes
//  2. CEF: / LEEF:      -> cef / leef
//  3. first byte { or [ -> json;  <?xml or <letter -> xml
//  4. >= 3 word= pairs  -> kv
//  5. >= 5 commas, no = -> csv
//  6. otherwise         -> unknown
func Detect(raw []byte) types.FormatHint {
	b := raw
	if len(b) > Window {
		b = b[:Window]
	}
	if len(b) == 0 {
		return types.HintUnknown
	}

	// 1. Syslog priority header.
	if n, ok := priorityHeader(b); ok {
		rest := b[n:]
		// A syslog-framed CEF or LEEF message is CEF or LEEF: the transport
		// is incidental, the payload is what a parser has to read.
		if h, ok := cefOrLeef(rest, cefSearchWindow); ok {
			return h
		}
		// RFC 5424 puts a version number and a space straight after the PRI.
		if len(rest) >= 2 && rest[0] == '1' && rest[1] == ' ' {
			return types.HintSyslog5424
		}
		return types.HintSyslog3164
	}

	// 2. Bare CEF or LEEF.
	if hasPrefix(b, "CEF:") {
		return types.HintCEF
	}
	if hasPrefix(b, "LEEF:") {
		return types.HintLEEF
	}

	// 3. Structured markup, judged by the first byte that is not whitespace.
	switch c := firstNonSpace(b); c {
	case '{', '[':
		return types.HintJSON
	case '<':
		if hasPrefix(trimLeadingSpace(b), "<?xml") {
			return types.HintXML
		}
		// "<" followed by a letter is an element. Followed by a digit it
		// would have been a PRI, which rule 1 already handled.
		if t := trimLeadingSpace(b); len(t) > 1 && isLetter(t[1]) {
			return types.HintXML
		}
	}

	// 4 and 5 both need the same scan, so it is done once.
	pairs, commas, anyEquals := scan(b)
	if pairs >= minKVPairs {
		return types.HintKV
	}
	if commas >= minCommas && !anyEquals {
		return types.HintCSV
	}
	return types.HintUnknown
}

// priorityHeader matches "<N>" where N is one to three digits, and returns how
// many bytes it spans.
func priorityHeader(b []byte) (int, bool) {
	if len(b) < 3 || b[0] != '<' {
		return 0, false
	}
	i := 1
	for i < len(b) && i <= 3 && isDigit(b[i]) {
		i++
	}
	if i == 1 || i >= len(b) || b[i] != '>' {
		return 0, false
	}
	return i + 1, true
}

// cefOrLeef looks for a CEF or LEEF marker within the first n bytes.
func cefOrLeef(b []byte, n int) (types.FormatHint, bool) {
	if len(b) > n {
		b = b[:n]
	}
	if indexOf(b, "CEF:") >= 0 {
		return types.HintCEF, true
	}
	if indexOf(b, "LEEF:") >= 0 {
		return types.HintLEEF, true
	}
	return types.HintUnknown, false
}

// scan counts key=value pairs and commas in one pass.
//
// A pair is an '=' immediately preceded by a word character, which is the
// cheap form of \b\w+=. Quoted values are not parsed: the point is to
// recognise a shape, not to tokenise it, and a parser will do that properly
// later.
func scan(b []byte) (pairs, commas int, anyEquals bool) {
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case '=':
			anyEquals = true
			if i > 0 && isWord(b[i-1]) {
				pairs++
			}
		case ',':
			commas++
		}
	}
	return pairs, commas, anyEquals
}

func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isLetter(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }
func isWord(c byte) bool   { return isLetter(c) || isDigit(c) || c == '_' }

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func firstNonSpace(b []byte) byte {
	for _, c := range b {
		if !isSpace(c) {
			return c
		}
	}
	return 0
}

func trimLeadingSpace(b []byte) []byte {
	i := 0
	for i < len(b) && isSpace(b[i]) {
		i++
	}
	return b[i:]
}

func hasPrefix(b []byte, s string) bool {
	if len(b) < len(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if b[i] != s[i] {
			return false
		}
	}
	return true
}

func indexOf(b []byte, s string) int {
	if len(s) == 0 || len(b) < len(s) {
		return -1
	}
	for i := 0; i+len(s) <= len(b); i++ {
		if b[i] == s[0] && hasPrefix(b[i:], s) {
			return i
		}
	}
	return -1
}
