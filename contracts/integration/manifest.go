package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Record is one entry of testdata/manifest.json (schema v1, frozen). A nil expected_* means "not known".
type Record struct {
	ID        string  `json:"record_id"`
	File      string  `json:"source_file"`
	ByteStart int     `json:"byte_start"`
	ByteEnd   int     `json:"byte_end"`
	SHA256    string  `json:"expected_sha256"`
	Expect    string  `json:"expect"` // parse | unknown_format | raw_only
	SrcIP     *string `json:"expected_src_ip"`
	DstIP     *string `json:"expected_dst_ip"`
	SrcPort   *int    `json:"expected_src_port"`
	DstPort   *int    `json:"expected_dst_port"`
	Proto     *string `json:"expected_proto"`
	Time      *string `json:"expected_time"`
	User      *string `json:"expected_user"`
}

// Manifest is the parsed manifest.
type Manifest struct{ Records []Record }

// LoadManifest reads <testdata>/manifest.json.
func LoadManifest(testdata string) (Manifest, error) {
	b, err := os.ReadFile(filepath.Join(testdata, "manifest.json"))
	if err != nil {
		return Manifest{}, err
	}
	var m struct {
		Records []Record `json:"records"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, err
	}
	return Manifest{m.Records}, nil
}

// In returns the records of the given files (all if none given).
func (m Manifest) In(files ...string) []Record {
	if len(files) == 0 {
		return m.Records
	}
	want := map[string]bool{}
	for _, f := range files {
		want[f] = true
	}
	var out []Record
	for _, r := range m.Records {
		if want[r.File] {
			out = append(out, r)
		}
	}
	return out
}
