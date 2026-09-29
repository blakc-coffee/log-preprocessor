// Command gen writes the ULPF synthetic fixture corpus and its ground-truth
// manifest.
//
//	go run ./tools/gen --seed 20260928 --out testdata
//	go run ./tools/gen --seed 20260928 --profile sample --out testdata/sample
//	go run ./tools/gen --list
//
// The same seed produces byte-identical output on any machine; `make
// fixtures-check` proves it. Everything generated is synthetic.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/blakc-coffee/log-preprocessor/tools/gen/internal/gen"
)

func main() {
	seed := flag.Uint64("seed", 20260928, "corpus seed; the same seed always produces the same bytes")
	out := flag.String("out", "testdata", "output directory")
	profile := flag.String("profile", "full", "full | sample (sample is ~50 records per source)")
	only := flag.String("only", "", "comma-separated file names to generate, e.g. cisco_asa.log")
	list := flag.Bool("list", false, "list the corpus files and exit")
	flag.Parse()

	if *list {
		for _, s := range gen.Sources() {
			fmt.Printf("%-24s full=%-6d sample=%-4d terminator=%s\n", s.Name, s.Full, s.Sample, s.Term)
		}
		return
	}

	opts := gen.Options{Seed: *seed, Out: *out}
	switch *profile {
	case "full":
	case "sample":
		opts.Sample = true
	default:
		fatal("unknown --profile %q: want full or sample", *profile)
	}
	if *only != "" {
		known := map[string]bool{}
		for _, s := range gen.Sources() {
			known[s.Name] = true
		}
		for _, n := range strings.Split(*only, ",") {
			n = strings.TrimSpace(n)
			if !known[n] {
				fatal("unknown --only name %q: run --list to see the corpus", n)
			}
			opts.Only = append(opts.Only, n)
		}
	}

	if err := gen.Run(opts); err != nil {
		fatal("%v", err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gen: "+format+"\n", args...)
	os.Exit(2)
}
