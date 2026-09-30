// Command integrate runs the linking checks of docs/integration.md against a running data plane.
//
//	integrate --admin http://127.0.0.1:9000 --step 1
//	integrate --step 2 --parser tests/testdata/parsers/palo_alto_traffic.yaml
//	integrate --step all
//
// Exit codes: 0 every gate passed, 1 a gate failed, 2 the checks could not run (bad flags, unreadable manifest).
// Steps 3 (sinks) and 6 (UI) are not covered here; step 3 belongs to Packaging and step 6 is a walk-through.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blakc-coffee/sluice/contracts/integration"
)

func main() {
	admin := flag.String("admin", "http://127.0.0.1:9000", "data-plane admin API")
	testdata := flag.String("testdata", "testdata", "fixture directory holding manifest.json")
	step := flag.String("step", "all", "1, 2, 4, 5 or all")
	parser := flag.String("parser", "tests/testdata/parsers/palo_alto_traffic.yaml", "step 2: the reference parser to approve")
	files := flag.String("files", "", "step 1: comma-separated manifest files that were ingested (default all)")
	settle := flag.Duration("settle", 15*time.Second, "step 4: how long to wait before checking for duplicates")
	flag.Parse()

	man, err := integration.LoadManifest(*testdata)
	if err != nil {
		fmt.Fprintln(os.Stderr, "integrate:", err)
		os.Exit(2)
	}
	api := integration.NewHTTP(*admin)
	var reports []integration.Report
	run := func(s string) {
		switch s {
		case "1":
			var f []string
			if *files != "" {
				f = strings.Split(*files, ",")
			}
			reports = append(reports, integration.Step1(api, man, integration.Step1Options{Files: f}))
		case "2":
			y, err := os.ReadFile(*parser)
			if err != nil {
				fmt.Fprintln(os.Stderr, "integrate:", err)
				os.Exit(2)
			}
			reports = append(reports, integration.Step2(api, man, integration.Step2Options{Files: []string{"palo_alto_unknown.log"}, Source: "palo_alto_unknown", ParserYAML: string(y)}))
		case "4":
			reports = append(reports, integration.Step4(api, man, integration.Step4Options{Source: "fortinet", Settle: func() { time.Sleep(*settle) }}))
		case "5":
			reports = append(reports, integration.Step5(api, man))
		default:
			fmt.Fprintln(os.Stderr, "integrate: unknown step", s)
			os.Exit(2)
		}
	}
	if *step == "all" {
		for _, s := range []string{"1", "2", "4", "5"} {
			run(s)
		}
	} else {
		run(*step)
	}
	code := 0
	for _, r := range reports {
		fmt.Print(r)
		if !r.Passed() {
			code = 1
		}
	}
	os.Exit(code)
}
