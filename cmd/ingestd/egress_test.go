package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNothingDialsOut is the code-level half of the air-gap claim.
//
// The other half is behavioural: the binaries were run with the operating
// system denying all network access and ingested, compacted and verified
// normally. This one is what stops a future change quietly adding a call home —
// telemetry, an update check, a licence server — that a network-denied run
// would only reveal by hanging or failing at some later date.
//
// It reads every non-test source file this workstream ships and rejects any
// call that opens an OUTBOUND connection, and any import of a package that
// exists only to make them. Listening is not egress and is allowed; so is the
// loopback health probe, which dials the address the operator configured for
// the daemon's own metrics listener.
func TestNothingDialsOut(t *testing.T) {
	roots := []string{"../../pkg", "../../cmd", "../../tools"}

	// Package selectors that open an outbound connection when called.
	outbound := map[string]map[string]bool{
		"net":  set("Dial", "DialTimeout", "DialTCP", "DialUDP", "DialIP", "DialUnix"),
		"tls":  set("Dial", "DialWithDialer"),
		"http": set("Get", "Post", "PostForm", "Head"),
	}
	// Imports that exist only to talk to something else.
	forbiddenImports := set("net/smtp", "net/rpc", "net/http/httptrace")

	// The one legitimate use: --healthcheck probing the daemon's own address.
	allowed := map[string]bool{"probeHealth": true}

	fset := token.NewFileSet()
	checked := 0
	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			checked++

			for _, imp := range f.Imports {
				if forbiddenImports[strings.Trim(imp.Path.Value, `"`)] {
					t.Errorf("%s imports %s, which exists to make outbound connections", path, imp.Path.Value)
				}
			}

			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || allowed[fn.Name.Name] {
					continue
				}
				ast.Inspect(fn, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					pkg, ok := sel.X.(*ast.Ident)
					if !ok {
						return true
					}
					if outbound[pkg.Name][sel.Sel.Name] {
						t.Errorf("%s: %s calls %s.%s, which opens an outbound connection",
							fset.Position(call.Pos()), fn.Name.Name, pkg.Name, sel.Sel.Name)
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked < 20 {
		t.Fatalf("only %d files were checked; the walk is not finding the code", checked)
	}
	t.Logf("checked %d source files for outbound connections", checked)
}

func set(items ...string) map[string]bool {
	m := map[string]bool{}
	for _, i := range items {
		m[i] = true
	}
	return m
}
