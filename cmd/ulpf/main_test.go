package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestVersionAndUIScan(t *testing.T) {
	var out, errout bytes.Buffer
	if code := run([]string{"version"}, &out, &errout); code != 0 {
		t.Fatalf("code=%d err=%s", code, errout.String())
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(`<script src="http://127.0.0.1/app.js"></script>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := scanUI(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.js"), []byte(`fetch("https://outside.example/x")`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := scanUI(dir); err == nil {
		t.Fatal("external URL was not rejected")
	}
}

func TestUIScanIgnoresAttributionComments(t *testing.T) {
	dir := t.TempDir()
	css := `/*! tailwindcss | MIT License | https://tailwindcss.com */ body{color:white}`
	if err := os.WriteFile(filepath.Join(dir, "app.css"), []byte(css), 0o600); err != nil {
		t.Fatal(err)
	}
	generatedDocs := `const message="https://reactjs.org/docs/error-decoder.html?invariant=1"`
	if err := os.WriteFile(filepath.Join(dir, "vendor.js"), []byte(generatedDocs), 0o600); err != nil {
		t.Fatal(err)
	}
	routerDocs := `console.warn("https://reactrouter.com/v6/upgrading/future#v7_starttransition")`
	if err := os.WriteFile(filepath.Join(dir, "router.js"), []byte(routerDocs), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "LICENSE.txt"), []byte("https://license.example/reference"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := scanUI(dir); err != nil {
		t.Fatalf("attribution comment rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(`const endpoint="https://outside.example/api"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := scanUI(dir); err == nil {
		t.Fatal("executable external URL was not rejected")
	}
}

func TestPipelineSelftests(t *testing.T) {
	if err := selftestVault(); err != nil {
		t.Fatal(err)
	}
	if err := selftestSQLite(); err != nil {
		t.Fatal(err)
	}
}
