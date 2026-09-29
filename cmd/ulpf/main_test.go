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
