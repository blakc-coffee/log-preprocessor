package anchor

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func head(b byte) [32]byte { var h [32]byte; h[0] = b; return h }

func TestAppendVerifyAndDedupe(t *testing.T) {
	dir := t.TempDir()
	k, err := LoadOrCreateKey(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := LoadOrCreateKey(filepath.Join(dir, "key")) // reload: same key
	if string(k.Public) != string(k2.Public) {
		t.Fatal("the key must be stable across loads")
	}
	if fi, _ := os.Stat(filepath.Join(dir, "key")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode %v", fi.Mode().Perm())
	}
	log := filepath.Join(dir, "anchors.log")
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for i, h := range []byte{1, 2, 3} {
		c, err := Append(log, k, head(h), uint64(100*(i+1)), uint64(i+1), now.Add(time.Duration(i)*time.Minute))
		if err != nil || c == nil {
			t.Fatalf("append %d: %v %v", i, c, err)
		}
	}
	if c, _ := Append(log, k, head(3), 300, 3, now); c != nil {
		t.Fatal("the same head must not be signed twice")
	}
	if n, err := VerifyLog(log, k.Public); err != nil || n != 3 {
		t.Fatalf("verify: %d %v", n, err)
	}
}

func TestTamperingWithTheLogIsCaught(t *testing.T) {
	dir := t.TempDir()
	k, _ := LoadOrCreateKey(filepath.Join(dir, "key"))
	log := filepath.Join(dir, "anchors.log")
	now := time.Now()
	for i, h := range []byte{1, 2, 3} {
		if _, err := Append(log, k, head(h), uint64(100*(i+1)), uint64(i+1), now); err != nil {
			t.Fatal(err)
		}
	}
	orig, _ := os.ReadFile(log)
	lines := strings.Split(strings.TrimSpace(string(orig)), "\n")
	h2 := hex.EncodeToString(func() []byte { h := head(2); return h[:] }())
	cases := map[string]string{
		"edited head":    strings.Replace(string(orig), h2, strings.Repeat("ff", 32), 1),
		"removed middle": lines[0] + "\n" + lines[2] + "\n",
		"swapped order":  lines[1] + "\n" + lines[0] + "\n" + lines[2] + "\n",
		"edited covered": strings.Replace(string(orig), `"sealed_through":200`, `"sealed_through":999`, 1),
		"truncated line": lines[0] + "\n" + lines[1][:20] + "\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "anchors.log")
			_ = os.WriteFile(p, []byte(content), 0o600)
			if _, err := VerifyLog(p, k.Public); err == nil {
				t.Fatal("tampered log verified")
			}
		})
	}
}

func TestWrongKeyAndGarbageKey(t *testing.T) {
	dir := t.TempDir()
	k, _ := LoadOrCreateKey(filepath.Join(dir, "a"))
	other, _ := LoadOrCreateKey(filepath.Join(dir, "b"))
	log := filepath.Join(dir, "anchors.log")
	if _, err := Append(log, k, head(1), 10, 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLog(log, other.Public); err == nil {
		t.Fatal("a checkpoint must not verify under a different key")
	}
	_ = os.WriteFile(filepath.Join(dir, "bad"), []byte("zz"), 0o600)
	if _, err := LoadOrCreateKey(filepath.Join(dir, "bad")); err == nil {
		t.Fatal("a corrupt key file must be refused, not silently replaced")
	}
}
