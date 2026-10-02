// Package anchor signs the vault's chain head. Every time the vault seals a segment, Sluice
// appends a signed checkpoint to anchors.log: the chain head, how much it covers, a timestamp, and
// the hash of the previous checkpoint's signature, all signed with an ed25519 key.
//
// This is the standard signed-tree-head idea (Certificate Transparency, Rekor, CloudTrail digests),
// kept outside the vault's own file format so existing vaults keep working.
//
// What a signed checkpoint adds, and its honest limit: someone who rewrites the vault can no longer
// produce a history that matches a checkpoint you already hold, unless they also hold the signing
// key. The key lives on the same machine by default, so against an administrator of that machine
// the protection is only as strong as where you keep the key and the checkpoints. Keep the private
// key off the host (see KeyPath in the runtime config), and publish checkpoints and the public key
// somewhere the operator cannot edit. SignedAt is the signer's own clock, not trusted time.
package anchor

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dark-14100/sluice/pkg/dataplane/atomicfile"
)

// Version names the checkpoint layout.
const Version = "sluice-checkpoint/1"

// Checkpoint is one signed statement about the chain.
type Checkpoint struct {
	Version       string    `json:"version"`
	Head          string    `json:"head"`           // hex chain head over all sealed segments
	SealedThrough uint64    `json:"sealed_through"` // last record id covered
	Segments      uint64    `json:"segments"`       // number of sealed segments covered
	SignedAt      time.Time `json:"signed_at"`      // signer's clock, not trusted time
	Prev          string    `json:"prev"`           // hex sha256 of the previous checkpoint's signature; zeros for the first
	KeyID         string    `json:"key_id"`
	Signature     string    `json:"signature"` // base64 ed25519 over message()
}

const zeroPrev = "0000000000000000000000000000000000000000000000000000000000000000"

func (c Checkpoint) message() []byte {
	return []byte(fmt.Sprintf("%s\nhead=%s\nsealed_through=%d\nsegments=%d\nsigned_at=%s\nprev=%s\nkey=%s",
		c.Version, c.Head, c.SealedThrough, c.Segments, c.SignedAt.UTC().Format(time.RFC3339Nano), c.Prev, c.KeyID))
}

// KeyID is the first 16 hex characters of the SHA-256 of the public key: short enough to read out.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

// Key is the signing key pair.
type Key struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// LoadOrCreateKey reads the private key at path (hex, mode 0600), creating a new one if absent.
func LoadOrCreateKey(path string) (Key, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		raw, err := hex.DecodeString(string(bytes.TrimSpace(b)))
		if err != nil || len(raw) != ed25519.PrivateKeySize {
			return Key{}, fmt.Errorf("anchor key %s: not a hex ed25519 private key", path)
		}
		priv := ed25519.PrivateKey(raw)
		return Key{Private: priv, Public: priv.Public().(ed25519.PublicKey)}, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Key{}, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Key{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return Key{}, err
	}
	if err := atomicfile.Write(path, []byte(hex.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return Key{}, err
	}
	// The public half is not secret: it sits beside the key so `sluice anchor` and evidence export
	// can name it without ever reading the private key.
	if err := atomicfile.Write(path+".pub", []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return Key{}, err
	}
	return Key{Private: priv, Public: pub}, nil
}

// ParsePublicKey reads a hex public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(string(bytes.TrimSpace([]byte(s))))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("not a hex ed25519 public key (64 hex characters)")
	}
	return ed25519.PublicKey(raw), nil
}

// Sign fills in the key id and signature. prev is the previous checkpoint, or nil for the first.
func Sign(k Key, head [32]byte, sealedThrough, segments uint64, now time.Time, prev *Checkpoint) Checkpoint {
	c := Checkpoint{Version: Version, Head: hex.EncodeToString(head[:]), SealedThrough: sealedThrough, Segments: segments,
		SignedAt: now.UTC(), Prev: zeroPrev, KeyID: KeyID(k.Public)}
	if prev != nil {
		sig, _ := base64.StdEncoding.DecodeString(prev.Signature)
		h := sha256.Sum256(sig)
		c.Prev = hex.EncodeToString(h[:])
	}
	c.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(k.Private, c.message()))
	return c
}

// Verify checks a checkpoint's signature against pub.
func (c Checkpoint) Verify(pub ed25519.PublicKey) error {
	if c.Version != Version {
		return fmt.Errorf("checkpoint version %q, want %q", c.Version, Version)
	}
	if c.KeyID != KeyID(pub) {
		return fmt.Errorf("checkpoint was signed by key %s, not %s", c.KeyID, KeyID(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(c.Signature)
	if err != nil || !ed25519.Verify(pub, c.message(), sig) {
		return errors.New("signature does not verify")
	}
	return nil
}

// Read returns every checkpoint in the log at path, in order. A missing file is an empty log.
func Read(path string) ([]Checkpoint, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Checkpoint
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		var c Checkpoint
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, n, err)
		}
		out = append(out, c)
	}
	return out, sc.Err()
}

// Append signs and appends a checkpoint for the given head, unless the log already ends at that head.
// It returns the checkpoint written, or nil if nothing was new.
func Append(path string, k Key, head [32]byte, sealedThrough, segments uint64, now time.Time) (*Checkpoint, error) {
	all, err := Read(path)
	if err != nil {
		return nil, err
	}
	var prev *Checkpoint
	if len(all) > 0 {
		prev = &all[len(all)-1]
		if prev.Head == hex.EncodeToString(head[:]) {
			return nil, nil
		}
	}
	c := Sign(k, head, sealedThrough, segments, now, prev)
	line, _ := json.Marshal(c)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return nil, err
	}
	return &c, f.Sync() // never retried: a failed fsync means the line may be gone
}

// VerifyLog checks every signature and that the checkpoints chain and only move forward.
func VerifyLog(path string, pub ed25519.PublicKey) (int, error) {
	all, err := Read(path)
	if err != nil {
		return 0, err
	}
	var prev *Checkpoint
	for i, c := range all {
		if err := c.Verify(pub); err != nil {
			return i, fmt.Errorf("checkpoint %d: %w", i+1, err)
		}
		want := zeroPrev
		if prev != nil {
			sig, _ := base64.StdEncoding.DecodeString(prev.Signature)
			h := sha256.Sum256(sig)
			want = hex.EncodeToString(h[:])
			if c.SealedThrough < prev.SealedThrough || c.Segments < prev.Segments {
				return i, fmt.Errorf("checkpoint %d goes backwards", i+1)
			}
		}
		if c.Prev != want {
			return i, fmt.Errorf("checkpoint %d does not follow checkpoint %d (a checkpoint was removed or reordered)", i+1, i)
		}
		cc := c
		prev = &cc
	}
	return len(all), nil
}

// ReadPublicKey reads the public key file written next to the private key (path is the private key's path).
func ReadPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path + ".pub")
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(string(b))
}
