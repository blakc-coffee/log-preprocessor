package source

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Checkpoints let a tail resume where it left off.
//
// # Delivery is at-least-once, and that is a design choice, not an oversight
//
// A checkpoint records the offset after the last record the vault confirmed
// durable. If the process dies between a record becoming durable and the
// checkpoint being written, that record is read again on restart and stored
// twice. The alternative - checkpointing first - would mean a crash could skip
// a record that was never stored, and losing data is worse than duplicating
// it. Every record carries Origin{path, offset}, which is the key a consumer
// de-duplicates on.

// checkpointFingerprintBytes is how much of a file's head identifies it. A
// device and inode pair is reused after a file is deleted and another created,
// so the content is what actually distinguishes them.
const checkpointFingerprintBytes = 1024

// checkpoint is the persisted position in one file.
type checkpoint struct {
	Path  string `json:"path"`
	Dev   uint64 `json:"dev"`
	Inode uint64 `json:"inode"`
	// Fingerprint is the SHA-256 of the file's first FingerprintLen bytes,
	// hex encoded. Together with dev and inode it answers "is this the same
	// file I was reading?" after a rotation or an inode reuse.
	Fingerprint string `json:"fingerprint"`
	// FingerprintLen is how many bytes Fingerprint covers.
	//
	// It has to be stored, not assumed. A log file is append-only, so its
	// first N bytes are immutable once it is N bytes long — but a file
	// shorter than the full window changes its own fingerprint every time it
	// grows. Recording the length means the check recomputes over exactly the
	// same prefix instead of over "however much there is now", which is what
	// made every checkpoint on a small file fail to match.
	FingerprintLen int `json:"fingerprint_len"`
	// Offset is the byte after the terminator of the last record the vault
	// confirmed durable.
	Offset int64 `json:"offset"`
}

// checkpointPath is where one file's checkpoint lives. The file name is
// derived from a hash of the path, never from the path itself: a log path can
// contain slashes, spaces and anything else a filesystem allows, and building
// a name out of attacker-influenced text is how directory traversal happens.
func checkpointPath(dir, logPath string) string {
	sum := sha256.Sum256([]byte(logPath))
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".json")
}

// fingerprint reads a file's identifying head and reports how many bytes it
// covers.
func fingerprint(f *os.File) (string, int, error) {
	buf := make([]byte, checkpointFingerprintBytes)
	n, err := f.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", 0, err
	}
	sum := sha256.Sum256(buf[:n])
	return hex.EncodeToString(sum[:]), n, nil
}

// fingerprintAt recomputes a fingerprint over exactly n bytes, for comparing
// against a stored one.
func fingerprintAt(f *os.File, n int) (string, error) {
	if n == 0 {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:]), nil
	}
	buf := make([]byte, n)
	got, err := f.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if got < n {
		// The file is shorter than it was. It is either a different file or
		// one that was truncated; either way the checkpoint does not apply.
		return "", nil
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:]), nil
}

// loadCheckpoint reads a checkpoint, returning nil if there is none.
//
// A corrupt checkpoint is treated as absent rather than fatal: the file is
// derived state, and refusing to start because of it would turn a recoverable
// annoyance into an outage. Re-reading from the beginning duplicates records,
// which the de-duplication key handles.
func loadCheckpoint(dir, logPath string) (*checkpoint, error) {
	raw, err := os.ReadFile(checkpointPath(dir, logPath))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var cp checkpoint
	if err := json.Unmarshal(raw, &cp); err != nil {
		return nil, nil
	}
	if cp.Offset < 0 || cp.Fingerprint == "" || cp.FingerprintLen < 0 {
		return nil, nil
	}
	return &cp, nil
}

// saveCheckpoint writes a checkpoint atomically.
//
// Write to a temporary file, fsync it, then rename. A partially written
// checkpoint read after a crash would resume at a garbage offset, which is
// either skipped data or a stream of duplicates. The rename is what makes the
// new value appear all at once.
func saveCheckpoint(dir string, cp checkpoint) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	final := checkpointPath(dir, cp.Path)

	tmp, err := os.CreateTemp(dir, ".ckpt-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once the rename succeeds

	raw, err := json.Marshal(cp)
	if err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), final); err != nil {
		return err
	}

	// Fsync the directory too, or the rename itself may not survive a crash.
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// matches reports whether a checkpoint still describes this file.
//
// All three have to agree. Device and inode alone are not enough because they
// are reused after a delete and create; the fingerprint alone is not enough
// because two files can start with the same bytes. The fingerprint is
// recomputed over the stored prefix length, not over the file's current head,
// or an append would look like a different file.
func (cp *checkpoint) matches(f *os.File, dev, ino uint64) (bool, error) {
	if cp == nil || cp.Dev != dev || cp.Inode != ino {
		return false, nil
	}
	fp, err := fingerprintAt(f, cp.FingerprintLen)
	if err != nil {
		return false, err
	}
	return fp != "" && fp == cp.Fingerprint, nil
}

func (cp checkpoint) String() string {
	return fmt.Sprintf("%s@%d (dev=%d inode=%d)", cp.Path, cp.Offset, cp.Dev, cp.Inode)
}
