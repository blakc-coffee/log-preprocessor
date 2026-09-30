package vault

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/blakc-coffee/sluice/pkg/dataplane/vault/merkle"
	"github.com/blakc-coffee/sluice/pkg/dataplane/vault/record"
	types "github.com/blakc-coffee/sluice/pkg/types"
)

// Background compaction.
//
// Sealed segments are rewritten from .wal to .zst to save disk. The procedure
// is built around one rule: the .wal is deleted only after the .zst has been
// read back from disk, decompressed, and shown to reproduce the segment's
// Merkle root. A compaction that dropped or altered a record would be silent —
// nothing would fail until someone asked for that record — so the check is not
// optional and not sampled.
//
// The steps, and why each is where it is:
//
//  1. Write seg-N.zst.tmp from the .wal.            (nothing visible yet)
//  2. fsync it.
//  3. Read it back FROM DISK: walk the blocks, checksum, decompress, parse
//     every record, recompute the root, require it to equal the footer's.
//  4. Write seg-N.hix.tmp from the hashes just verified.
//  5. Rename .hix, then rename .zst LAST.            (.zst present == complete)
//  6. fsync the directory.
//  7. Swap the in-memory segment over, then delete the .wal.
//
// A crash anywhere leaves either the .wal alone (steps 1-5), or both files
// (between 5 and 7). Recovery prefers a verified .zst and only then removes
// the .wal; it never deletes the only good copy.
//
// # A failed compaction is not a failed vault
//
// The data is intact in the .wal, so an error here is logged, counted and the
// segment left uncompacted. It never puts the vault into ErrFailed.

// kickCompactor asks the background compactor to look for work. It never
// blocks: a pending kick already means "look again".
func (v *Vault) kickCompactor() {
	if v.compactKick == nil {
		return
	}
	select {
	case v.compactKick <- struct{}{}:
	default:
	}
}

// compactor is the background goroutine.
func (v *Vault) compactor() {
	defer close(v.compactDone)
	for {
		select {
		case <-v.compactStop:
			return
		case <-v.compactKick:
		}
		for {
			s := v.nextToCompact()
			if s == nil {
				break
			}
			if err := v.compactSegment(s); err != nil {
				if errors.Is(err, errCompactionAborted) {
					return
				}
				v.metrics.CompactionFailures.Inc()
				v.opts.Logger.Error("compaction failed; the segment is intact in its .wal",
					"segment", s.id, "err", err)
				v.mu.Lock()
				s.compactFailed = true
				v.mu.Unlock()
			}
			select {
			case <-v.compactStop:
				return
			default:
			}
		}
	}
}

// nextToCompact returns the oldest sealed segment still stored as a WAL.
func (v *Vault) nextToCompact() *segState {
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, s := range v.segs {
		if s.sealed && !s.compacted && !s.compactFailed {
			return s
		}
	}
	return nil
}

// shuttingDown reports whether the compactor has been told to stop.
func (v *Vault) shuttingDown() bool {
	select {
	case <-v.compactStop:
		return true
	default:
		return false
	}
}

// compactSegment rewrites one sealed segment as a .zst. See the package
// comment on this file for the procedure.
func (v *Vault) compactSegment(s *segState) (err error) {
	start := time.Now()
	dir := v.opts.Dir
	wal, zst, hix := walPath(dir, s.id), zstPath(dir, s.id), hixPath(dir, s.id)
	zstTmp, hixTmp := zst+".tmp", hix+".tmp"

	// Whatever happens, do not leave temporaries behind.
	defer func() {
		if err != nil {
			os.Remove(zstTmp)
			os.Remove(hixTmp)
		}
	}()

	walInfo, err := os.Stat(wal)
	if err != nil {
		return err
	}

	// The header and footer are carried over byte for byte, so a compacted
	// segment states its place in the chain exactly as the original did.
	hdr := make([]byte, HeaderSize)
	if _, err := s.file.ReadAt(hdr, 0); err != nil {
		return err
	}
	ftrBytes := make([]byte, FooterSize)
	if _, err := s.file.ReadAt(ftrBytes, walInfo.Size()-FooterSize); err != nil {
		return err
	}
	ftr, err := decodeFooter(ftrBytes)
	if err != nil {
		return fmt.Errorf("the source footer: %w", err)
	}

	enc, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(v.opts.ZstdLevel)),
		zstd.WithEncoderConcurrency(1),
		zstd.WithEncoderCRC(true))
	if err != nil {
		return err
	}
	defer enc.Close()

	// ---- 1 and 2: write and fsync the temporary .zst.
	out, err := os.OpenFile(zstTmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(out, 1<<20)
	closeOut := func() { bw.Flush(); out.Close() }

	if _, err := bw.Write(hdr); err != nil {
		closeOut()
		return err
	}

	maxBody := record.MaxBodyBytes(v.opts.MaxFrameBytes)
	blockBuf := make([]byte, 0, v.opts.CompactBlockBytes+maxBody)
	var compBytes int64

	flush := func() error {
		if len(blockBuf) == 0 {
			return nil
		}
		comp := enc.EncodeAll(blockBuf, nil)
		var pre [blockPrefixSize]byte
		binary.BigEndian.PutUint32(pre[0:4], uint32(len(comp)))
		binary.BigEndian.PutUint32(pre[4:8], uint32(len(blockBuf)))
		binary.BigEndian.PutUint32(pre[8:12], crc32.Checksum(comp, castagnoliBlock))
		if _, err := bw.Write(pre[:]); err != nil {
			return err
		}
		if _, err := bw.Write(comp); err != nil {
			return err
		}
		compBytes += int64(blockPrefixSize + len(comp))
		blockBuf = blockBuf[:0]
		return nil
	}

	off := int64(HeaderSize)
	end := walInfo.Size() - FooterSize
	for off < end {
		if v.shuttingDown() {
			closeOut()
			return errCompactionAborted
		}
		framed, err := readFramed(s.file.ReadAt, off, maxBody)
		if err != nil {
			closeOut()
			return fmt.Errorf("reading the source record at %d: %w", off, err)
		}
		// Never split a record across blocks: a block boundary inside a
		// record would make every read of it need two decompressions.
		if len(blockBuf) > 0 && len(blockBuf)+len(framed) > v.opts.CompactBlockBytes {
			if err := flush(); err != nil {
				closeOut()
				return err
			}
		}
		blockBuf = append(blockBuf, framed...)
		off += int64(len(framed))
	}
	if err := flush(); err != nil {
		closeOut()
		return err
	}
	if _, err := bw.Write(ftrBytes); err != nil {
		closeOut()
		return err
	}
	if err := bw.Flush(); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}

	// ---- 3: read it back from disk and prove it reproduces the segment.
	hashes, err := verifyCompacted(zstTmp, hdr, ftrBytes, ftr, s.firstSeq, maxBody)
	if err != nil {
		return fmt.Errorf("verification of the compacted file failed, the .wal is kept: %w", err)
	}
	if v.shuttingDown() {
		return errCompactionAborted
	}

	// ---- 4: the hash index, from the hashes just verified.
	var hixContent []byte
	if !v.opts.DisableHashIndex {
		hixContent = encodeHix(hashes, s.firstSeq)
		if err := writeFileTmp(hixTmp, hixContent); err != nil {
			return err
		}
	}

	// ---- 5 and 6: rename. .zst is LAST: its presence means "complete".
	if !v.opts.DisableHashIndex {
		if err := os.Rename(hixTmp, hix); err != nil {
			return err
		}
	}
	if err := os.Rename(zstTmp, zst); err != nil {
		return err
	}
	if err := v.dir.Sync(); err != nil {
		return err
	}

	// ---- 7: switch readers over, then delete the .wal.
	zf, err := os.Open(zst)
	if err != nil {
		return err
	}
	zi, err := zf.Stat()
	if err != nil {
		zf.Close()
		return err
	}
	blocks, err := walkBlocks(zf, zi.Size())
	if err != nil {
		zf.Close()
		return err
	}
	var idx *hashIndex
	if !v.opts.DisableHashIndex {
		if idx, err = openHixFile(hix); err != nil {
			zf.Close()
			return err
		}
	}

	v.mu.Lock()
	if v.closed {
		v.mu.Unlock()
		zf.Close()
		idx.close()
		return errCompactionAborted
	}
	old := s.file
	s.file, s.blocks, s.compacted, s.hix = zf, blocks, true, idx
	if !v.opts.DisableHashIndex {
		// These hashes now live in the .hix. Delete a map entry only if it
		// points into THIS segment: the same payload may also have been
		// stored later, and the newest occurrence has to keep winning.
		last := s.firstSeq + types.RecordID(s.count) - 1
		for _, h := range hashes {
			if id, ok := v.byHash[h]; ok && id >= s.firstSeq && id <= last {
				delete(v.byHash, h)
			}
		}
	}
	v.mu.Unlock()

	old.Close()
	if err := os.Remove(wal); err != nil {
		return err
	}
	if err := v.dir.Sync(); err != nil {
		return err
	}

	elapsed := time.Since(start)
	v.metrics.CompactionSeconds.Observe(elapsed.Seconds())
	v.metrics.CompactedBytesIn.Add(float64(walInfo.Size()))
	v.metrics.CompactedBytesOut.Add(float64(zi.Size()))
	ratio := float64(walInfo.Size()) / float64(zi.Size())
	v.metrics.CompactionRatio.Set(ratio)
	v.opts.Logger.Info("segment compacted",
		"segment", s.id, "wal_bytes", walInfo.Size(), "zst_bytes", zi.Size(),
		"ratio", fmt.Sprintf("%.2f", ratio), "seconds", fmt.Sprintf("%.3f", elapsed.Seconds()))
	return nil
}

// readFramed reads one framed record at a known offset and returns its bytes,
// length prefix and CRC included, CRC checked.
func readFramed(readAt func([]byte, int64) (int, error), off int64, maxBody int) ([]byte, error) {
	var pre [record.FrameOverhead]byte
	if _, err := readAt(pre[:], off); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(pre[0:4]))
	if length > maxBody {
		return nil, fmt.Errorf("%w: declares %d bytes", record.ErrTooLarge, length)
	}
	buf := make([]byte, record.FrameOverhead+length)
	if _, err := readAt(buf, off); err != nil {
		return nil, err
	}
	if _, _, err := record.ParseFramed(buf, maxBody); err != nil {
		return nil, err
	}
	return buf, nil
}

// writeFileTmp writes and fsyncs a temporary file. The caller renames it.
func writeFileTmp(path string, content []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// verifyCompacted is the verify-before-delete check. It opens the file fresh,
// so it exercises exactly what recovery will later do, and returns the raw
// hashes of every record in order.
//
// It requires: the header and footer bytes equal the source's; every block's
// checksum holds and decompresses to its stated length; every record parses,
// with a valid CRC and the next expected sequence number; and the Merkle root
// over all of them equals the source footer's root. That last is the one that
// matters: it commits to every byte of every record.
func verifyCompacted(path string, wantHdr, wantFtr []byte, ftr footer, firstSeq types.RecordID, maxBody int) ([][32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	hdr := make([]byte, HeaderSize)
	if _, err := f.ReadAt(hdr, 0); err != nil {
		return nil, err
	}
	if string(hdr) != string(wantHdr) {
		return nil, errors.New("the header does not match the source")
	}
	tail := make([]byte, FooterSize)
	if _, err := f.ReadAt(tail, fi.Size()-FooterSize); err != nil {
		return nil, err
	}
	if string(tail) != string(wantFtr) {
		return nil, errors.New("the footer does not match the source")
	}

	blocks, err := walkBlocks(f, fi.Size())
	if err != nil {
		return nil, err
	}
	dec, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(decoderMaxMemory))
	if err != nil {
		return nil, err
	}
	defer dec.Close()

	var leaves [][32]byte
	var hashes [][32]byte
	next := firstSeq
	for i, b := range blocks {
		data, err := decodeBlock(f, b, dec)
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", i, err)
		}
		for pos := 0; pos < len(data); {
			body, n, err := record.ParseFramed(data[pos:], maxBody)
			if err != nil {
				return nil, fmt.Errorf("block %d offset %d: %w", i, pos, err)
			}
			seq, r, err := record.Decode(body)
			if err != nil {
				return nil, fmt.Errorf("block %d offset %d: %w", i, pos, err)
			}
			if seq != next {
				return nil, fmt.Errorf("block %d holds record %d where %d belongs", i, seq, next)
			}
			leaves = append(leaves, merkle.LeafHash(body))
			hashes = append(hashes, sha256.Sum256(r.Raw))
			next++
			pos += n
		}
	}

	if uint64(len(leaves)) != ftr.Count {
		return nil, fmt.Errorf("holds %d records, the footer says %d", len(leaves), ftr.Count)
	}
	if merkle.Root(leaves) != ftr.Root {
		return nil, errors.New("the records do not reproduce the segment's Merkle root")
	}
	return hashes, nil
}

var _ = io.EOF
