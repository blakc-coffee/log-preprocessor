package vault

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/klauspost/compress/zstd"

	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
)

// Compacted segments.
//
// A sealed .wal is rewritten as a .zst:
//
//	header (72 bytes, raw, identical to the WAL's)
//	block × k:   comp_len u32 | uncomp_len u32 | crc u32 | zstd frame
//	footer (100 bytes, raw, identical to the WAL's)
//
// # A compacted segment is a "logical WAL"
//
// The concatenation of the decompressed blocks is byte-for-byte the record
// region of the original .wal, and records keep their original byte offsets.
// That is the design decision everything else follows from: the in-memory
// index, Get, Proof, the recovery scan and deep verification all address
// records by WAL offset, and they keep working unchanged because the only
// thing that moved is what sits underneath readSeg.
//
// # The block table lives inside the file
//
// Each block carries its own length prefix, so the table is rebuilt by walking
// those prefixes rather than read from a side file. A separate .meta would be a
// second copy of information the file already contains, and a second thing to
// keep consistent with it; this way it cannot disagree with the data, and it is
// rebuildable, which is what decision D5 actually promises.
//
// # Nothing here is trusted
//
// The prefixes are bounded before use, the compressed bytes are CRC-checked
// before they reach the decompressor, and the decompressed length must equal
// what the prefix claimed. The decoder also has a hard memory cap, so a crafted
// frame that claims to expand to gigabytes fails instead of allocating them.

const (
	blockPrefixSize = 12

	// maxBlockUncompressed bounds one block. Blocks are compact_block_bytes
	// plus at most one record (~1 MiB), and compact_block_bytes is capped well
	// below this, so a value beyond it is corruption or hostility.
	maxBlockUncompressed = 32 << 20
	// maxBlockCompressed allows for zstd's worst-case expansion of
	// incompressible data.
	maxBlockCompressed = maxBlockUncompressed + maxBlockUncompressed/64 + 1024

	// MaxCompactBlockBytes is the largest compact_block_bytes accepted.
	MaxCompactBlockBytes = 16 << 20
	// DefaultCompactBlockBytes is the default block size: large enough for zstd
	// to find redundancy across neighbouring records, small enough that a
	// random read decompresses a quarter of a megabyte and not the segment.
	DefaultCompactBlockBytes = 256 << 10
	// DefaultZstdLevel is the default compression level.
	DefaultZstdLevel = 3

	// blockCacheSize is how many decompressed blocks are kept. Sequential
	// replay wants only the current one; a burst of lineage lookups clustered
	// in time wants a few.
	blockCacheSize = 32

	// decoderMaxMemory caps what a single frame may make the decoder allocate.
	decoderMaxMemory = 64 << 20
)

var castagnoliBlock = crc32.MakeTable(crc32.Castagnoli)

// block locates one compressed block.
type block struct {
	// logOff is the block's first byte in the logical (decompressed) stream,
	// which is also its offset in the original WAL.
	logOff int64
	// compOff is where the block's prefix starts in the .zst file.
	compOff   int64
	compLen   uint32
	uncompLen uint32
}

func (b block) logEnd() int64 { return b.logOff + int64(b.uncompLen) }

// walkBlocks rebuilds the block table from the length prefixes in a .zst file
// of the given size.
func walkBlocks(f io.ReaderAt, size int64) ([]block, error) {
	if size < HeaderSize+FooterSize {
		return nil, fmt.Errorf("%w: compacted segment is %d bytes", ErrShort, size)
	}
	end := size - FooterSize
	var blocks []block
	off, logOff := int64(HeaderSize), int64(HeaderSize)

	var pre [blockPrefixSize]byte
	for off < end {
		if end-off < blockPrefixSize {
			return nil, fmt.Errorf("%w: a block prefix at offset %d runs past the footer", ErrCorrupt, off)
		}
		if _, err := f.ReadAt(pre[:], off); err != nil {
			return nil, fmt.Errorf("%w: reading the block prefix at %d: %v", ErrCorrupt, off, err)
		}
		compLen := binary.BigEndian.Uint32(pre[0:4])
		uncompLen := binary.BigEndian.Uint32(pre[4:8])
		if compLen == 0 || uncompLen == 0 || compLen > maxBlockCompressed || uncompLen > maxBlockUncompressed {
			return nil, fmt.Errorf("%w: the block at offset %d declares %d compressed and %d decompressed bytes",
				ErrCorrupt, off, compLen, uncompLen)
		}
		if off+blockPrefixSize+int64(compLen) > end {
			return nil, fmt.Errorf("%w: the block at offset %d runs past the footer", ErrCorrupt, off)
		}
		blocks = append(blocks, block{logOff: logOff, compOff: off, compLen: compLen, uncompLen: uncompLen})
		off += blockPrefixSize + int64(compLen)
		logOff += int64(uncompLen)
	}
	if len(blocks) == 0 {
		return nil, fmt.Errorf("%w: compacted segment holds no blocks", ErrCorrupt)
	}
	return blocks, nil
}

// decodeBlock reads, checksums and decompresses one block.
func decodeBlock(f io.ReaderAt, b block, dec *zstd.Decoder) ([]byte, error) {
	buf := make([]byte, blockPrefixSize+int(b.compLen))
	if _, err := f.ReadAt(buf, b.compOff); err != nil {
		return nil, fmt.Errorf("%w: reading the block at %d: %v", ErrCorrupt, b.compOff, err)
	}
	if binary.BigEndian.Uint32(buf[0:4]) != b.compLen || binary.BigEndian.Uint32(buf[4:8]) != b.uncompLen {
		return nil, fmt.Errorf("%w: the block prefix at %d changed under us", ErrCorrupt, b.compOff)
	}
	comp := buf[blockPrefixSize:]

	// Checksum the compressed bytes before they reach the decompressor, so a
	// flipped bit is reported as a checksum failure rather than as whatever
	// the decoder makes of garbage.
	if got, want := crc32.Checksum(comp, castagnoliBlock), binary.BigEndian.Uint32(buf[8:12]); got != want {
		return nil, fmt.Errorf("%w: block at %d fails its checksum: computed %08x, stored %08x",
			ErrCorrupt, b.compOff, got, want)
	}

	out, err := dec.DecodeAll(comp, make([]byte, 0, b.uncompLen))
	if err != nil {
		return nil, fmt.Errorf("%w: decompressing the block at %d: %v", ErrCorrupt, b.compOff, err)
	}
	if uint32(len(out)) != b.uncompLen {
		return nil, fmt.Errorf("%w: the block at %d decompressed to %d bytes, its prefix says %d",
			ErrCorrupt, b.compOff, len(out), b.uncompLen)
	}
	return out, nil
}

// ------------------------------------------------------------- block cache

type cacheKey struct {
	seg uint64
	idx int
}

type cacheEntry struct {
	key  cacheKey
	data []byte
}

// blockCache is a small LRU of decompressed blocks. It has its own mutex
// because readers reach it holding only the vault's read lock, concurrently.
type blockCache struct {
	mu  sync.Mutex
	max int
	ll  *list.List
	m   map[cacheKey]*list.Element
}

func newBlockCache(max int) *blockCache {
	return &blockCache{max: max, ll: list.New(), m: map[cacheKey]*list.Element{}}
}

func (c *blockCache) get(k cacheKey) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[k]; ok {
		c.ll.MoveToFront(e)
		return e.Value.(*cacheEntry).data, true
	}
	return nil, false
}

func (c *blockCache) put(k cacheKey, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[k]; ok {
		c.ll.MoveToFront(e)
		return
	}
	c.m[k] = c.ll.PushFront(&cacheEntry{key: k, data: data})
	for c.ll.Len() > c.max {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.m, last.Value.(*cacheEntry).key)
	}
}

// drop forgets every block of one segment.
func (c *blockCache) drop(seg uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.m {
		if k.seg == seg {
			c.ll.Remove(e)
			delete(c.m, k)
		}
	}
}

// ------------------------------------------------------------ the read path

// decoder returns the shared decompressor, creating it on first use.
func (v *Vault) decoder() (*zstd.Decoder, error) {
	v.decOnce.Do(func() {
		// Concurrency 1: DecodeAll is safe to call from many goroutines
		// regardless, and a pool of background workers per vault is more
		// machinery than block decompression needs.
		v.dec, v.decErr = zstd.NewReader(nil,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxMemory(decoderMaxMemory))
	})
	return v.dec, v.decErr
}

// readSeg reads from a segment's record region, whichever way it is stored.
//
// For a WAL this is a pread. For a compacted segment it locates the
// containing block, decompresses it (or finds it in the cache) and copies out
// of that. Offsets are WAL offsets in both cases, which is what lets every
// caller stay ignorant of compaction.
func (v *Vault) readSeg(s *segState, p []byte, off int64) (int, error) {
	if !s.compacted {
		return s.file.ReadAt(p, off)
	}

	n := 0
	for n < len(p) {
		pos := off + int64(n)
		i := sort.Search(len(s.blocks), func(i int) bool { return s.blocks[i].logEnd() > pos })
		if i == len(s.blocks) {
			return n, io.EOF
		}
		b := s.blocks[i]
		if pos < b.logOff {
			return n, fmt.Errorf("%w: offset %d is before segment %d's first block", ErrCorrupt, pos, s.id)
		}
		data, err := v.blockData(s, i)
		if err != nil {
			return n, err
		}
		n += copy(p[n:], data[pos-b.logOff:])
	}
	return n, nil
}

func (v *Vault) blockData(s *segState, i int) ([]byte, error) {
	k := cacheKey{seg: s.id, idx: i}
	if data, ok := v.blocks.get(k); ok {
		return data, nil
	}
	dec, err := v.decoder()
	if err != nil {
		return nil, err
	}
	data, err := decodeBlock(s.file, s.blocks[i], dec)
	if err != nil {
		return nil, fmt.Errorf("segment %d: %w", s.id, err)
	}
	v.blocks.put(k, data)
	return data, nil
}

// --------------------------------------------------------------- hash index

// hixEntrySize is one (raw_sha256, seq) pair.
const hixEntrySize = 32 + 8

// hashIndex answers "which record has this raw hash" for one compacted
// segment without holding every hash in memory.
//
// It is the .hix file: (raw_sha256[32] || seq[8]) pairs sorted by hash and then
// by seq, searched by binary search over ReadAt. It is derived data, verified
// against the records at open, so a wrong or missing one is repaired rather
// than trusted.
type hashIndex struct {
	r io.ReaderAt
	n int
	// closer is the backing file, when there is one.
	closer io.Closer
}

// encodeHix builds the .hix content for a segment whose records start at
// firstSeq and whose raw hashes are given in record order.
func encodeHix(hashes [][32]byte, firstSeq types.RecordID) []byte {
	type pair struct {
		h   [32]byte
		seq uint64
	}
	ps := make([]pair, len(hashes))
	for i, h := range hashes {
		ps[i] = pair{h: h, seq: uint64(firstSeq) + uint64(i)}
	}
	sort.Slice(ps, func(i, j int) bool {
		if c := bytes.Compare(ps[i].h[:], ps[j].h[:]); c != 0 {
			return c < 0
		}
		return ps[i].seq < ps[j].seq
	})
	out := make([]byte, 0, len(ps)*hixEntrySize)
	for _, p := range ps {
		out = append(out, p.h[:]...)
		out = binary.BigEndian.AppendUint64(out, p.seq)
	}
	return out
}

// lookup returns the highest seq holding this hash. Highest, because the same
// payload can be stored more than once and the newest wins everywhere else.
func (h *hashIndex) lookup(sum [32]byte) (uint64, bool, error) {
	var ent [hixEntrySize]byte
	read := func(i int) error {
		_, err := h.r.ReadAt(ent[:], int64(i)*hixEntrySize)
		return err
	}

	lo, hi := 0, h.n
	for lo < hi {
		mid := (lo + hi) / 2
		if err := read(mid); err != nil {
			return 0, false, err
		}
		if bytes.Compare(ent[:32], sum[:]) < 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}

	var best uint64
	found := false
	for i := lo; i < h.n; i++ {
		if err := read(i); err != nil {
			return 0, false, err
		}
		if !bytes.Equal(ent[:32], sum[:]) {
			break
		}
		best, found = binary.BigEndian.Uint64(ent[32:]), true
	}
	return best, found, nil
}

func (h *hashIndex) close() {
	if h != nil && h.closer != nil {
		h.closer.Close()
	}
}

// openHixFile opens a .hix file for searching.
func openHixFile(path string) (*hashIndex, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &hashIndex{r: f, n: int(fi.Size() / hixEntrySize), closer: f}, nil
}

// memHix serves a hash index from memory. It is the fallback for a read-only
// open, which must not write a repaired .hix but still has to answer
// correctly.
func memHix(content []byte) *hashIndex {
	return &hashIndex{r: bytes.NewReader(content), n: len(content) / hixEntrySize}
}

// writeFileAtomic writes content to path via a temporary file: write, fsync,
// rename, fsync the directory. A half-written derived file read after a crash
// would be trusted or be a puzzle; this way it either exists whole or not.
func writeFileAtomic(dir, path string, content []byte, syncDir func() error) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir()
}

// errCompactionAborted is returned when shutdown interrupts a compaction.
var errCompactionAborted = errors.New("vault: compaction aborted")

func hixPath(dir string, id uint64) string { return filepath.Join(dir, segmentName(id, "hix")) }
func zstPath(dir string, id uint64) string { return filepath.Join(dir, segmentName(id, "zst")) }
func walPath(dir string, id uint64) string { return filepath.Join(dir, segmentName(id, "wal")) }
