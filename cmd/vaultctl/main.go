// Command vaultctl inspects and verifies a Sluice vault.
//
//	vaultctl --dir ./data/vault stats
//	vaultctl --dir ./data/vault ls
//	vaultctl --dir ./data/vault get <seq> [--raw]
//	vaultctl --dir ./data/vault proof <seq>
//	vaultctl verify-proof <proof.json>        # no vault needed
//	vaultctl --dir ./data/vault verify [--deep]
//	vaultctl --dir ./data/vault head
//	vaultctl --dir ./data/vault scan --from <seq> --limit N
//
// # Exit codes are part of the contract
//
//	0  the vault is intact, or the command succeeded
//	1  tamper or corruption detected
//	2  usage error, or the vault could not be read
//
// verify_airgap.sh and the demo script branch on these, so 1 and 2 must stay
// distinguishable: "someone changed the data" and "I could not look" are very
// different answers.
//
// Every command opens the vault read-only, so vaultctl can inspect a vault
// another process is writing to, and can open a damaged one in order to say
// what is wrong with it.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/dark-14100/sluice/pkg/dataplane/vault"
	types "github.com/dark-14100/sluice/pkg/types"
)

// Exit codes.
const (
	exitOK     = 0
	exitTamper = 1
	exitUsage  = 2
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("vaultctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "vault directory")
	deep := fs.Bool("deep", false, "verify: also re-read every record and recompute every segment root")
	raw := fs.Bool("raw", false, "get: write the raw bytes to stdout and nothing else")
	from := fs.Uint64("from", 1, "scan: first record id")
	limit := fs.Int("limit", 20, "scan: maximum records to print")
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}
	// Go's flag package stops parsing at the first non-flag argument, so a
	// single Parse would leave `verify --deep` with --deep unparsed and
	// silently run a shallow check while the command line said otherwise.
	// Parse, take one positional, parse again, until none are left: flags may
	// then appear anywhere.
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return exitUsage
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}

	if len(positional) == 0 {
		fs.Usage()
		return exitUsage
	}
	cmd, cmdArgs := positional[0], positional[1:]

	// verify-proof is pure: it needs no vault, which is the point of it.
	if cmd == "verify-proof" {
		return verifyProof(cmdArgs, stdout, stderr)
	}

	if *dir == "" {
		fmt.Fprintln(stderr, "vaultctl: --dir is required")
		return exitUsage
	}
	v, err := vault.Open(vault.Options{Dir: *dir, ReadOnly: true})
	if err != nil {
		fmt.Fprintf(stderr, "vaultctl: opening %s: %v\n", *dir, err)
		// Damage that even a read-only open cannot get past is a detection,
		// not an inability to look.
		if errors.Is(err, vault.ErrCorrupt) {
			return exitTamper
		}
		return exitUsage
	}
	defer v.Close()

	ctx := context.Background()
	switch cmd {
	case "stats":
		return stats(ctx, v, stdout, stderr)
	case "ls":
		return ls(ctx, v, stdout, stderr)
	case "head":
		return head(ctx, v, stdout, stderr)
	case "verify":
		return verify(ctx, v, *deep, stdout, stderr)
	case "get":
		return get(ctx, v, cmdArgs, *raw, stdout, stderr)
	case "proof":
		return proof(ctx, v, cmdArgs, stdout, stderr)
	case "scan":
		return scan(ctx, v, types.RecordID(*from), *limit, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "vaultctl: unknown command %q\n", cmd)
		fs.Usage()
		return exitUsage
	}
}

const usage = `vaultctl inspects and verifies a Sluice vault.

  vaultctl --dir DIR stats                  segment and record counts
  vaultctl --dir DIR ls                     one line per sealed segment
  vaultctl --dir DIR head                   chain head, for external anchoring
  vaultctl --dir DIR verify [--deep]        exit 0 intact, 1 tampered, 2 unreadable
  vaultctl --dir DIR get SEQ [--raw]        metadata and a hexdump, or raw bytes
  vaultctl --dir DIR proof SEQ              inclusion proof as JSON
  vaultctl --dir DIR scan --from SEQ --limit N
  vaultctl verify-proof FILE                check a proof with no vault at all

Flags:
`

func stats(ctx context.Context, v *vault.Vault, stdout, stderr io.Writer) int {
	seals, err := v.Seals(ctx)
	if err != nil {
		return fail(stderr, err)
	}
	head, through, err := v.Head(ctx)
	if err != nil {
		return fail(stderr, err)
	}
	var records uint64
	for _, s := range seals {
		records += s.Count
	}
	fmt.Fprintf(stdout, "sealed segments  %d\n", len(seals))
	fmt.Fprintf(stdout, "sealed records   %d\n", records)
	fmt.Fprintf(stdout, "sealed through   %d\n", through)
	fmt.Fprintf(stdout, "chain head       %s\n", hex.EncodeToString(head[:]))
	return exitOK
}

func ls(ctx context.Context, v *vault.Vault, stdout, stderr io.Writer) int {
	seals, err := v.Seals(ctx)
	if err != nil {
		return fail(stderr, err)
	}
	w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEGMENT\tFIRST\tLAST\tCOUNT\tROOT\tSEALED AT\tRECOVERED")
	for _, s := range seals {
		fmt.Fprintf(w, "%d\t%d\t%d\t%d\t%s\t%s\t%v\n",
			s.Segment, s.FirstSeq, s.LastSeq, s.Count,
			hex.EncodeToString(s.Root[:8])+"...",
			s.SealedAt.Format(time.RFC3339), s.Recovered)
	}
	w.Flush()
	return exitOK
}

func head(ctx context.Context, v *vault.Vault, stdout, stderr io.Writer) int {
	h, through, err := v.Head(ctx)
	if err != nil {
		return fail(stderr, err)
	}
	// Copy this somewhere the vault's owner cannot reach. It is the only
	// thing that makes a consistent rewrite of the whole directory
	// detectable.
	fmt.Fprintf(stdout, "%s %d\n", hex.EncodeToString(h[:]), through)
	return exitOK
}

func verify(ctx context.Context, v *vault.Vault, deep bool, stdout, stderr io.Writer) int {
	rep, err := v.VerifyChain(ctx, deep)
	if err != nil {
		return fail(stderr, err)
	}
	if !rep.OK {
		fmt.Fprintf(stderr, "TAMPER DETECTED at segment %d: %s\n", rep.FirstBad, rep.Reason)
		return exitTamper
	}
	mode := "shallow"
	if deep {
		mode = "deep"
	}
	fmt.Fprintf(stdout, "chain intact (%s): %d segments, %d records, head %s\n",
		mode, rep.Segments, rep.Records, hex.EncodeToString(rep.Head[:]))
	return exitOK
}

func get(ctx context.Context, v *vault.Vault, args []string, rawOnly bool, stdout, stderr io.Writer) int {
	id, code := parseSeq(args, stderr)
	if code != exitOK {
		return code
	}
	r, rc, err := v.Get(ctx, id)
	if err != nil {
		return fail(stderr, err)
	}
	if rawOnly {
		// Byte-exact, nothing added. This is what makes "the vault gave back
		// exactly what the device sent" checkable with sha256sum.
		if _, err := stdout.Write(r.Raw); err != nil {
			return fail(stderr, err)
		}
		return exitOK
	}

	fmt.Fprintf(stdout, "record      %d\n", rc.ID)
	fmt.Fprintf(stdout, "segment     %d\n", rc.Segment)
	fmt.Fprintf(stdout, "source      %s\n", r.SourceID)
	fmt.Fprintf(stdout, "received_at %s\n", r.ReceivedAt.Format(time.RFC3339Nano))
	fmt.Fprintf(stdout, "origin      kind=%d addr=%s offset=%d\n", r.Origin.Kind, r.Origin.Addr, r.Origin.Offset)
	fmt.Fprintf(stdout, "terminator  %d\n", r.Term)
	fmt.Fprintf(stdout, "fragment    %d\n", r.Frag)
	fmt.Fprintf(stdout, "raw_sha256  %s\n", hex.EncodeToString(rc.RawSHA256[:]))
	fmt.Fprintf(stdout, "raw_bytes   %d\n\n", len(r.Raw))
	hexdump(stdout, r.Raw)
	return exitOK
}

func proof(ctx context.Context, v *vault.Vault, args []string, stdout, stderr io.Writer) int {
	id, code := parseSeq(args, stderr)
	if code != exitOK {
		return code
	}
	p, err := v.Proof(ctx, id)
	if errors.Is(err, types.ErrNotSealed) {
		// Not a failure: the record is stored, its segment simply has no root
		// yet. Exit 2 because there is no proof to hand back.
		fmt.Fprintf(stderr, "vaultctl: record %d is in the active segment, which has no root until it is sealed\n", id)
		return exitUsage
	}
	if err != nil {
		return fail(stderr, err)
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(vault.NewProofJSON(p)); err != nil {
		return fail(stderr, err)
	}
	return exitOK
}

func verifyProof(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: vaultctl verify-proof <proof.json>   (use /dev/stdin to pipe)")
		return exitUsage
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "vaultctl: %v\n", err)
		return exitUsage
	}
	j, err := vault.VerifyProofJSON(raw)
	if err != nil {
		fmt.Fprintf(stderr, "PROOF INVALID: %v\n", err)
		return exitTamper
	}
	fmt.Fprintf(stdout, "proof valid: record %d of %d in segment %d, root %s\n",
		j.LeafIndex, j.TreeSize, j.Segment, j.Root)
	fmt.Fprintln(stdout, "note: this proves the record is in a tree with that root and that the root is")
	fmt.Fprintln(stdout, "      linked into the chain. Compare the root against a chain head obtained")
	fmt.Fprintln(stdout, "      independently to know it is the root the vault really published.")
	return exitOK
}

func scan(ctx context.Context, v *vault.Vault, from types.RecordID, limit int, stdout, stderr io.Writer) int {
	if limit <= 0 {
		fmt.Fprintln(stderr, "vaultctl: --limit must be positive")
		return exitUsage
	}
	n := 0
	w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSEGMENT\tSOURCE\tBYTES\tRAW_SHA256\tPREVIEW")
	err := v.Scan(ctx, from, func(r types.RawRecord, rc types.Receipt) error {
		if n >= limit {
			return errStop
		}
		n++
		fmt.Fprintf(w, "%d\t%d\t%s\t%d\t%s\t%s\n",
			rc.ID, rc.Segment, r.SourceID, len(r.Raw),
			hex.EncodeToString(rc.RawSHA256[:8])+"...", preview(r.Raw, 60))
		return nil
	})
	w.Flush()
	if err != nil && !errors.Is(err, errStop) {
		return fail(stderr, err)
	}
	return exitOK
}

var errStop = errors.New("stop")

func parseSeq(args []string, stderr io.Writer) (types.RecordID, int) {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "vaultctl: expected exactly one record id")
		return 0, exitUsage
	}
	n, err := strconv.ParseUint(args[0], 10, 64)
	if err != nil || n == 0 {
		fmt.Fprintf(stderr, "vaultctl: %q is not a record id (they start at 1)\n", args[0])
		return 0, exitUsage
	}
	return types.RecordID(n), exitOK
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "vaultctl: %v\n", err)
	if errors.Is(err, vault.ErrCorrupt) {
		return exitTamper
	}
	return exitUsage
}

// preview renders a payload for a table cell. Raw bytes are never printed
// unescaped: a log line is attacker-controlled and could otherwise carry
// terminal escapes or fake up another row.
func preview(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	out := make([]rune, 0, len(b))
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			out = append(out, '.')
			continue
		}
		out = append(out, rune(c))
	}
	return string(out)
}

// hexdump writes the classic offset/hex/ASCII view.
func hexdump(f io.Writer, b []byte) {
	for off := 0; off < len(b); off += 16 {
		end := off + 16
		if end > len(b) {
			end = len(b)
		}
		line := b[off:end]
		fmt.Fprintf(f, "%08x  ", off)
		for i := 0; i < 16; i++ {
			if i < len(line) {
				fmt.Fprintf(f, "%02x ", line[i])
			} else {
				fmt.Fprint(f, "   ")
			}
			if i == 7 {
				fmt.Fprint(f, " ")
			}
		}
		fmt.Fprintf(f, " |%s|\n", preview(line, 16))
	}
}
