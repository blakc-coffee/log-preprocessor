import { describe, expect, it } from 'vitest';
import {
  base64ToBytes,
  bytesToHex,
  chainHash,
  checkMerkle,
  checkSha,
  hexToBytes,
  leafHash,
  recordBody,
  rfc3339Nanos,
  verifyInclusion,
  type LineageInput,
} from './merkle';
import { golden, merkleVectors } from '../test/repo';
import type { Lineage, NormalizedEvent, RawResponse } from '../api/types';

interface Vectors {
  trees: {
    size: number;
    bodies: string[];
    leaves: string[];
    root: string;
    proofs: { index: number; path: string[] }[];
  }[];
  chain: { segment: number; count: number; prev: string; root: string; chain: string }[];
}

const v = merkleVectors<Vectors>();
const enc = new TextEncoder();

describe('merkle vectors (testdata/merkle_vectors.json)', () => {
  it('covers sizes 1-20 and 64', () => {
    expect(v.trees.map((t) => t.size)).toEqual([...Array.from({ length: 20 }, (_, i) => i + 1), 64]);
  });

  for (const t of v.trees) {
    it(`size ${t.size}: every leaf hash and every proof verifies`, () => {
      const root = hexToBytes(t.root);
      t.bodies.forEach((b, i) => expect(bytesToHex(leafHash(enc.encode(b)))).toBe(t.leaves[i]));
      for (const p of t.proofs) {
        const leaf = hexToBytes(t.leaves[p.index]!);
        const path = p.path.map(hexToBytes);
        expect(verifyInclusion(leaf, p.index, t.size, path, root)).toBe(true);

        // Tamper cases: each must fail.
        const flipped = leaf.slice();
        flipped[0]! ^= 1;
        expect(verifyInclusion(flipped, p.index, t.size, path, root)).toBe(false);
        if (path.length > 0) {
          const badPath = path.map((x) => x.slice());
          badPath[0]![31]! ^= 0x80;
          expect(verifyInclusion(leaf, p.index, t.size, badPath, root)).toBe(false);
          expect(verifyInclusion(leaf, p.index, t.size, path.slice(1), root)).toBe(false);
        }
        if (t.size > 1) expect(verifyInclusion(leaf, (p.index + 1) % t.size, t.size, path, root)).toBe(false);
        expect(verifyInclusion(leaf, p.index, t.size, [...path, root], root)).toBe(false);
        expect(verifyInclusion(leaf, t.size, t.size, path, root)).toBe(false);
      }
    });
  }

  it('recomputes every chain link, and a changed count breaks it', () => {
    for (const c of v.chain) {
      const got = chainHash(hexToBytes(c.prev), hexToBytes(c.root), c.segment, c.count);
      expect(bytesToHex(got)).toBe(c.chain);
      expect(bytesToHex(chainHash(hexToBytes(c.prev), hexToBytes(c.root), c.segment, c.count + 1))).not.toBe(c.chain);
    }
  });

  // An RFC 6962 proof does not bind the tree size by itself (see
  // DECISIONS.log 03:45): the root does. A proof from a smaller tree must
  // not verify against the real root of a bigger one.
  it('a proof from a tree of n does not verify against the root of n+1', () => {
    const small = v.trees.find((t) => t.size === 19)!;
    const big = v.trees.find((t) => t.size === 20)!;
    for (const p of small.proofs) {
      expect(
        verifyInclusion(hexToBytes(small.leaves[p.index]!), p.index, 20, p.path.map(hexToBytes), hexToBytes(big.root)),
      ).toBe(false);
    }
  });
});

describe('record body and lineage (contracts/golden)', () => {
  const ev = golden<NormalizedEvent>('event_asa_built');
  const raw = golden<RawResponse>('raw_response');
  const lin = golden<Lineage>('lineage_sealed');
  const input = (): LineageInput => ({
    raw: base64ToBytes(raw.raw_base64),
    eventRawSha256: ev.raw_sha256,
    serverRawSha256: raw.raw_sha256,
    meta: {
      recordId: raw.record_id,
      receivedAt: raw.received_at,
      sourceId: ev.source_id,
      origin: raw.origin,
      terminator: raw.terminator,
      fragment: raw.fragment,
    },
    sealed: lin.sealed,
    proof: lin.proof,
  });

  it('keeps nanoseconds that Date drops', () => {
    expect(rfc3339Nanos('2026-09-28T03:30:07.123456789Z') % 1_000_000_000n).toBe(123456789n);
    expect(rfc3339Nanos('2026-09-28T03:30:07Z') % 1_000_000_000n).toBe(0n);
    expect(() => rfc3339Nanos('2026-09-28T09:00:07+05:30')).toThrow();
  });

  it('rebuilds the golden leaf from the raw bytes', () => {
    const i = input();
    expect(bytesToHex(leafHash(recordBody(i.raw, i.meta)))).toBe(lin.proof!.leaf_hash);
  });

  it('passes all checks on the golden event', () => {
    expect(checkSha(input()).state).toBe('pass');
    expect(checkMerkle(input()).state).toBe('pass');
  });

  it('fails when a single raw bit flips', () => {
    const i = input();
    i.raw[10]! ^= 1;
    expect(checkSha(i).state).toBe('fail');
    expect(checkMerkle(i).state).toBe('fail');
  });

  it('fails when the metadata is altered even if the bytes are intact', () => {
    const i = input();
    i.meta = { ...i.meta, receivedAt: '2026-09-28T03:30:07.121Z' };
    expect(checkSha(i).state).toBe('pass');
    expect(checkMerkle(i).state).toBe('fail');
  });

  it('fails on a wrong path element, index or chain', () => {
    const p = lin.proof!;
    const flip = (h: string) => (h[0] === '0' ? '1' : '0') + h.slice(1);
    for (const proof of [
      { ...p, path: [flip(p.path[0]!), ...p.path.slice(1)] },
      { ...p, leaf_index: p.leaf_index + 1 },
      { ...p, tree_size: p.tree_size + 1 },
      { ...p, chain: flip(p.chain) },
      { ...p, root: flip(p.root) },
    ]) {
      expect(checkMerkle({ ...input(), proof }).state).toBe('fail');
    }
  });

  it('reports an unsealed segment as pending, not as a failure', () => {
    expect(checkMerkle({ ...input(), sealed: false, proof: null }).state).toBe('pending');
  });
});
