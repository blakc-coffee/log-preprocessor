// Browser-side lineage verification. Nothing here trusts the server: every
// hash is recomputed from bytes the browser holds.
//
//   leaf  = SHA-256(0x00 || record body)            RFC 6962
//   node  = SHA-256(0x01 || left || right)          RFC 6962
//   chain = SHA-256(0x02 || prev || root || segment_be64 || count_be64)
//
// Inclusion proofs are verified per RFC 9162 section 2.1.3.2, a mirror of
// pkg/dataplane/vault/merkle.VerifyInclusion. The record body is rebuilt from
// the raw bytes plus the record metadata exactly as the vault encodes it
// (docs/vault-format.md), which ties the raw bytes on screen to the leaf in
// the proof: a proof alone only shows that *some* leaf is in the tree.
//
// @noble/hashes is pure JS, so this works on plain-http LAN origins where
// crypto.subtle is unavailable.
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

export { bytesToHex, hexToBytes };

export function sha256Hex(b: Uint8Array): string {
  return bytesToHex(sha256(b));
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

const LEAF = Uint8Array.of(0x00);
const NODE = Uint8Array.of(0x01);
const CHAIN = Uint8Array.of(0x02);

export function leafHash(body: Uint8Array): Uint8Array {
  return sha256(concat(LEAF, body));
}

export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concat(NODE, left, right));
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

/** RFC 9162 2.1.3.2. Indices are numbers: a segment never approaches 2^53 records. */
export function verifyInclusion(
  leaf: Uint8Array,
  index: number,
  size: number,
  path: Uint8Array[],
  root: Uint8Array,
): boolean {
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || index < 0 || index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of path) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && equalBytes(r, root);
}

function be64(v: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt.asUintN(64, v));
  return b;
}

export function chainHash(prev: Uint8Array, root: Uint8Array, segment: number, count: number): Uint8Array {
  return sha256(concat(CHAIN, prev, root, be64(BigInt(segment)), be64(BigInt(count))));
}

/**
 * Unix nanoseconds of an RFC 3339 UTC timestamp, keeping every fractional
 * digit. Date.parse keeps only milliseconds, and the leaf hash covers the
 * full nanoseconds, so the fraction is parsed by hand.
 */
export function rfc3339Nanos(ts: string): bigint {
  const m = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z$/.exec(ts);
  if (!m) throw new Error(`not an RFC 3339 UTC timestamp: ${ts}`);
  const secs = Date.parse(m[1] + 'Z');
  if (Number.isNaN(secs)) throw new Error(`invalid timestamp: ${ts}`);
  const frac = BigInt((m[2] ?? '').padEnd(9, '0') || '0');
  return BigInt(secs / 1000) * 1_000_000_000n + frac;
}

const ORIGIN_KIND: Record<string, number> = { unknown: 0, file: 1, udp: 2, tcp: 3, tls: 4, http: 5 };
const TERMINATOR: Record<string, number> = { none: 0, LF: 1, CRLF: 2, NUL: 3 };

export interface RecordMeta {
  recordId: number;
  receivedAt: string;
  sourceId: string;
  origin: { kind: string; addr: string; offset: number };
  terminator: string;
  fragment: number;
}

/** The vault's record body (record codec version 1), rebuilt from its parts. */
export function recordBody(raw: Uint8Array, meta: RecordMeta): Uint8Array {
  const enc = new TextEncoder();
  const src = enc.encode(meta.sourceId);
  const addr = enc.encode(meta.origin.addr);
  const kind = ORIGIN_KIND[meta.origin.kind];
  const term = TERMINATOR[meta.terminator];
  if (kind === undefined || term === undefined) throw new Error('unknown origin kind or terminator');
  const flags = term | (meta.fragment & 1 ? 4 : 0) | (meta.fragment & 2 ? 8 : 0);
  const head = new Uint8Array(2 + 8 + 8 + 2);
  const dv = new DataView(head.buffer);
  head[0] = 1;
  head[1] = flags;
  dv.setBigUint64(2, BigInt(meta.recordId));
  dv.setBigInt64(10, rfc3339Nanos(meta.receivedAt));
  dv.setUint16(18, src.length);
  const mid = new Uint8Array(1 + 2);
  mid[0] = kind;
  new DataView(mid.buffer).setUint16(1, addr.length);
  const tail = new Uint8Array(8 + 4);
  const tv = new DataView(tail.buffer);
  tv.setBigUint64(0, BigInt(meta.origin.offset));
  tv.setUint32(8, raw.length);
  return concat(head, src, mid, addr, tail, raw);
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export type CheckState = 'pending' | 'pass' | 'fail' | 'na';

export interface Check {
  state: CheckState;
  detail: string;
}

export interface LineageInput {
  raw: Uint8Array;
  eventRawSha256: string;
  serverRawSha256: string;
  meta: RecordMeta;
  sealed: boolean;
  proof: {
    segment: number;
    leaf_index: number;
    tree_size: number;
    leaf_hash: string;
    path: string[];
    root: string;
    prev_chain: string;
    chain: string;
  } | null;
}

/** Check 1: the raw bytes hash to the digest the event and the vault carry. */
export function checkSha(i: LineageInput): Check {
  const got = sha256Hex(i.raw);
  if (got !== i.eventRawSha256)
    return {
      state: 'fail',
      detail: `Bytes hash to ${got.slice(0, 12)}…, event says ${i.eventRawSha256.slice(0, 12)}…`,
    };
  if (got !== i.serverRawSha256) return { state: 'fail', detail: 'Event and vault disagree on the raw digest.' };
  return { state: 'pass', detail: `SHA-256 ${got.slice(0, 16)}… computed here matches the event.` };
}

/** Check 2: raw bytes -> leaf -> root (inclusion) -> chain link. */
export function checkMerkle(i: LineageInput): Check {
  if (!i.sealed || !i.proof) return { state: 'pending', detail: 'Segment not sealed yet, proof available after seal.' };
  const p = i.proof;
  let leaf: Uint8Array;
  try {
    leaf = leafHash(recordBody(i.raw, i.meta));
  } catch (e) {
    return { state: 'fail', detail: `Cannot rebuild the record: ${(e as Error).message}` };
  }
  if (bytesToHex(leaf) !== p.leaf_hash)
    return { state: 'fail', detail: 'Leaf rebuilt from these bytes is not the leaf in the proof.' };
  const ok = verifyInclusion(leaf, p.leaf_index, p.tree_size, p.path.map(hexToBytes), hexToBytes(p.root));
  if (!ok) return { state: 'fail', detail: `Inclusion path does not reach segment ${p.segment}'s root.` };
  const link = chainHash(hexToBytes(p.prev_chain), hexToBytes(p.root), p.segment, p.tree_size);
  if (bytesToHex(link) !== p.chain)
    return { state: 'fail', detail: `Segment ${p.segment} root does not link into the chain.` };
  return {
    state: 'pass',
    detail: `Leaf ${p.leaf_index + 1} of ${p.tree_size} in segment ${p.segment}; chain link verified.`,
  };
}
