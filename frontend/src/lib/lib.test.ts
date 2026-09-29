import { describe, expect, it } from 'vitest';
import { ByteClass, classify, summarize } from './hex';
import { diffLines } from './diff';
import { parseSearch } from './search';
import { setFieldPath, summarizeParser } from './yamlEdit';
import { fmtBytes, fmtClock, productName } from './format';

describe('hex byte classes', () => {
  const b = (...x: number[]) => Uint8Array.from(x);
  it('accepts valid UTF-8 and marks invalid sequences', () => {
    expect([...classify(b(0x41, 0x0a, 0x00))]).toEqual([ByteClass.Printable, ByteClass.Control, ByteClass.Control]);
    expect([...classify(b(0xc3, 0xa9))]).toEqual([ByteClass.Utf8, ByteClass.Utf8]); // é
    expect([...classify(b(0xff, 0xfe, 0x41))]).toEqual([ByteClass.Invalid, ByteClass.Invalid, ByteClass.Printable]);
    expect([...classify(b(0xc0, 0xaf))]).toEqual([ByteClass.Invalid, ByteClass.Invalid]); // overlong
    expect([...classify(b(0xed, 0xa0, 0x80))].every((c) => c === ByteClass.Invalid)).toBe(true); // surrogate
    expect([...classify(b(0xe2, 0x82))]).toEqual([ByteClass.Invalid, ByteClass.Invalid]); // truncated at the end
    expect(summarize(classify(b(0xff, 0x00, 0x41)))).toEqual({ invalid: 1, control: 1 });
  });
});

describe('diffLines', () => {
  it('keeps shared lines and marks changes', () => {
    const d = diffLines('a\nb\nc\n', 'a\nB\nc\nd\n');
    expect(d.map((x) => `${x.kind}:${x.text}`)).toEqual(['same:a', 'del:b', 'add:B', 'same:c', 'add:d']);
  });
});

describe('parseSearch', () => {
  it('recognises IPs, prefixes, vendors and names', () => {
    expect(parseSearch('10.1.4.7').params).toEqual({ ip: '10.1.4.7' });
    expect(parseSearch('suricata user:alice dst:203.0.113.9').params).toEqual({
      vendor: 'oisf',
      user: 'alice',
      dst_ip: '203.0.113.9',
    });
    expect(parseSearch('fe80::1').params).toEqual({ ip: 'fe80::1' });
    expect(parseSearch('carol').params).toEqual({ user: 'carol' });
    const h = parseSearch('a'.repeat(64));
    expect(h.params).toEqual({});
    expect(h.unsupported).toHaveLength(1);
  });
});

const csv = `id: palo_alto_traffic
version: 1.0.0
extractors:
  - id: pan_traffic
    kind: csv
    columns: [_, ts, _, _, _, _, _, src_ip, dst_ip, _, _, _, _]
    map:
      - {from: ts, to: time, type: time, layout: "2006/01/02 15:04:05"}
      - {from: src_ip, to: src_endpoint.ip, type: ip}
      - {from: dst_ip, to: dst_endpoint.ip, type: ip}
`;

describe('setFieldPath', () => {
  it('re-points a mapped csv column', () => {
    const r = setFieldPath(
      csv,
      { field: 'col_8', ocsf_path: 'dst_endpoint.ip', type: 'ipv4', confidence: 0.8, evidence: '' },
      'src_endpoint.ip',
    );
    expect(r.error).toBeUndefined();
    expect(r.yaml).toContain('{from: dst_ip, to: src_endpoint.ip, type: ip}');
    const lines = diffLines(csv, r.yaml).filter((l) => l.kind !== 'same');
    expect(lines).toHaveLength(2); // only the edited mapping changed
  });
  it('names and maps an abstained column', () => {
    const r = setFieldPath(
      csv,
      { field: 'col_12', ocsf_path: '', type: 'username', confidence: 0.4, evidence: '' },
      'actor.user.name',
    );
    expect(r.error).toBeUndefined();
    expect(r.yaml).toMatch(/columns: \[.*col_12]/);
    expect(r.yaml).toContain('{from: col_12, to: actor.user.name, type: string}');
  });
  it('unmaps a field', () => {
    const r = setFieldPath(
      csv,
      { field: 'col_7', ocsf_path: 'src_endpoint.ip', type: 'ipv4', confidence: 0.9, evidence: '' },
      '',
    );
    expect(r.yaml).not.toContain('to: src_endpoint.ip');
  });
  it('refuses paths that need an enum', () => {
    expect(
      setFieldPath(
        csv,
        { field: 'col_7', ocsf_path: 'src_endpoint.ip', type: 'ipv4', confidence: 1, evidence: '' },
        'action_id',
      ).error,
    ).toMatch(/enum/);
  });
  it('re-points a kv key', () => {
    const kv =
      'id: fortinet\nextractors:\n  - id: t\n    kind: kv\n    map:\n      - {from: src, to: src_endpoint.ip, type: ip}\n';
    const r = setFieldPath(
      kv,
      { field: 'src', ocsf_path: 'src_endpoint.ip', type: 'ipv4', confidence: 1, evidence: '' },
      'dst_endpoint.ip',
    );
    expect(r.yaml).toContain('to: dst_endpoint.ip');
  });
  it('summarizes a parser', () => {
    const s = summarizeParser(csv);
    expect(s.version).toBe('1.0.0');
    expect(s.kinds).toEqual(['csv']);
    expect(s.mappings[1]).toEqual({ from: 'src_ip', to: 'src_endpoint.ip' });
  });
});

describe('format', () => {
  it('formats', () => {
    expect(fmtClock('2026-09-28T03:30:07.441Z', true)).toBe('03:30:07.441');
    expect(fmtBytes(2.4 * 1024 ** 3)).toBe('2.4 GB');
    expect(productName('cisco', 'asa')).toBe('Cisco ASA');
    expect(productName('acme', 'fw')).toBe('Acme fw');
  });
});
