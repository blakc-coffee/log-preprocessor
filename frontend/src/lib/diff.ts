// Line diff (LCS) for parser YAML: small documents, so the O(n*m) table is fine.

export type DiffLine = { kind: 'same' | 'add' | 'del'; text: string; a?: number; b?: number };

export function diffLines(before: string, after: string): DiffLine[] {
  const a = before.replace(/\n$/, '').split('\n');
  const b = after.replace(/\n$/, '').split('\n');
  const n = a.length;
  const m = b.length;
  const lcs: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i]![j] = a[i] === b[j] ? lcs[i + 1]![j + 1]! + 1 : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ kind: 'same', text: a[i]!, a: i + 1, b: j + 1 });
      i++;
      j++;
    } else if (lcs[i + 1]![j]! >= lcs[i]![j + 1]!) {
      out.push({ kind: 'del', text: a[i]!, a: i + 1 });
      i++;
    } else {
      out.push({ kind: 'add', text: b[j]!, b: j + 1 });
      j++;
    }
  }
  for (; i < n; i++) out.push({ kind: 'del', text: a[i]!, a: i + 1 });
  for (; j < m; j++) out.push({ kind: 'add', text: b[j]!, b: j + 1 });
  return out;
}
