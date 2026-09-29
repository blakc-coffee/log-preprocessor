// Byte classification for the hex view. Raw records are hostile and may be
// invalid UTF-8, so the view marks what it cannot show as text rather than
// letting a decoder silently replace it.

export const enum ByteClass {
  Printable = 0, // 0x20-0x7e
  Control = 1, // other ASCII, including CR, LF, TAB, NUL
  Utf8 = 2, // part of a valid multi-byte UTF-8 sequence
  Invalid = 3, // not valid UTF-8 here
}

/** Classifies every byte, validating UTF-8 per RFC 3629 (no overlongs, no surrogates). */
export function classify(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(b.length);
  let i = 0;
  while (i < b.length) {
    const c = b[i]!;
    if (c < 0x80) {
      out[i] = c >= 0x20 && c < 0x7f ? ByteClass.Printable : ByteClass.Control;
      i++;
      continue;
    }
    let n = 0;
    let lo = 0x80;
    let hi = 0xbf;
    if (c >= 0xc2 && c <= 0xdf) n = 1;
    else if (c >= 0xe0 && c <= 0xef) {
      n = 2;
      if (c === 0xe0) lo = 0xa0;
      if (c === 0xed) hi = 0x9f;
    } else if (c >= 0xf0 && c <= 0xf4) {
      n = 3;
      if (c === 0xf0) lo = 0x90;
      if (c === 0xf4) hi = 0x8f;
    }
    // A sequence of n continuation bytes needs bytes i..i+n to exist.
    let ok = n > 0 && i + n < b.length;
    for (let k = 1; ok && k <= n; k++) {
      const x = b[i + k];
      if (x === undefined || x < (k === 1 ? lo : 0x80) || x > (k === 1 ? hi : 0xbf)) ok = false;
    }
    if (ok) {
      out.fill(ByteClass.Utf8, i, i + n + 1);
      i += n + 1;
    } else {
      out[i] = ByteClass.Invalid;
      i++;
    }
  }
  return out;
}

export interface ByteSummary {
  invalid: number;
  control: number;
}

export function summarize(cls: Uint8Array): ByteSummary {
  let invalid = 0;
  let control = 0;
  for (const c of cls) {
    if (c === ByteClass.Invalid) invalid++;
    else if (c === ByteClass.Control) control++;
  }
  return { invalid, control };
}

export const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));

/** The ASCII gutter character for a byte: itself when printable, else a dot. */
export function gutterChar(c: number): string {
  return c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : '.';
}

export function hexOffset(n: number): string {
  return n.toString(16).padStart(8, '0');
}

export function toHexString(b: Uint8Array): string {
  const lines: string[] = [];
  for (let o = 0; o < b.length; o += 16) {
    const row = b.subarray(o, o + 16);
    lines.push(`${hexOffset(o)}  ${Array.from(row, (x) => HEX[x]).join(' ')}`);
  }
  return lines.join('\n');
}
