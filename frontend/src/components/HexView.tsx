import { useMemo, useRef, useState } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import type { RawResponse } from '../api/types';
import { ByteClass, classify, gutterChar, HEX, hexOffset, summarize, toHexString } from '../lib/hex';
import { Button, cx } from './ui';

const ROW = 18; // one 11px mono line

/**
 * Hex dump: offset, 16 bytes, ASCII gutter. Rows are virtualized, so a
 * 1.5 MiB record renders only what is on screen. Invalid UTF-8 is shown
 * inverted (white block), control bytes muted.
 */
export function HexView({ bytes, raw, eventId }: { bytes: Uint8Array; raw: RawResponse; eventId: string }) {
  const cls = useMemo(() => classify(bytes), [bytes]);
  const sum = useMemo(() => summarize(cls), [cls]);
  const scroll = useRef<HTMLDivElement>(null);
  const rows = Math.max(1, Math.ceil(bytes.length / 16));
  const rv = useVirtualizer({
    count: rows,
    getScrollElement: () => scroll.current,
    estimateSize: () => ROW,
    overscan: 20,
  });
  const [copied, setCopied] = useState(false);

  const download = () => {
    const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type: 'application/octet-stream' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `${eventId.replace(/[^A-Za-z0-9._@-]/g, '_')}.raw`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const frag =
    raw.fragment === 0
      ? 'none'
      : [raw.fragment & 1 ? 'more follows' : '', raw.fragment & 2 ? 'continuation' : ''].filter(Boolean).join(', ');

  return (
    <>
      <div className="shrink-0 px-card py-3 border-b border-border space-y-2">
        <dl className="grid grid-cols-[max-content_minmax(0,1fr)_max-content_minmax(0,1fr)] gap-x-3 gap-y-0.5 font-mono text-label">
          <dt className="text-text-muted">length</dt>
          <dd>{bytes.length} B</dd>
          <dt className="text-text-muted">terminator</dt>
          <dd>{raw.terminator}</dd>
          <dt className="text-text-muted">origin</dt>
          <dd className="truncate" title={`${raw.origin.kind} ${raw.origin.addr} @${raw.origin.offset}`}>
            {raw.origin.kind} {raw.origin.addr}
          </dd>
          <dt className="text-text-muted">fragment</dt>
          <dd>{frag}</dd>
          <dt className="text-text-muted">invalid utf-8</dt>
          <dd>{sum.invalid}</dd>
          <dt className="text-text-muted">control</dt>
          <dd>{sum.control}</dd>
        </dl>
        <div className="flex gap-2">
          <Button
            onClick={() => {
              void navigator.clipboard?.writeText(toHexString(bytes)).then(() => setCopied(true));
              setTimeout(() => setCopied(false), 1500);
            }}
          >
            {copied ? 'Copied' : 'Copy hex'}
          </Button>
          <Button onClick={download}>Download raw</Button>
        </div>
      </div>
      <div
        ref={scroll}
        className="flex-1 min-h-0 overflow-auto px-card py-2 bg-canvas"
        role="region"
        aria-label="Hex dump"
        tabIndex={0}
      >
        <div style={{ height: rv.getTotalSize(), position: 'relative' }} className="font-mono text-label">
          {rv.getVirtualItems().map((vi) => {
            const off = vi.index * 16;
            const row = bytes.subarray(off, off + 16);
            return (
              <div
                key={vi.index}
                className="absolute inset-x-0 flex gap-3 whitespace-pre"
                style={{ top: vi.start, height: ROW, lineHeight: `${ROW}px` }}
              >
                <span className="text-text-muted">{hexOffset(off)}</span>
                <span>
                  {Array.from({ length: 16 }, (_, i) => {
                    const b = row[i];
                    if (b === undefined) return <span key={i}>{'   '}</span>;
                    return (
                      <span key={i} className={byteCls(cls[off + i]!)}>
                        {HEX[b]}
                        {i === 7 ? '  ' : ' '}
                      </span>
                    );
                  })}
                </span>
                <span aria-hidden>
                  |
                  {Array.from(row, (b, i) => (
                    <span key={i} className={byteCls(cls[off + i]!)}>
                      {gutterChar(b)}
                    </span>
                  ))}
                  |
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </>
  );
}

function byteCls(c: number): string {
  return cx(c === ByteClass.Invalid && 'bg-text-primary text-canvas', c === ByteClass.Control && 'text-text-muted');
}
