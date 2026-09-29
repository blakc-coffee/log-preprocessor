import { useEffect, useMemo, useRef, useState } from 'react';
import { useEvent, useLineage, useRaw } from '../api/hooks';
import type { Coverage, Entity, NormalizedEvent } from '../api/types';
import { base64ToBytes, checkMerkle, checkSha, type Check, type LineageInput } from '../lib/merkle';
import { fmtDateTime, fmtPct, productName } from '../lib/format';
import { useUtc } from '../components/utc';
import { Button, cx, Empty, Label, StateWord } from '../components/ui';
import { JsonTree } from '../components/JsonTree';
import { HexView } from '../components/HexView';

/**
 * Byte-exact forensic split modal (Screen 2): the normalized event on the
 * left, the raw bytes on the right, and three verifications computed in this
 * browser in the footer. The explorer behind it is darkened, not blurred:
 * DESIGN.md bans backdrop-filter.
 */
export function EventModal({ eventId, onClose }: { eventId: string; onClose: () => void }) {
  const ev = useEvent(eventId);
  const raw = useRaw(eventId);
  const lin = useLineage(eventId);
  const utc = useUtc();
  const box = useRef<HTMLDivElement>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    box.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
      if (e.key === 'Tab' && box.current) {
        // Keep focus inside the dialog.
        const f = box.current.querySelectorAll<HTMLElement>('button, [href], input, summary, [tabindex="0"]');
        if (!f.length) return;
        const first = f[0]!;
        const last = f[f.length - 1]!;
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      prev?.focus();
    };
  }, [onClose]);

  const bytes = useMemo(() => (raw.data ? base64ToBytes(raw.data.raw_base64) : null), [raw.data]);

  const checks = useMemo(() => {
    if (!ev.data || !raw.data || !lin.data || !bytes) return null;
    const input: LineageInput = {
      raw: bytes,
      eventRawSha256: ev.data.raw_sha256,
      serverRawSha256: raw.data.raw_sha256,
      meta: {
        recordId: raw.data.record_id,
        receivedAt: raw.data.received_at,
        sourceId: ev.data.source_id,
        origin: raw.data.origin,
        terminator: raw.data.terminator,
        fragment: raw.data.fragment,
      },
      sealed: lin.data.sealed,
      proof: lin.data.proof,
    };
    return { sha: checkSha(input), merkle: checkMerkle(input), render: checkRender(lin.data.coverage, bytes.length) };
  }, [ev.data, raw.data, lin.data, bytes]);

  const e = ev.data;
  const error = ev.error ?? raw.error ?? lin.error;

  return (
    <div
      className="fixed inset-0 z-50 bg-backdrop flex items-center justify-center p-page"
      onMouseDown={(x) => x.target === x.currentTarget && onClose()}
    >
      <div
        ref={box}
        role="dialog"
        aria-modal="true"
        aria-labelledby="event-modal-title"
        tabIndex={-1}
        className="bg-card rounded-card border border-border w-full max-w-modal h-modal-h max-h-[80vh] overflow-hidden flex flex-col"
      >
        <header className="h-band shrink-0 flex items-center gap-4 px-card border-b border-border min-w-0">
          <h2 id="event-modal-title" className="text-heading font-semibold truncate">
            {e ? productName(e.vendor, e.product) : 'Event'}
          </h2>
          <span className="font-mono text-code text-text-muted truncate">{eventId}</span>
          {e && (
            <span className="text-body text-text-muted whitespace-nowrap hidden lg:inline">
              {fmtDateTime(e.event_time ?? e.received_at, utc)}
            </span>
          )}
          <span className="flex-1" />
          <Button
            disabled={!e}
            onClick={() => {
              void navigator.clipboard?.writeText(JSON.stringify(e, null, 2)).then(() => setCopied(true));
              setTimeout(() => setCopied(false), 1500);
            }}
          >
            {copied ? 'Copied' : 'Copy JSON'}
          </Button>
          <Button aria-label="Close" onClick={onClose}>
            Close
          </Button>
        </header>

        {error ? (
          <div className="flex-1">
            <Empty title="This event could not be loaded.">{(error as Error).message}</Empty>
          </div>
        ) : (
          <div className="flex-1 min-h-0 grid grid-cols-2">
            <div
              className="min-h-0 overflow-y-auto border-r border-border p-card space-y-4"
              aria-label="Normalized event"
            >
              {e ? <EventDetail e={e} utc={utc} /> : <Empty title="Loading event…" />}
            </div>
            <div className="min-h-0 flex flex-col" aria-label="Raw bytes">
              {raw.data && bytes ? (
                <HexView bytes={bytes} raw={raw.data} eventId={eventId} />
              ) : (
                <Empty title="Loading raw bytes from the vault…" />
              )}
            </div>
          </div>
        )}

        <footer
          className="h-band shrink-0 grid grid-cols-3 border-t border-border"
          aria-label="Verification, computed in this browser"
        >
          <CheckCell title="SHA-256 in your browser" check={checks?.sha} />
          <CheckCell title="Merkle inclusion + chain" check={checks?.merkle} />
          <CheckCell title="Render-back + coverage" check={checks?.render} last />
        </footer>
      </div>
    </div>
  );
}

function checkRender(c: Coverage, rawLen: number): Check {
  const sum = c.mapped_bytes + c.unmapped_bytes + c.constant_bytes + c.uncovered_bytes;
  if (sum !== rawLen) return { state: 'fail', detail: `Coverage accounts for ${sum} of ${rawLen} bytes.` };
  if (!c.applicable) return { state: 'na', detail: `Not a template parser; ${c.uncovered_bytes} uncovered bytes.` };
  if (c.render_back_ok === false)
    return { state: 'fail', detail: 'Re-rendering the typed values does not reproduce the raw line.' };
  return { state: 'pass', detail: `Raw line re-rendered exactly; ${c.uncovered_bytes} uncovered bytes.` };
}

function CheckCell({ title, check, last }: { title: string; check: Check | undefined; last?: boolean }) {
  const state = check?.state ?? 'pending';
  return (
    <div
      className={cx('min-w-0 px-card flex flex-col justify-center', !last && 'border-r border-border')}
      title={check?.detail}
    >
      <div className="flex items-center gap-2 min-w-0">
        <StateWord state={state} />
        <span className="text-body text-text-primary truncate">{title}</span>
      </div>
      <span className="text-label text-text-muted truncate">
        {check?.detail ?? 'Waiting for the event, raw bytes and lineage…'}
      </span>
    </div>
  );
}

function Section({
  label,
  children,
  count,
  highlight,
}: {
  label: string;
  children: React.ReactNode;
  count?: number;
  highlight?: boolean;
}) {
  return (
    <section className={cx('rounded-button', highlight && 'bg-selected -mx-2 px-2 py-2')}>
      <Label as="h3" className="block mb-2">
        {label}
        {count !== undefined && <span className="text-text-primary"> · {count}</span>}
      </Label>
      {children}
    </section>
  );
}

function EventDetail({ e, utc }: { e: NormalizedEvent; utc: boolean }) {
  const ids: [string, string][] = [
    ['record_id', String(e.record_id)],
    ['segment', String(e.segment)],
    ['parser', `${e.parser_id}@${e.parser_version}`],
    ['template_id', e.template_id],
    ['source_id', e.source_id],
    ['received_at', fmtDateTime(e.received_at, utc)],
    [
      'event_time',
      e.time_from_receipt ? `${fmtDateTime(e.event_time, utc)} (from receipt)` : fmtDateTime(e.event_time, utc),
    ],
    ['parse_confidence', fmtPct(e.parse_confidence)],
    ['raw_sha256', e.raw_sha256],
  ];
  return (
    <>
      <Section label="Identifiers">
        <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1 font-mono text-code">
          {ids.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-text-muted">{k}</dt>
              <dd className="truncate" title={v}>
                {v}
              </dd>
            </div>
          ))}
        </dl>
        {e.integrity_flags.length > 0 && (
          <p className="mt-2 font-mono text-code">
            <span className="text-text-muted">flags </span>
            {e.integrity_flags.join(' ')}
          </p>
        )}
      </Section>
      <Section label="OCSF">
        <JsonTree value={e.ocsf} />
      </Section>
      <Section label="Unmapped" count={Object.keys(e.unmapped).length} highlight>
        {Object.keys(e.unmapped).length ? (
          <JsonTree value={e.unmapped} />
        ) : (
          <p className="text-body text-text-muted">Every capture is mapped.</p>
        )}
      </Section>
      <Section label="Entities" count={e.entities.length}>
        {e.entities.length ? (
          <ul className="space-y-1">
            {e.entities.map((x, i) => (
              <EntityRow key={i} x={x} utc={utc} />
            ))}
          </ul>
        ) : (
          <p className="text-body text-text-muted">No identity resolved for these addresses.</p>
        )}
      </Section>
      <Section label="Coverage">
        <CoverageBar c={e.coverage} />
      </Section>
      {e.identity && (
        <Section label="Identity fact">
          <JsonTree value={e.identity} />
        </Section>
      )}
    </>
  );
}

function EntityRow({ x, utc }: { x: Entity; utc: boolean }) {
  const valid = x.valid_from
    ? `${fmtDateTime(x.valid_from, utc)} → ${x.valid_to ? fmtDateTime(x.valid_to, utc) : 'open'}`
    : '';
  return (
    <li className="flex items-center gap-2 min-w-0 text-body">
      <span className="bg-canvas border border-border rounded-pill px-2 py-0.5 font-mono text-code whitespace-nowrap">
        {x.type} {x.id}
      </span>
      <span className="text-text-muted whitespace-nowrap">{x.role}</span>
      <span className="text-text-muted truncate text-label" title={valid}>
        {valid}
      </span>
      {x.evidence.length > 0 && (
        <span
          className="ml-auto font-mono text-label text-text-muted whitespace-nowrap"
          title="Identity records that justify this binding"
        >
          {x.evidence.map((ev) => `#${ev.record_id} ${ev.kind}`).join(', ')}
        </span>
      )}
    </li>
  );
}

/** Byte accounting as one bar: lavender at decreasing strength, uncovered left empty. */
export function CoverageBar({ c }: { c: Coverage }) {
  const total = c.mapped_bytes + c.unmapped_bytes + c.constant_bytes + c.uncovered_bytes || 1;
  const segs = [
    { k: 'mapped', v: c.mapped_bytes, cls: 'bg-lavender' },
    { k: 'unmapped', v: c.unmapped_bytes, cls: 'bg-lavender opacity-50' },
    { k: 'constant', v: c.constant_bytes, cls: 'bg-lavender opacity-20' },
    { k: 'uncovered', v: c.uncovered_bytes, cls: 'bg-canvas' },
  ];
  return (
    <div className="space-y-2">
      <div
        role="img"
        aria-label="Byte coverage"
        className="h-2 flex rounded-bar overflow-hidden border border-border bg-canvas"
      >
        {segs.map((s) => (
          <span key={s.k} className={s.cls} style={{ width: `${(s.v / total) * 100}%` }} />
        ))}
      </div>
      <dl className="grid grid-cols-4 gap-2 text-label">
        {segs.map((s) => (
          <div key={s.k} className="min-w-0">
            <dt className="text-text-muted uppercase tracking-label flex items-center gap-1.5">
              <span className={cx('inline-block size-2 rounded-bar border border-border', s.cls)} />
              {s.k}
            </dt>
            <dd className="font-mono text-code">{s.v} B</dd>
          </div>
        ))}
      </dl>
      <p className="text-label text-text-muted">
        {c.mapped_fields} mapped fields, {c.unmapped_fields} unmapped · render-back{' '}
        {c.applicable ? (c.render_back_ok ? 'OK' : 'mismatch') : 'not applicable'}
      </p>
    </div>
  );
}
