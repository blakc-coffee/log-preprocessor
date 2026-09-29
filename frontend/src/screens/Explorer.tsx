import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { useVirtualizer } from '@tanstack/react-virtual';
import { EVENT_PAGE, epsHistory, fetchTail, useEventPages, useTelemetry } from '../api/hooks';
import type { NormalizedEvent } from '../api/types';
import { ApiError } from '../api/client';
import {
  actionName,
  actionOptions,
  fmtBytes,
  fmtClock,
  fmtInt,
  fmtPct,
  fmtRate,
  productName,
  severityName,
  severityOptions,
} from '../lib/format';
import { parseSearch } from '../lib/search';
import { useUtc } from '../components/utc';
import { Button, cx, Empty, Input, Meter, PageHeader, Pill, Select, Sparkline, StatCard } from '../components/ui';
import { EventModal } from './EventModal';

// Column template. Severity, confidence and flags drop out below 1280px so
// the table never overlaps at the 1024px artboard width.
const COLS =
  'grid-cols-[120px_112px_minmax(0,1fr)_104px_92px_minmax(0,160px)_104px] xl:grid-cols-[128px_124px_minmax(0,1fr)_104px_92px_96px_minmax(0,180px)_136px_80px_104px]';
const WIDE = 'hidden xl:flex';

const VENDORS = [
  { value: 'cisco', label: 'Cisco ASA' },
  { value: 'fortinet', label: 'Fortinet' },
  { value: 'oisf', label: 'Suricata' },
  { value: 'palo_alto', label: 'Palo Alto' },
  { value: 'isc', label: 'ISC DHCP' },
  { value: 'freeradius', label: 'RADIUS' },
];
const FLAGS = [
  'invalid_utf8',
  'control_chars',
  'duplicate_key',
  'key_injection_suspect',
  'oversize_field',
  'render_back_mismatch',
  'low_confidence',
  'time_unparseable',
  'fragment_record',
];
const RANGES = [
  { value: '', label: 'All time' },
  { value: '15', label: 'Last 15 min' },
  { value: '60', label: 'Last hour' },
  { value: '1440', label: 'Last 24 h' },
];

export function Explorer() {
  const { eventId } = useParams();
  const navigate = useNavigate();
  const utc = useUtc();
  const tel = useTelemetry();
  // Re-read the history whenever a telemetry poll lands.
  const eps = useMemo(() => epsHistory(), [tel.dataUpdatedAt]); // eslint-disable-line react-hooks/exhaustive-deps

  const [params] = useSearchParams();
  const [query, setQuery] = useState(() => params.get('q') ?? '');
  const [vendor, setVendor] = useState('');
  const [severity, setSeverity] = useState('');
  const [action, setAction] = useState('');
  const [flag, setFlag] = useState('');
  const [range, setRange] = useState('');
  const [live, setLive] = useState(true);
  const searchRef = useRef<HTMLInputElement>(null);

  const search = useMemo(() => parseSearch(query), [query]);
  // `from` is fixed when the range is chosen, so the query key is stable.
  const from = useMemo(() => (range ? new Date(Date.now() - Number(range) * 60_000).toISOString() : ''), [range]);
  const filters = useMemo(() => {
    const f: Record<string, string> = { ...search.params };
    if (vendor) f.vendor = vendor;
    if (severity) f.severity = severity;
    if (action) f.action = action;
    if (flag) f.flag = flag;
    if (from) f.from = from;
    return f;
  }, [search.params, vendor, severity, action, flag, from]);

  const pages = useEventPages(filters);
  const paged = useMemo(() => pages.data?.pages.flatMap((p) => p.events) ?? [], [pages.data]);
  const maxSeq = pages.data?.pages[0]?.max_seq;

  // Live tail: poll since the newest sequence seen, prepend what arrives. If
  // the reader has scrolled down, hold new rows behind an "N new" pill.
  const [tail, setTail] = useState<NormalizedEvent[]>([]);
  const [held, setHeld] = useState<NormalizedEvent[]>([]);
  const seq = useRef<number | undefined>(undefined);
  const scrollRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    setTail([]);
    setHeld([]);
    seq.current = undefined;
  }, [filters]);
  useEffect(() => {
    if (seq.current === undefined && maxSeq !== undefined) seq.current = maxSeq;
  }, [maxSeq]);
  useEffect(() => {
    if (!live) return;
    const ac = new AbortController();
    const t = setInterval(async () => {
      if (seq.current === undefined) return;
      try {
        const r = await fetchTail(filters, seq.current, ac.signal);
        seq.current = r.max_seq;
        if (!r.events.length) return;
        const fresh = [...r.events].reverse(); // newest first
        if ((scrollRef.current?.scrollTop ?? 0) > 4) setHeld((h) => [...fresh, ...h]);
        else setTail((t0) => [...fresh, ...t0]);
      } catch {
        /* the banner reports an unreachable admin; keep the rows we have */
      }
    }, 2000);
    return () => {
      clearInterval(t);
      ac.abort();
    };
  }, [live, filters]);

  const rows = useMemo(() => {
    const seen = new Set<string>();
    return [...tail, ...paged].filter((e) => (seen.has(e.event_id) ? false : (seen.add(e.event_id), true)));
  }, [tail, paged]);

  const showHeld = useCallback(() => {
    setTail((t) => [...held, ...t]);
    setHeld([]);
    scrollRef.current?.scrollTo({ top: 0 });
  }, [held]);

  const rv = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 48,
    overscan: 12,
  });
  const items = rv.getVirtualItems();
  const lastIndex = items.at(-1)?.index ?? 0;
  useEffect(() => {
    if (lastIndex >= rows.length - 20 && pages.hasNextPage && !pages.isFetchingNextPage) void pages.fetchNextPage();
  }, [lastIndex, rows.length, pages]);

  const [sel, setSel] = useState(0);
  const open = useCallback(
    (e: NormalizedEvent | undefined) => e && navigate(`/events/${encodeURIComponent(e.event_id)}`),
    [navigate],
  );
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (eventId || e.metaKey || e.ctrlKey || e.altKey) return;
      const tag = (e.target as HTMLElement).tagName;
      if (tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA') return;
      if (e.key === '/') {
        e.preventDefault();
        searchRef.current?.focus();
      } else if (e.key === 'j' || e.key === 'k') {
        const n = Math.min(rows.length - 1, Math.max(0, sel + (e.key === 'j' ? 1 : -1)));
        setSel(n);
        rv.scrollToIndex(n, { align: 'auto' });
      } else if (e.key === 'Enter') {
        open(rows[sel]);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [eventId, rows, sel, rv, open]);

  const t = tel.data;
  const err = pages.error instanceof ApiError ? pages.error : null;
  const terms = [...search.terms.map((x) => `${x.key} = ${x.value}`)];

  return (
    <div className="flex-1 min-h-0 flex flex-col gap-4 py-6">
      <PageHeader title="Unified Lineage Explorer" subtitle="Normalized telemetry with immutable raw lineage." />

      <section aria-label="Telemetry" className="grid grid-cols-4 gap-4 shrink-0">
        <StatCard
          label="Events / sec"
          value={t ? fmtRate(t.eps_1m) : '—'}
          sub={t ? `peak ${fmtRate(t.eps_peak)}` : undefined}
          title="1-minute average and peak"
        >
          <Sparkline samples={eps} label="Events per second, recent history" />
        </StatCard>
        <StatCard
          label="Vault size"
          value={t ? fmtBytes(t.vault.bytes_raw) : '—'}
          sub={t ? `${fmtInt(t.vault.records)} records · ${t.vault.ratio.toFixed(2)}× compressed` : undefined}
        />
        <StatCard
          label="Lossless"
          value={!t ? '—' : t.lossless.last_verify_ok ? '100%' : 'FAILED'}
          tone={t?.lossless.last_verify_ok ? 'mint' : undefined}
          sub={t ? `sealed through #${fmtInt(t.vault.sealed_through)}` : undefined}
          title={
            t && t.vault.records > t.vault.sealed_through
              ? `Last chain verification passed. ${fmtInt(t.vault.records - t.vault.sealed_through)} newest records are in the active segment and are chained when it seals.`
              : 'Last hash-chain verification of the vault.'
          }
        />
        <StatCard
          label="Quarantined"
          value={t ? fmtInt(t.quarantine_open) : '—'}
          sub={t ? 'open · review' : undefined}
          onClick={() => navigate('/review')}
          title="Open the Review Queue"
        />
      </section>

      <div role="search" className="h-band shrink-0 flex items-center gap-2 min-w-0">
        <Input
          ref={searchRef}
          type="search"
          aria-label="Search events"
          placeholder="Search by IP, user, host or vendor  (/)"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="flex-1"
        />
        <Select aria-label="Source" value={vendor} onChange={(e) => setVendor(e.target.value)}>
          <option value="">All sources</option>
          {VENDORS.map((v) => (
            <option key={v.value} value={v.value}>
              {v.label}
            </option>
          ))}
        </Select>
        <Select aria-label="Severity" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">Severity: All</option>
          {severityOptions.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </Select>
        <Select aria-label="Action" value={action} onChange={(e) => setAction(e.target.value)}>
          <option value="">Action: All</option>
          {actionOptions.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </Select>
        <Select
          aria-label="Integrity flag"
          value={flag}
          onChange={(e) => setFlag(e.target.value)}
          className="hidden lg:block"
        >
          <option value="">Flags: Any</option>
          {FLAGS.map((f) => (
            <option key={f} value={f}>
              {f}
            </option>
          ))}
        </Select>
        <Select aria-label="Time range" value={range} onChange={(e) => setRange(e.target.value)}>
          {RANGES.map((r) => (
            <option key={r.value} value={r.value}>
              {r.label}
            </option>
          ))}
        </Select>
        <Button pressed={live} onClick={() => setLive(!live)} title="Poll for new events every 2 seconds">
          {live ? 'Live' : 'Paused'}
        </Button>
      </div>

      <section
        aria-label="Events"
        className="flex-1 min-h-0 flex flex-col bg-card rounded-card border border-border overflow-hidden"
      >
        <div role="row" className={cx('grid shrink-0 h-12 items-center bg-canvas border-b border-border', COLS)}>
          {['Timestamp', 'Source', 'Src to dst', 'Protocol', 'Action'].map((h) => (
            <Header key={h}>{h}</Header>
          ))}
          <Header className={WIDE}>Severity</Header>
          <Header>User / host</Header>
          <Header className={WIDE}>Confidence</Header>
          <Header className={WIDE}>Flags</Header>
          <Header>Status</Header>
        </div>
        <div
          ref={scrollRef}
          className="relative flex-1 min-h-0 overflow-y-auto"
          role="rowgroup"
          aria-label="Event rows"
        >
          {held.length > 0 && (
            <button
              type="button"
              onClick={showHeld}
              className="sticky top-2 z-10 mx-auto block bg-text-primary text-canvas rounded-pill px-3 py-1 text-label font-semibold"
            >
              {held.length} new {held.length === 1 ? 'event' : 'events'}
            </button>
          )}
          {pages.isPending ? (
            <Empty title="Loading events…" />
          ) : err && rows.length === 0 ? (
            <Empty title={err.adminDown ? 'The data plane is not answering.' : 'Events could not be loaded.'}>
              {err.message}
            </Empty>
          ) : rows.length === 0 ? (
            <Empty title="No events match these filters.">
              {Object.keys(filters).length
                ? 'Clear a filter or widen the time range.'
                : 'Nothing has been ingested yet.'}
            </Empty>
          ) : (
            <div style={{ height: rv.getTotalSize(), position: 'relative' }}>
              {items.map((vi) => {
                const e = rows[vi.index]!;
                return (
                  <EventRow
                    key={e.event_id}
                    e={e}
                    utc={utc}
                    index={vi.index}
                    selected={vi.index === sel}
                    top={vi.start}
                    onOpen={() => {
                      setSel(vi.index);
                      open(e);
                    }}
                  />
                );
              })}
            </div>
          )}
        </div>
        <footer className="shrink-0 h-12 flex items-center justify-between gap-4 border-t border-border px-card text-body text-text-muted min-w-0">
          <span className="truncate">
            {fmtInt(rows.length)} loaded{t ? ` of ${fmtInt(t.events_total)} events` : ''}
            {pages.isFetchingNextPage
              ? ' · loading more…'
              : pages.hasNextPage
                ? ''
                : rows.length >= EVENT_PAGE
                  ? ' · end of results'
                  : ''}
          </span>
          <span className="truncate text-right">
            {terms.length > 0 && `Search: ${terms.join(', ')}`}
            {search.unsupported.length > 0 && ` · ${search.unsupported.join('; ')}`}
            {terms.length === 0 && search.unsupported.length === 0 && 'j / k to move · Enter to open'}
          </span>
        </footer>
      </section>

      {eventId && <EventModal eventId={eventId} onClose={() => navigate('/')} />}
    </div>
  );
}

function Header({ children, className }: { children: string; className?: string }) {
  return (
    <div
      role="columnheader"
      className={cx(
        'px-card text-label font-medium uppercase tracking-label text-text-muted truncate flex items-center',
        className,
      )}
    >
      {children}
    </div>
  );
}

function endpoint(ep: { ip?: string; port?: number } | undefined): string {
  if (!ep?.ip) return '—';
  return ep.port !== undefined ? `${ep.ip}:${ep.port}` : ep.ip;
}

function EventRow({
  e,
  utc,
  index,
  selected,
  top,
  onOpen,
}: {
  e: NormalizedEvent;
  utc: boolean;
  index: number;
  selected: boolean;
  top: number;
  onOpen: () => void;
}) {
  const o = e.ocsf;
  const user = e.entities.find((x) => x.type === 'user')?.id;
  const host = e.entities.find((x) => x.type === 'host')?.id;
  const flags = e.integrity_flags.length;
  const cell = 'px-card truncate flex items-center min-w-0';
  return (
    <div
      role="row"
      aria-selected={selected}
      tabIndex={-1}
      onClick={onOpen}
      className={cx(
        'grid absolute inset-x-0 h-row items-center border-b border-border text-body cursor-pointer hover:bg-hover',
        selected ? 'bg-selected' : index % 2 === 0 ? 'bg-card' : 'bg-canvas',
        COLS,
      )}
      style={{ transform: `translateY(${top}px)` }}
    >
      <span
        role="gridcell"
        className={cx(cell, 'font-mono text-code text-text-muted')}
        title={e.event_time ?? e.received_at}
      >
        {fmtClock(e.event_time ?? e.received_at, utc)}
      </span>
      <span role="gridcell" className={cell}>
        <span className="truncate">{productName(e.vendor, e.product)}</span>
      </span>
      <span role="gridcell" className={cell} title={`${endpoint(o.src_endpoint)} to ${endpoint(o.dst_endpoint)}`}>
        <span className="truncate">
          {endpoint(o.src_endpoint)} <span className="text-text-muted">to</span> {endpoint(o.dst_endpoint)}
        </span>
      </span>
      <span role="gridcell" className={cell}>
        {o.connection_info?.protocol_name?.toUpperCase() ?? '—'}
      </span>
      <span role="gridcell" className={cell}>
        {actionName(o.action_id)}
      </span>
      <span role="gridcell" className={cx(cell, WIDE)}>
        {severityName(o.severity_id)}
      </span>
      <span role="gridcell" className={cx(cell, 'text-text-muted')} title={[user, host].filter(Boolean).join(' · ')}>
        <span className="truncate">{[user, host].filter(Boolean).join(' · ') || '—'}</span>
      </span>
      <span role="gridcell" className={cx(cell, WIDE, 'gap-2')}>
        <Meter value={e.parse_confidence} label="Parse confidence" size="sm" />
        <span className="text-text-muted">{fmtPct(e.parse_confidence)}</span>
      </span>
      <span
        role="gridcell"
        className={cx(cell, WIDE, flags ? 'text-text-primary' : 'text-text-muted')}
        title={e.integrity_flags.join(', ')}
      >
        {flags || '—'}
      </span>
      <span role="gridcell" className={cell}>
        <Pill title={e.current ? 'Normalized to OCSF 1.1.0' : 'Superseded by a newer parser version'}>
          {e.current ? 'OCSF' : 'Superseded'}
        </Pill>
      </span>
    </div>
  );
}
