import { useEffect, useMemo } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useDrift, useHistory, useProposals, useQuarantine, useTelemetry } from '../api/hooks';
import type { DriftAlert, Proposal, QuarantineRecord, QuarantineSummary } from '../api/types';
import { fmtClock, fmtInt, fmtPct } from '../lib/format';
import { useUtc } from '../components/utc';
import { Card, cx, Empty, PageHeader, Pill, StatCard, Td, Th, Table, rowActivate, rowClass } from '../components/ui';
import { ProposalDetail } from './review/ProposalDetail';
import { DriftDetail } from './review/DriftDetail';
import { QuarantineDetail } from './review/QuarantineDetail';

type Item =
  | {
      kind: 'proposal';
      id: string;
      at: string;
      source: string;
      reason: string;
      score: string;
      scoreTitle: string;
      status: string;
      active: boolean;
      p: Proposal;
    }
  | {
      kind: 'drift';
      id: string;
      at: string;
      source: string;
      reason: string;
      score: string;
      scoreTitle: string;
      status: string;
      active: boolean;
      a: DriftAlert;
    }
  | {
      kind: 'source';
      id: string;
      at: string;
      source: string;
      reason: string;
      score: string;
      scoreTitle: string;
      status: string;
      active: boolean;
      s: QuarantineSummary;
    };

const STAGE_REASON: Record<string, string> = {
  detect: 'No parser matched',
  extract: 'Extractor failed',
  normalize: 'Mapping failed',
  integrity: 'Integrity check failed',
};

/**
 * Screen 3, Self-Healing Review Queue. The Figma layout (four stat cards, a
 * queue table, a detail panel) carrying the PRD's content: drift alerts,
 * parser proposals with typed fields and dry-run results, and the quarantine
 * they came from. Approval is per proposal, because that is what the data
 * plane activates and replays; a single quarantined record cannot be
 * "approved" on its own.
 */
export default function ReviewQueue() {
  const { kind, id } = useParams();
  const navigate = useNavigate();
  const utc = useUtc();
  const tel = useTelemetry();
  const proposals = useProposals();
  const drift = useDrift();
  const quarantine = useQuarantine({ status: 'open' });
  const history = useHistory();

  const items = useMemo<Item[]>(() => {
    const out: Item[] = [];
    const recs = quarantine.data?.records ?? [];
    for (const p of proposals.data?.proposals ?? []) {
      out.push({
        kind: 'proposal',
        id: p.id,
        at: p.created_at,
        source: p.source_id,
        reason: p.kind === 'new' ? `New parser ${p.parser_id}` : `Patch ${p.parser_id} ${p.base_version}`,
        score: p.dry_run ? fmtPct(p.dry_run.match_rate) : '—',
        scoreTitle: 'Dry-run match rate',
        status: p.status,
        active: p.status === 'pending',
        p,
      });
    }
    for (const a of drift.data?.alerts ?? []) {
      out.push({
        kind: 'drift',
        id: a.id,
        at: a.first_seen,
        source: a.source_id,
        reason: a.signals[0] ?? 'Format drift',
        score: a.score.toFixed(2),
        scoreTitle: 'Drift score (0-1)',
        status: a.status,
        active: a.status === 'open' || a.status === 'proposed',
        a,
      });
    }
    for (const s of quarantine.data?.summary ?? []) {
      if (s.open === 0) continue;
      const first = recs.filter((r) => r.source_id === s.source_id);
      const stage = Object.entries(s.by_stage).sort((x, y) => y[1] - x[1])[0]?.[0] ?? 'detect';
      out.push({
        kind: 'source',
        id: s.source_id,
        at: first.at(-1)?.received_at ?? first[0]?.received_at ?? '',
        source: s.source_id,
        reason: STAGE_REASON[stage] ?? stage,
        score: fmtInt(s.open),
        scoreTitle: 'Open quarantined records',
        status: 'quarantined',
        active: true,
        s,
      });
    }
    const rank = (x: Item) =>
      x.kind === 'proposal' && x.active ? 0 : x.kind === 'drift' && x.active ? 1 : x.kind === 'source' ? 2 : 3;
    return out.sort((a, b) => rank(a) - rank(b) || b.at.localeCompare(a.at));
  }, [proposals.data, drift.data, quarantine.data]);

  const selected = items.find((x) => x.kind === kind && x.id === id) ?? (kind ? undefined : items[0]);
  useEffect(() => {
    if (!kind && items[0]) navigate(`/review/${items[0].kind}/${encodeURIComponent(items[0].id)}`, { replace: true });
  }, [kind, items, navigate]);

  const pendingProposals = (proposals.data?.proposals ?? []).filter((p) => p.status === 'pending').length;
  const openDrift = (drift.data?.alerts ?? []).filter((a) => a.status === 'open' || a.status === 'proposed').length;
  const t = tel.data;
  const loading = proposals.isPending || drift.isPending || quarantine.isPending;

  return (
    <div className="flex-1 min-h-0 flex flex-col gap-4 py-6">
      <PageHeader title="Review Queue" subtitle="Inspect only the records that need human judgment." />
      <section aria-label="Queue summary" className="grid grid-cols-4 gap-4 shrink-0">
        <StatCard label="Open cases" value={t ? fmtInt(t.quarantine_open) : '—'} sub="quarantined records" />
        <StatCard label="Pending proposals" value={fmtInt(pendingProposals)} sub="awaiting approval" />
        <StatCard label="Drift alerts" value={fmtInt(openDrift)} sub="open" />
        <StatCard
          label="Lossless"
          value={!t ? '—' : t.lossless.last_verify_ok ? '100%' : 'FAILED'}
          tone={t?.lossless.last_verify_ok ? 'mint' : undefined}
          sub="raw safe in vault"
        />
      </section>
      <div className="flex-1 min-h-0 grid grid-cols-[minmax(0,2fr)_minmax(0,3fr)] xl:grid-cols-2 gap-4">
        <Card pad={false} className="min-h-0 overflow-hidden flex flex-col">
          <div className="min-h-0 overflow-y-auto">
            <Table>
              <colgroup>
                <col className="hidden xl:table-column w-32" />
                <col className="hidden xl:table-column w-28" />
                <col />
                <col className="hidden xl:table-column w-20" />
                <col className="w-40" />
              </colgroup>
              <thead className="sticky top-0 z-10">
                <tr>
                  <Th dense className="hidden xl:table-cell">
                    Received
                  </Th>
                  <Th dense className="hidden xl:table-cell">
                    Source
                  </Th>
                  <Th dense>Reason</Th>
                  <Th dense className="hidden xl:table-cell">
                    Score
                  </Th>
                  <Th dense>Status</Th>
                </tr>
              </thead>
              <tbody>
                {items.map((x, i) => (
                  <tr
                    key={`${x.kind}:${x.id}`}
                    className={cx(rowClass(i, x === selected), !x.active && 'text-text-muted')}
                    {...rowActivate(() => navigate(`/review/${x.kind}/${encodeURIComponent(x.id)}`))}
                    aria-selected={x === selected}
                  >
                    <Td dense className="hidden xl:table-cell font-mono text-code text-text-muted">
                      {x.at ? fmtClock(x.at, utc) : '—'}
                    </Td>
                    <Td dense className="hidden xl:table-cell" title={x.source}>
                      {x.source}
                    </Td>
                    <Td dense title={`${x.source}: ${x.reason}`}>
                      <span className="xl:hidden text-text-muted">{x.source} · </span>
                      {x.reason}
                    </Td>
                    <Td dense className="hidden xl:table-cell" title={x.scoreTitle}>
                      {x.score}
                    </Td>
                    <Td dense>
                      <Pill
                        tone={
                          x.status === 'approved' || x.status === 'resolved'
                            ? 'verified'
                            : x.active
                              ? 'primary'
                              : 'muted'
                        }
                      >
                        {x.status}
                      </Pill>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
            {loading ? (
              <Empty title="Loading the queue…" />
            ) : (
              items.length === 0 && (
                <Empty title="Nothing needs review.">
                  Every record parsed, no drift detected, no proposals pending.
                </Empty>
              )
            )}
          </div>
        </Card>
        <Card className="min-h-0 overflow-y-auto">
          {!selected ? (
            <Empty title={kind ? 'This item is no longer in the queue.' : 'Select an item.'} />
          ) : selected.kind === 'proposal' ? (
            <ProposalDetail key={selected.id} proposal={selected.p} history={history.data?.history ?? []} />
          ) : selected.kind === 'drift' ? (
            <DriftDetail alert={selected.a} proposals={proposals.data?.proposals ?? []} utc={utc} />
          ) : (
            <QuarantineDetail
              summary={selected.s}
              records={(quarantine.data?.records ?? []).filter((r: QuarantineRecord) => r.source_id === selected.id)}
              proposals={proposals.data?.proposals ?? []}
              utc={utc}
            />
          )}
        </Card>
      </div>
    </div>
  );
}
