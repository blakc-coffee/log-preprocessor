import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  useHistory,
  useParsers,
  useParserVersions,
  useParserYAML,
  useRollback,
  useTelemetry,
  useVerifyParser,
} from '../api/hooks';
import type { ParserInfo, RegistryRow } from '../api/types';
import { fmtDateTime, fmtInt, fmtPct, productName, vendorName } from '../lib/format';
import { recordedName } from '../lib/prefs';
import { OCSF_CLASS, summarizeParser } from '../lib/yamlEdit';
import { useUtc } from '../components/utc';
import {
  Button,
  Card,
  CodeBlock,
  Empty,
  Input,
  KV,
  Label,
  PageHeader,
  Pill,
  StatCard,
  StateWord,
  Td,
  Th,
  Table,
  rowActivate,
  rowClass,
} from '../components/ui';
import { YamlDiff } from '../components/Yaml';
import { meetsThreshold } from './review/ProposalDetail';

/**
 * Parser Registry (Figma screen 3). The data plane owns the active parser set
 * (D10); this screen shows it, the approval history the control plane keeps,
 * and offers verification (a dry run of the active version, no side effects)
 * and rollback.
 */
export default function ParserRegistry() {
  const { parserId } = useParams();
  const navigate = useNavigate();
  const parsers = useParsers();
  const history = useHistory();
  const tel = useTelemetry();
  const list = useMemo(() => parsers.data?.parsers ?? [], [parsers.data]);
  const selected = list.find((p) => p.id === parserId) ?? (parserId ? undefined : list[0]);

  useEffect(() => {
    if (!parserId && list[0]) navigate(`/parsers/${encodeURIComponent(list[0].id)}`, { replace: true });
  }, [parserId, list, navigate]);

  const rows = history.data?.history ?? [];
  const t = tel.data;
  return (
    <div className="flex-1 min-h-0 flex flex-col gap-4 py-6">
      <PageHeader title="Parser Registry" subtitle="Manage deterministic parsers without leaving the air gap." />
      <section aria-label="Registry summary" className="grid grid-cols-4 gap-4 shrink-0">
        <StatCard label="Active parsers" value={fmtInt(list.length)} />
        <StatCard
          label="Versions"
          value={fmtInt(list.reduce((n, p) => n + p.versions.length, 0))}
          sub="immutable once written"
        />
        <StatCard
          label="Approvals recorded"
          value={fmtInt(rows.filter((r) => r.action === 'approve' && r.result === 'ok').length)}
          sub={`${fmtInt(rows.length)} audit rows`}
        />
        <StatCard
          label="Lossless"
          value={!t ? '—' : t.lossless.last_verify_ok ? '100%' : 'FAILED'}
          tone={t?.lossless.last_verify_ok ? 'mint' : undefined}
        />
      </section>
      <div className="flex-1 min-h-0 grid grid-cols-2 gap-4">
        <Card pad={false} className="min-h-0 overflow-hidden flex flex-col">
          <div className="min-h-0 overflow-y-auto">
            <Table>
              <colgroup>
                <col />
                <col className="hidden xl:table-column w-28" />
                <col className="w-24" />
                <col className="w-24" />
                <col className="hidden xl:table-column w-32" />
                <col className="w-24" />
              </colgroup>
              <thead className="sticky top-0 z-10">
                <tr>
                  <Th dense>Parser</Th>
                  <Th dense className="hidden xl:table-cell">
                    Vendor
                  </Th>
                  <Th dense>Format</Th>
                  <Th dense>Version</Th>
                  <Th dense className="hidden xl:table-cell">
                    Last change
                  </Th>
                  <Th dense>Status</Th>
                </tr>
              </thead>
              <tbody>
                {list.map((p, i) => (
                  <ParserRow
                    key={p.id}
                    p={p}
                    i={i}
                    selected={p === selected}
                    last={rows.find((r) => r.parser_id === p.id && r.result === 'ok')}
                    onClick={() => navigate(`/parsers/${encodeURIComponent(p.id)}`)}
                  />
                ))}
              </tbody>
            </Table>
            {parsers.isPending && <Empty title="Loading parsers…" />}
          </div>
        </Card>
        <Card className="min-h-0 overflow-y-auto">
          {selected ? (
            <ParserDetail key={selected.id} p={selected} />
          ) : (
            <Empty title={parserId ? `No active parser ${parserId}.` : 'Select a parser.'} />
          )}
        </Card>
      </div>
    </div>
  );
}

function ParserRow({
  p,
  i,
  selected,
  last,
  onClick,
}: {
  p: ParserInfo;
  i: number;
  selected: boolean;
  last?: RegistryRow;
  onClick: () => void;
}) {
  const utc = useUtc();
  const yaml = useParserYAML(p.id, p.active_version);
  const kinds = useMemo(() => (yaml.data ? summarizeParser(yaml.data).kinds : []), [yaml.data]);
  return (
    <tr className={rowClass(i, selected)} {...rowActivate(onClick)} aria-selected={selected}>
      <Td dense title={p.id}>
        {productName(p.vendor, p.product)}
      </Td>
      <Td dense className="hidden xl:table-cell">
        {vendorName(p.vendor)}
      </Td>
      <Td dense>{kinds.map((k) => k.toUpperCase()).join(', ') || '—'}</Td>
      <Td dense className="font-mono text-code">
        {p.active_version}
      </Td>
      <Td
        dense
        className="hidden xl:table-cell text-text-muted"
        title={last ? `${last.action} by ${last.approved_by}` : 'built-in'}
      >
        {last ? fmtDateTime(last.at, utc).slice(5, 16) : 'built-in'}
      </Td>
      <Td dense>
        <Pill>OCSF</Pill>
      </Td>
    </tr>
  );
}

function ParserDetail({ p }: { p: ParserInfo }) {
  const utc = useUtc();
  const yaml = useParserYAML(p.id, p.active_version);
  const versions = useParserVersions(p.id);
  const verify = useVerifyParser(p.id);
  const rollback = useRollback(p.id);
  const sum = useMemo(() => (yaml.data ? summarizeParser(yaml.data) : null), [yaml.data]);
  const [showVersions, setShowVersions] = useState(false);
  const [compare, setCompare] = useState('');
  const other = useParserYAML(p.id, compare || undefined);
  const [name, setName] = useState(recordedName.get);
  const [comment, setComment] = useState('');
  const [confirm, setConfirm] = useState('');

  const cls = sum?.classUid;
  const d = verify.data;
  return (
    <div className="space-y-4">
      <header className="space-y-1">
        <h2 className="text-heading font-semibold">{productName(p.vendor, p.product)}</h2>
        <p className="text-body text-text-muted">
          {sum?.kinds.length ? `${sum.kinds.join(' + ')} parser` : 'Parser'} · {p.id}@{p.active_version}
        </p>
      </header>
      <CodeBlock label="Input signature">{p.signature}</CodeBlock>
      <CodeBlock label="Emitted class">{cls ? `${OCSF_CLASS[cls] ?? 'class'} (${cls})` : '—'}</CodeBlock>
      <CodeBlock label="Mapping" className="max-h-52 overflow-y-auto">
        {sum
          ? sum.mappings.map((m) => `${m.from.padEnd(18)} → ${m.to}`).join('\n') || '(no mappings)'
          : yaml.isError
            ? 'YAML unavailable.'
            : 'Loading…'}
      </CodeBlock>

      <p className="text-body min-h-6">
        {verify.isPending ? (
          <span className="text-text-muted">Dry-running {p.active_version} against stored samples…</span>
        ) : d ? (
          <>
            <StateWord state={meetsThreshold(d) ? 'pass' : 'fail'} />{' '}
            <span className="text-text-muted">
              - {fmtInt(d.parsed)} of {fmtInt(d.samples)} samples parsed, {fmtPct(d.mean_coverage)} coverage
              {d.warnings.length ? ` · ${d.warnings[0]}` : ''}
            </span>
          </>
        ) : verify.error ? (
          <span className="text-text-primary">{verify.error.message}</span>
        ) : (
          <span className="text-text-muted">
            Not verified in this session. Verification is a dry run: nothing is written.
          </span>
        )}
      </p>
      <div className="flex gap-2">
        <Button onClick={() => setShowVersions(!showVersions)} aria-expanded={showVersions}>
          {showVersions ? 'Hide versions' : `Versions & history (${p.versions.length})`}
        </Button>
        <Button variant="primary" onClick={() => verify.mutate()} disabled={verify.isPending}>
          Run verification
        </Button>
      </div>

      {showVersions && (
        <section aria-label="Versions" className="space-y-3 pt-2 border-t border-border">
          {versions.data?.versions.map((v) => (
            <div key={v.version} className="bg-canvas border border-border rounded-button px-4 py-3 space-y-1">
              <div className="flex items-center gap-2">
                <span className="font-mono text-code">{v.version}</span>
                {v.active && <Pill tone="primary">active</Pill>}
                <span className="flex-1" />
                {!v.active && (
                  <Button
                    onClick={() => setCompare(v.version === compare ? '' : v.version)}
                    pressed={compare === v.version}
                  >
                    Diff vs {p.active_version}
                  </Button>
                )}
                {!v.active && <Button onClick={() => setConfirm(v.version)}>Roll back</Button>}
              </div>
              {v.history.length === 0 ? (
                <p className="text-label text-text-muted">
                  {v.version === '1.0.0' ? 'Built-in version.' : 'No approval recorded by this control plane.'}
                </p>
              ) : (
                v.history.map((h) => (
                  <p key={h.id} className="text-label text-text-muted">
                    {h.action} by <span className="text-text-primary">{h.approved_by}</span> · {fmtDateTime(h.at, utc)}{' '}
                    · {h.result}
                    {h.comment && ` · “${h.comment}”`}
                  </p>
                ))
              )}
            </div>
          ))}
          {compare && other.data && yaml.data && <YamlDiff before={other.data} after={yaml.data} />}
          {confirm && (
            <div className="space-y-2 bg-canvas border border-border rounded-button px-4 py-3">
              <Label className="block">
                Roll back {p.id} to {confirm}
              </Label>
              <p className="text-body text-text-muted">
                The data plane activates {confirm} immediately. Events already normalized keep their version until
                replayed.
              </p>
              <div className="grid grid-cols-[minmax(0,1fr)_minmax(0,2fr)] gap-2">
                <Input
                  aria-label="Recorded name"
                  placeholder="Your name (recorded)"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
                <Input
                  aria-label="Comment"
                  placeholder="Why roll back?"
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                />
              </div>
              <div className="flex justify-end gap-2">
                <Button onClick={() => setConfirm('')}>Cancel</Button>
                <Button
                  variant="primary"
                  disabled={!name.trim() || rollback.isPending}
                  onClick={() => {
                    recordedName.set(name);
                    rollback.mutate(
                      { to_version: confirm, by: name.trim(), comment, replay: false },
                      { onSuccess: () => setConfirm('') },
                    );
                  }}
                >
                  Roll back to {confirm}
                </Button>
              </div>
              {rollback.error && <p className="text-body text-text-primary">{rollback.error.message}</p>}
            </div>
          )}
          {versions.data && versions.data.history.length > 0 && (
            <div>
              <Label className="block mb-1">Audit trail</Label>
              {versions.data.history.map((h) => (
                <KV
                  key={h.id}
                  k={`${fmtDateTime(h.at, utc).slice(0, 16)} ${h.action}`}
                  v={`${h.from_version || '—'} → ${h.to_version || '—'} · ${h.approved_by} · ${h.result}`}
                />
              ))}
            </div>
          )}
        </section>
      )}
    </div>
  );
}
