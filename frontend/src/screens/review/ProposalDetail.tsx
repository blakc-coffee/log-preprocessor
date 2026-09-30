import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApprove, useDryRun, useProposal, useReject } from '../../api/hooks';
import { ApiError } from '../../api/client';
import type { DryRunResult, Proposal, RegistryRow, TypedField } from '../../api/types';
import { fmtInt, fmtPct } from '../../lib/format';
import { recordedName } from '../../lib/prefs';
import { OCSF_PATHS, setFieldPath } from '../../lib/yamlEdit';
import { Button, CodeBlock, cx, Input, KV, Label, Meter, Pill, Select, StateWord, TextArea } from '../../components/ui';
import { Tabs } from '../../components/Tabs';
import { YamlDiff, YamlView } from '../../components/Yaml';
import { ReplayProgress } from '../../components/ReplayProgress';

// Acceptance thresholds (Contracts PRD 5.6). The data plane applies no
// threshold on approve; the UI asks for an explicit "approve anyway".
export const THRESHOLDS = { match: 0.95, coverage: 0.9, renderBack: 0.95 };
const LOW_CONFIDENCE = 0.8;

export function meetsThreshold(d: DryRunResult | null | undefined): boolean {
  if (!d || d.samples === 0) return false;
  return (
    d.match_rate >= THRESHOLDS.match &&
    d.mean_coverage >= THRESHOLDS.coverage &&
    (d.render_back_ok_rate === null || d.render_back_ok_rate >= THRESHOLDS.renderBack)
  );
}

type Tab = 'fields' | 'yaml' | 'dryrun';

export function ProposalDetail({ proposal: listed, history }: { proposal: Proposal; history: RegistryRow[] }) {
  const navigate = useNavigate();
  const view = useProposal(listed.id);
  const p = view.data?.proposal ?? listed;
  const activeYaml = view.data?.active_yaml ?? '';

  const [yaml, setYaml] = useState(listed.yaml);
  const [fields, setFields] = useState<TypedField[]>(listed.typed_fields);
  const [fieldErr, setFieldErr] = useState<Record<string, string>>({});
  const [tab, setTab] = useState<Tab>('fields');
  const [yamlMode, setYamlMode] = useState<'view' | 'edit' | 'diff'>(listed.kind === 'patch' ? 'diff' : 'view');
  const [dry, setDry] = useState<DryRunResult | null>(listed.dry_run);
  const [dryFor, setDryFor] = useState(listed.yaml); // the YAML the shown dry-run belongs to
  const [name, setName] = useState(recordedName.get);
  const [comment, setComment] = useState('');
  const [confirmAnyway, setConfirmAnyway] = useState(false);
  const [rejecting, setRejecting] = useState(false);

  const dryRun = useDryRun(p.id);
  const approve = useApprove(p.id);
  const reject = useReject(p.id);

  const edited = yaml !== p.yaml;
  const dryStale = dryFor !== yaml;
  const ok = meetsThreshold(dry) && !dryStale;
  const pending = p.status === 'pending';
  const stale =
    p.status === 'stale' || (approve.error instanceof ApiError && approve.error.code === 'stale_base_version');

  // The replay job of this proposal's approval: from this session, or from
  // the registry after a reload.
  const jobId =
    approve.data?.replay_job_id ??
    history.find((h) => h.proposal_id === p.id && h.action === 'approve' && h.replay_job_id)?.replay_job_id;

  const editField = (f: TypedField, path: string) => {
    const r = setFieldPath(yaml, f, path);
    setFieldErr((e) => ({ ...e, [f.field]: r.error ?? '' }));
    if (r.error) return;
    setYaml(r.yaml);
    setFields((fs) => fs.map((x) => (x.field === f.field ? { ...x, ocsf_path: path } : x)));
  };

  const runDry = () =>
    dryRun.mutate(yaml, {
      onSuccess: (d) => {
        setDry(d);
        setDryFor(yaml);
      },
    });

  const doApprove = () => {
    recordedName.set(name);
    approve.mutate({ approved_by: name.trim(), comment, yaml: edited ? yaml : undefined });
  };

  const diffBase = p.kind === 'patch' ? activeYaml : p.yaml;
  const lowRows = useMemo(
    () => fields.filter((f) => f.confidence < LOW_CONFIDENCE || f.ocsf_path === '').length,
    [fields],
  );

  return (
    <div className="space-y-4">
      <header className="space-y-1">
        <div className="flex items-center gap-3">
          <h2 className="text-heading font-semibold truncate">
            {p.kind === 'new' ? 'New parser' : 'Parser patch'} · {p.parser_id}
          </h2>
          <Pill tone={p.status === 'approved' ? 'verified' : 'muted'}>{p.status}</Pill>
        </div>
        <p className="text-body text-text-muted">
          Source {p.source_id} · {p.kind === 'patch' ? `patches ${p.base_version}` : 'no parser today'} ·{' '}
          {fmtInt(p.cluster_size)} quarantined records · {p.id}
        </p>
      </header>

      {p.templates.length > 0 && <CodeBlock label="Motivating templates">{p.templates.join('\n')}</CodeBlock>}

      <Tabs<Tab>
        label="Proposal"
        value={tab}
        onChange={setTab}
        tabs={[
          { value: 'fields', label: `Typed fields${lowRows ? ` · ${lowRows} to check` : ''}` },
          { value: 'yaml', label: edited ? 'Parser YAML · edited' : 'Parser YAML' },
          { value: 'dryrun', label: 'Dry run' },
        ]}
      />

      {tab === 'fields' && (
        <div className="overflow-x-auto">
          <table className="w-full table-fixed border-collapse text-body">
            <colgroup>
              <col className="w-20" />
              <col className="w-48" />
              <col className="hidden xl:table-column w-20" />
              <col className="w-24" />
              <col />
            </colgroup>
            <thead>
              <tr>
                {['Field', 'OCSF path', 'Type', 'Confidence', 'Evidence'].map((h) => (
                  <th
                    key={h}
                    className={cx(
                      h === 'Type' && 'hidden xl:table-cell',
                      'bg-canvas h-10 px-3 text-left text-label font-medium uppercase tracking-label text-text-muted border-b border-border',
                    )}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {fields.map((f) => {
                const check = f.confidence < LOW_CONFIDENCE || f.ocsf_path === '';
                const options = Array.from(
                  new Set([f.ocsf_path, ...(f.alternatives ?? []), ...OCSF_PATHS].filter((x) => x !== '')),
                );
                return (
                  <tr key={f.field} className={cx('border-b border-border align-top', check && 'bg-selected')}>
                    <td className="py-2 px-3 font-mono text-code truncate" title={`${f.field} (${f.type})`}>
                      {f.field}
                    </td>
                    <td className="py-2 px-3">
                      {check && pending ? (
                        <>
                          <Select
                            aria-label={`OCSF path for ${f.field}`}
                            value={f.ocsf_path}
                            onChange={(e) => editField(f, e.target.value)}
                            className="w-full"
                          >
                            <option value="">(unmapped)</option>
                            {options.map((o) => (
                              <option key={o} value={o}>
                                {o}
                              </option>
                            ))}
                          </Select>
                          {fieldErr[f.field] && (
                            <p className="mt-1 text-label text-text-primary">{fieldErr[f.field]}</p>
                          )}
                        </>
                      ) : (
                        <span className="font-mono text-code truncate block" title={f.ocsf_path}>
                          {f.ocsf_path || '(unmapped)'}
                        </span>
                      )}
                    </td>
                    <td className="hidden xl:table-cell py-2 pr-3 truncate">{f.type}</td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <Meter value={f.confidence} label={`Confidence for ${f.field}`} size="sm" className="mr-2" />
                      {fmtPct(f.confidence)}
                      {check && <span className="block text-label text-text-primary">check</span>}
                    </td>
                    <td className="py-2 px-3 text-text-muted">
                      <span className="line-clamp-2" title={f.evidence}>
                        {f.evidence}
                      </span>
                      {f.alternatives && f.alternatives.length > 0 && (
                        <span className="block text-label">or {f.alternatives.join(', ')}</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <p className="mt-2 text-label text-text-muted">
            Rows below 80% confidence or left unmapped are marked for review. Changing a path rewrites that line of the
            YAML; run the dry run again before approving.
          </p>
        </div>
      )}

      {tab === 'yaml' && (
        <div className="space-y-2">
          <div className="flex gap-2">
            <Button onClick={() => setYamlMode('view')} pressed={yamlMode === 'view'}>
              View
            </Button>
            {pending && (
              <Button onClick={() => setYamlMode('edit')} pressed={yamlMode === 'edit'}>
                Edit
              </Button>
            )}
            <Button
              onClick={() => setYamlMode('diff')}
              pressed={yamlMode === 'diff'}
              disabled={p.kind === 'patch' && !activeYaml}
            >
              {p.kind === 'patch' ? `Diff vs ${p.base_version}` : 'Diff vs proposed'}
            </Button>
            {edited && (
              <Button onClick={() => setYaml(p.yaml)} className="ml-auto">
                Discard edits
              </Button>
            )}
          </div>
          {yamlMode === 'edit' ? (
            <TextArea
              aria-label="Parser YAML"
              value={yaml}
              onChange={(e) => setYaml(e.target.value)}
              spellCheck={false}
              rows={18}
              className="w-full whitespace-pre"
            />
          ) : yamlMode === 'diff' ? (
            <YamlDiff before={diffBase} after={yaml} />
          ) : (
            <YamlView text={yaml} />
          )}
        </div>
      )}

      {tab === 'dryrun' && (
        <DryRunPanel d={dry} stale={dryStale} running={dryRun.isPending} error={dryRun.error} onRun={runDry} />
      )}

      {tab !== 'dryrun' && (
        <p className="text-body">
          <StateWord state={dryStale ? 'pending' : ok ? 'pass' : 'fail'} />{' '}
          <span className="text-text-muted">
            {dryStale
              ? 'The YAML changed since the last dry run.'
              : dry
                ? `dry run: ${fmtPct(dry.match_rate)} match, ${fmtPct(dry.mean_coverage)} coverage on ${fmtInt(dry.samples)} samples`
                : 'No dry run yet.'}
          </span>
        </p>
      )}

      {stale && (
        <CodeBlock label="Base version changed">
          The {p.parser_id} parser changed since this proposal was generated. Approving it would overwrite that change,
          so the data plane refused. Regenerate the proposal from the current version.
        </CodeBlock>
      )}

      {jobId && (
        <ReplayProgress
          jobId={jobId}
          total={p.cluster_size}
          onViewEvents={() => navigate(`/?q=${encodeURIComponent(`source:${p.source_id}`)}`)}
        />
      )}

      {pending && !stale && (
        <div className="sticky -bottom-6 -mx-6 px-card py-4 bg-card border-t border-border space-y-3">
          <div className="grid grid-cols-[minmax(0,1fr)_minmax(0,2fr)] gap-2">
            <Input
              aria-label="Recorded name"
              placeholder="Your name (recorded)"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <Input
              aria-label="Comment"
              placeholder="Comment for the audit trail"
              value={comment}
              onChange={(e) => setComment(e.target.value)}
            />
          </div>
          {rejecting ? (
            <div className="flex items-center gap-2">
              <span className="text-body text-text-muted flex-1">
                Reject this proposal{comment ? '' : ' (a comment helps whoever regenerates it)'}?
              </span>
              <Button onClick={() => setRejecting(false)}>Cancel</Button>
              <Button
                variant="primary"
                disabled={!name.trim() || reject.isPending}
                onClick={() => {
                  recordedName.set(name);
                  reject.mutate({ by: name.trim(), comment });
                }}
              >
                Reject proposal
              </Button>
            </div>
          ) : confirmAnyway ? (
            <div className="flex items-center gap-2">
              <span className="text-body text-text-primary flex-1">
                {dryStale ? 'The edited YAML has not been dry-run.' : 'The dry run is below the acceptance thresholds.'}{' '}
                Approve anyway?
              </span>
              <Button onClick={() => setConfirmAnyway(false)}>Cancel</Button>
              <Button variant="primary" onClick={doApprove} disabled={approve.isPending}>
                Approve anyway
              </Button>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <span className="text-label text-text-muted flex-1">
                {name.trim()
                  ? 'Recorded, not verified: there is no login in v1.'
                  : 'Enter a name to approve or reject.'}
              </span>
              <Button onClick={() => setRejecting(true)} disabled={!name.trim()}>
                Reject
              </Button>
              <Button
                variant="primary"
                disabled={!name.trim() || approve.isPending}
                onClick={() => (ok ? doApprove() : setConfirmAnyway(true))}
              >
                {approve.isPending ? 'Approving…' : 'Approve & Replay from Vault'}
              </Button>
            </div>
          )}
          {(approve.error || reject.error) && !stale && (
            <p className="text-body text-text-primary">{((approve.error ?? reject.error) as Error).message}</p>
          )}
        </div>
      )}
    </div>
  );
}

function DryRunPanel({
  d,
  stale,
  running,
  error,
  onRun,
}: {
  d: DryRunResult | null;
  stale: boolean;
  running: boolean;
  error: Error | null;
  onRun: () => void;
}) {
  const row = (k: string, v: number | null, min?: number) => (
    <KV
      k={k}
      v={
        <>
          {v === null ? 'n/a' : fmtPct(v, 1)}{' '}
          {min !== undefined && v !== null && <StateWord state={v >= min ? 'pass' : 'fail'} />}
        </>
      }
    />
  );
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <span className="text-body text-text-muted">
          {stale
            ? 'Results are for an earlier version of the YAML.'
            : 'Parsed against stored samples. Nothing is written.'}
        </span>
        <Button onClick={onRun} disabled={running}>
          {running ? 'Running…' : 'Re-run dry run'}
        </Button>
      </div>
      {error && <p className="text-body text-text-primary">{error.message}</p>}
      {!d ? (
        <p className="text-body text-text-muted">No dry run yet.</p>
      ) : (
        <>
          <div>
            <KV k="samples" v={`${fmtInt(d.parsed)} parsed / ${fmtInt(d.failed)} failed of ${fmtInt(d.samples)}`} />
            {row(`match_rate (≥ ${fmtPct(THRESHOLDS.match)})`, d.match_rate, THRESHOLDS.match)}
            {row(`mean_coverage (≥ ${fmtPct(THRESHOLDS.coverage)})`, d.mean_coverage, THRESHOLDS.coverage)}
            {row(
              `render_back_ok_rate (≥ ${fmtPct(THRESHOLDS.renderBack)})`,
              d.render_back_ok_rate,
              THRESHOLDS.renderBack,
            )}
          </div>
          {Object.keys(d.field_stats).length > 0 && (
            <div>
              <Label className="block mb-1">Field values seen</Label>
              {Object.entries(d.field_stats).map(([k, s]) => (
                <KV key={k} k={k} v={`${s.distinct} distinct · ${s.sample.join(', ')}`} title={s.sample.join(', ')} />
              ))}
            </div>
          )}
          {d.warnings.length > 0 && (
            <div>
              <Label className="block mb-1">Warnings</Label>
              <ul className="text-body text-text-primary list-disc pl-5 space-y-0.5">
                {d.warnings.map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            </div>
          )}
          {d.failures.length > 0 && (
            <div>
              <Label className="block mb-1">Failures</Label>
              {d.failures.map((f) => (
                <KV key={f.record_id} k={`#${f.record_id}`} v={f.error} title={f.error} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
