import { useSegments, useTelemetry, useVerifyChain } from '../api/hooks';
import { fmtDateTime, fmtInt, shortHash } from '../lib/format';
import { useUtc } from '../components/utc';
import {
  Button,
  Card,
  CodeBlock,
  Empty,
  KV,
  Label,
  PageHeader,
  Pill,
  StatCard,
  StateWord,
  Td,
  Th,
  Table,
  rowClass,
} from '../components/ui';

/** Vault & Chain (PRD screen 5, not in the Figma set): built only from the shared components. */
export default function Vault() {
  const utc = useUtc();
  const seg = useSegments();
  const tel = useTelemetry();
  const verify = useVerifyChain();
  const seals = [...(seg.data?.segments ?? [])].reverse();
  const active = seg.data?.active;
  const t = tel.data;
  const r = verify.data;

  return (
    <div className="flex-1 min-h-0 flex flex-col gap-4 py-6">
      <PageHeader title="Vault & Chain" subtitle="Every raw record, hash-chained before anything reads it." />
      <section aria-label="Vault summary" className="grid grid-cols-4 gap-4 shrink-0">
        <StatCard
          label="Sealed segments"
          value={fmtInt(seg.data?.segments.length ?? 0)}
          sub={active ? `segment ${active.segment} active` : undefined}
        />
        <StatCard
          label="Records"
          value={t ? fmtInt(t.vault.records) : '—'}
          sub={t ? `sealed through #${fmtInt(t.vault.sealed_through)}` : undefined}
        />
        <StatCard
          label="Chain head"
          value={<span className="font-mono">{t ? shortHash(t.vault.chain_head, 10) : '—'}</span>}
          title={t?.vault.chain_head}
        />
        <StatCard
          label="Last verification"
          value={!t ? '—' : t.lossless.last_verify_ok ? 'Intact' : 'FAILED'}
          tone={t?.lossless.last_verify_ok ? 'mint' : undefined}
          sub={t ? fmtDateTime(t.lossless.last_verify_at, utc) : undefined}
        />
      </section>
      <div className="flex-1 min-h-0 grid grid-cols-2 gap-4">
        <Card pad={false} className="min-h-0 overflow-y-auto">
          <Table>
            <colgroup>
              <col className="w-16" />
              <col />
              <col className="hidden xl:table-column w-20" />
              <col className="w-36" />
              <col className="w-40" />
            </colgroup>
            <thead className="sticky top-0">
              <tr>
                <Th dense>Seg</Th>
                <Th dense>Records</Th>
                <Th dense className="hidden xl:table-cell">
                  Count
                </Th>
                <Th dense>Root</Th>
                <Th dense>Sealed</Th>
              </tr>
            </thead>
            <tbody>
              {active && active.records > 0 && (
                <tr className={rowClass(0)}>
                  <Td dense className="font-mono text-code">
                    {active.segment}
                  </Td>
                  <Td dense className="font-mono text-code">
                    #{fmtInt(active.first_seq)} →
                  </Td>
                  <Td dense className="hidden xl:table-cell">
                    {fmtInt(active.records)}
                  </Td>
                  <Td dense className="text-text-muted">
                    —
                  </Td>
                  <Td dense>
                    <Pill>pending seal</Pill>
                  </Td>
                </tr>
              )}
              {seals.map((s, i) => (
                <tr key={s.segment} className={rowClass(i + (active?.records ? 1 : 0))}>
                  <Td dense className="font-mono text-code">
                    {s.segment}
                  </Td>
                  <Td dense className="font-mono text-code">
                    #{fmtInt(s.first_seq)} – #{fmtInt(s.last_seq)}
                  </Td>
                  <Td dense className="hidden xl:table-cell">
                    {fmtInt(s.count)}
                  </Td>
                  <Td dense className="font-mono text-label" title={s.root}>
                    {shortHash(s.root, 12)}
                  </Td>
                  <Td dense className="text-text-muted" title={s.recovered ? 'Sealed by crash recovery' : undefined}>
                    {fmtDateTime(s.sealed_at, utc).slice(11, 19)}
                    {s.recovered && ' · recovered'}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
          {seg.isPending && <Empty title="Loading segments…" />}
        </Card>
        <Card className="min-h-0 overflow-y-auto space-y-4">
          <CodeBlock label="Chain head" hash>
            {t?.vault.chain_head ?? '—'}
          </CodeBlock>
          <div className="flex gap-2">
            <Button onClick={() => verify.mutate(false)} disabled={verify.isPending}>
              Verify chain
            </Button>
            <Button variant="primary" onClick={() => verify.mutate(true)} disabled={verify.isPending}>
              {verify.isPending ? 'Verifying…' : 'Verify chain (deep)'}
            </Button>
          </div>
          {r && (
            <div aria-live="polite">
              <p className="text-body mb-2">
                <StateWord state={r.ok ? 'pass' : 'fail'} />{' '}
                <span className="text-text-muted">
                  {r.deep ? 'Deep: every record re-read, every root recomputed.' : 'Shallow: ledger links and footers.'}
                </span>
              </p>
              <KV k="segments" v={fmtInt(r.segments)} />
              <KV k="records" v={fmtInt(r.records)} />
              <KV k="head" v={shortHash(r.head, 24)} title={r.head} />
              {!r.ok && <KV k="first_bad_segment" v={String(r.first_bad ?? '—')} />}
              {r.reason && <KV k="reason" v={r.reason} title={r.reason} />}
            </div>
          )}
          {verify.error && <p className="text-body text-text-primary">{verify.error.message}</p>}
          <div className="space-y-2 text-body text-text-muted">
            <Label className="block">What verification can and cannot detect</Label>
            <p>
              <span className="text-text-primary">Detects:</span> a changed byte, a deleted, inserted or reordered
              record, a missing or swapped segment, and a truncated or edited ledger, as long as later ledger entries or
              an exported chain head survive.
            </p>
            <p>
              <span className="text-text-primary">Does not detect:</span> a consistent rewrite of the whole vault
              directory by someone with write access to all of it, or deletion of the newest segment together with its
              ledger line. Only a chain head copied elsewhere (vaultctl head) defeats that. Tamper-evident, not
              tamper-proof.
            </p>
          </div>
        </Card>
      </div>
    </div>
  );
}
