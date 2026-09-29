import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSamples } from '../../api/hooks';
import type { Proposal, QuarantineRecord, QuarantineSummary } from '../../api/types';
import { base64ToBytes, sha256Hex } from '../../lib/merkle';
import { ByteClass, classify } from '../../lib/hex';
import { fmtClock, fmtInt } from '../../lib/format';
import { Button, cx, KV, Label, Pill } from '../../components/ui';

/** A raw line as text, with bytes that are not printable UTF-8 shown as \xNN. */
function RawText({ bytes }: { bytes: Uint8Array }) {
  const parts = useMemo(() => {
    const cls = classify(bytes);
    const out: { text: string; escaped: boolean }[] = [];
    let i = 0;
    while (i < bytes.length) {
      const escaped = cls[i] === ByteClass.Invalid || cls[i] === ByteClass.Control;
      let j = i;
      while (j < bytes.length && (cls[j] === ByteClass.Invalid || cls[j] === ByteClass.Control) === escaped) j++;
      const seg = bytes.subarray(i, j);
      out.push({
        escaped,
        text: escaped
          ? Array.from(seg, (b) => `\\x${b.toString(16).padStart(2, '0')}`).join('')
          : new TextDecoder().decode(seg),
      });
      i = j;
    }
    return out;
  }, [bytes]);
  return (
    <pre className="font-mono text-code whitespace-pre-wrap break-all">
      {parts.map((p, i) => (
        <span key={i} className={cx(p.escaped && 'bg-text-primary text-canvas')}>
          {p.text}
        </span>
      ))}
    </pre>
  );
}

export function QuarantineDetail({
  summary: s,
  records,
  proposals,
  utc,
}: {
  summary: QuarantineSummary;
  records: QuarantineRecord[];
  proposals: Proposal[];
  utc: boolean;
}) {
  const navigate = useNavigate();
  const samples = useSamples(s.source_id, 'quarantined', 3);
  const proposal = proposals.find((p) => p.source_id === s.source_id && p.status === 'pending');
  return (
    <div className="space-y-4">
      <header className="space-y-1">
        <div className="flex items-center gap-3">
          <h2 className="text-heading font-semibold truncate">Quarantine · {s.source_id}</h2>
          <Pill>quarantined</Pill>
        </div>
        <p className="text-body text-text-muted">
          {fmtInt(s.open)} open · {fmtInt(s.resolved)} resolved · {fmtInt(s.ignored)} ignored
        </p>
      </header>
      <div>
        {Object.entries(s.by_stage).map(([stage, n]) => (
          <KV key={stage} k={`stage ${stage}`} v={fmtInt(n)} />
        ))}
      </div>
      <div>
        <Label className="block mb-2">Raw samples, as stored</Label>
        <div className="space-y-2">
          {samples.data?.samples.map((x) => {
            const b = base64ToBytes(x.raw_base64);
            return (
              <div key={x.record_id} className="bg-canvas border border-border rounded-button px-4 py-3 space-y-1">
                <p className="text-label text-text-muted font-mono">
                  #{x.record_id} · {fmtClock(x.received_at, utc)} · {b.length} B · sha256 {sha256Hex(b).slice(0, 16)}…
                </p>
                <RawText bytes={b} />
              </div>
            );
          })}
          {samples.data?.samples.length === 0 && <p className="text-body text-text-muted">No samples returned.</p>}
        </div>
        <p className="mt-2 text-label text-text-muted">
          The digest is computed here. It is verified against the vault's chain once a parser normalizes the record and
          it gains an event and lineage.
        </p>
      </div>
      <div>
        <Label className="block mb-2">Latest failures</Label>
        {records.slice(0, 8).map((r) => (
          <KV key={r.record_id} k={`#${r.record_id} ${r.failure_stage}`} v={r.error} title={r.error} />
        ))}
      </div>
      {proposal ? (
        <Button variant="primary" onClick={() => navigate(`/review/proposal/${encodeURIComponent(proposal.id)}`)}>
          Review proposal {proposal.id}
        </Button>
      ) : (
        <p className="text-body text-text-muted">
          No proposal for this source yet. Records stay quarantined, raw bytes intact, until a parser that reads them is
          approved.
        </p>
      )}
    </div>
  );
}
