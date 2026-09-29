import { useNavigate } from 'react-router-dom';
import type { DriftAlert, Proposal } from '../../api/types';
import { fmtDateTime, fmtPct } from '../../lib/format';
import { Button, KV, Label, Meter, Pill } from '../../components/ui';

export function DriftDetail({ alert: a, proposals, utc }: { alert: DriftAlert; proposals: Proposal[]; utc: boolean }) {
  const navigate = useNavigate();
  const linked = proposals.filter((p) => p.drift_alert_id === a.id);
  return (
    <div className="space-y-4">
      <header className="space-y-1">
        <div className="flex items-center gap-3">
          <h2 className="text-heading font-semibold truncate">Format drift · {a.source_id}</h2>
          <Pill tone={a.status === 'resolved' ? 'verified' : 'primary'}>{a.status}</Pill>
        </div>
        <p className="text-body text-text-muted">
          Parser {a.parser_id} · first seen {fmtDateTime(a.first_seen, utc)} · {a.id}
        </p>
      </header>
      <div>
        <KV
          k="drift_score"
          v={
            <>
              <Meter value={a.score} label="Drift score" className="mr-2" />
              {a.score.toFixed(2)}
            </>
          }
        />
        <KV k="quarantine_rate" v={fmtPct(a.quarantine_rate)} />
      </div>
      <div>
        <Label className="block mb-2">Signals</Label>
        <ul className="font-mono text-code space-y-1">
          {a.signals.map((s) => (
            <li key={s} className="bg-canvas border border-border rounded-button px-3 py-2 break-words">
              {s}
            </li>
          ))}
        </ul>
      </div>
      <p className="text-body text-text-muted">
        The quarantined records are safe in the vault. They are re-normalized from their original bytes when a parser
        for the new layout is approved.
      </p>
      {linked.map((p) => (
        <Button
          key={p.id}
          variant={p.status === 'pending' ? 'primary' : 'secondary'}
          onClick={() => navigate(`/review/proposal/${encodeURIComponent(p.id)}`)}
        >
          Open {p.kind === 'patch' ? 'patch' : 'proposal'} {p.id} ({p.status})
        </Button>
      ))}
      {linked.length === 0 && (
        <p className="text-body text-text-muted">
          No proposal yet: the intelligence sidecar posts one when enough quarantined records share a template.
        </p>
      )}
    </div>
  );
}
