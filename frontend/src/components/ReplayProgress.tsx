import { useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useReplay } from '../api/hooks';
import { fmtInt } from '../lib/format';
import { Button, CodeBlock, Label, StateWord } from './ui';

/** Replay job progress, polled once a second until it finishes. */
export function ReplayProgress({
  jobId,
  total,
  onViewEvents,
}: {
  jobId: string;
  total: number;
  onViewEvents?: () => void;
}) {
  const job = useReplay(jobId);
  const qc = useQueryClient();
  // When this card first saw the job, for the rate; later times come from the
  // query's own update stamps, so rendering stays pure.
  const [seenAt] = useState(() => Date.now());
  const j = job.data;
  const done = j?.state === 'done' || j?.state === 'failed';

  // Quarantine and events change while the job runs: refresh them as it goes.
  useEffect(() => {
    if (!j) return;
    void qc.invalidateQueries({ queryKey: ['quarantine'] });
    void qc.invalidateQueries({ queryKey: ['telemetry'] });
    if (done) void qc.invalidateQueries({ queryKey: ['events'] });
  }, [j, done, qc]);

  if (!j)
    return <CodeBlock label={`Replay ${jobId}`}>{job.isError ? 'Replay status unavailable.' : 'Starting…'}</CodeBlock>;
  const of = Math.max(total, j.processed, 1);
  const frac = done ? 1 : j.processed / of;
  const rate = j.processed / Math.max(1, (job.dataUpdatedAt - seenAt) / 1000);
  const eta = !done && rate > 0 ? Math.ceil((of - j.processed) / rate) : 0;

  return (
    <div className="bg-canvas border border-border rounded-button px-4 py-3 space-y-2" aria-live="polite">
      <div className="flex items-center justify-between gap-2">
        <Label>Replay from vault · {j.job_id}</Label>
        <StateWord
          state={
            j.state === 'done' && j.failed === 0
              ? 'pass'
              : j.state === 'failed' || (done && j.failed > 0)
                ? 'fail'
                : 'pending'
          }
        />
      </div>
      <div
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(frac * 100)}
        className="h-1.5 rounded-bar border border-border bg-card overflow-hidden"
      >
        <span className="block h-full bg-lavender opacity-70" style={{ width: `${frac * 100}%` }} />
      </div>
      <p className="text-body text-text-muted">
        {fmtInt(j.processed)} processed · <span className="text-text-primary">{fmtInt(j.succeeded)} recovered</span> ·{' '}
        {fmtInt(j.failed)} failed
        {!done && eta > 0 && ` · about ${eta}s left`}
        {j.error && ` · ${j.error}`}
      </p>
      {done && j.succeeded > 0 && onViewEvents && (
        <Button onClick={onViewEvents}>View {fmtInt(j.succeeded)} recovered events</Button>
      )}
    </div>
  );
}
