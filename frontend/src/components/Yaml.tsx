import { useMemo } from 'react';
import { diffLines } from '../lib/diff';
import { cx } from './ui';

/** Read-only YAML with line numbers. */
export function YamlView({ text }: { text: string }) {
  const lines = text.replace(/\n$/, '').split('\n');
  return (
    <div className="bg-canvas border border-border rounded-button overflow-auto font-mono text-code">
      <table className="border-collapse">
        <tbody>
          {lines.map((l, i) => (
            <tr key={i}>
              <td className="select-none text-right text-text-muted px-3 align-top">{i + 1}</td>
              <td className="pr-4 whitespace-pre">{l || ' '}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * A line diff. Removed and added lines are told apart by a leading -/+ and by
 * weight (added lines full white, removed lines muted and struck through):
 * the palette has no red or green for this, and DESIGN.md allows none.
 */
export function YamlDiff({ before, after }: { before: string; after: string }) {
  const d = useMemo(() => diffLines(before, after), [before, after]);
  const changed = d.filter((x) => x.kind !== 'same').length;
  return (
    <div className="space-y-2">
      <p className="text-label text-text-muted">
        {changed ? `${changed} changed ${changed === 1 ? 'line' : 'lines'}` : 'No differences.'}
      </p>
      <div className="bg-canvas border border-border rounded-button overflow-auto font-mono text-code">
        <table className="border-collapse w-full">
          <tbody>
            {d.map((l, i) => (
              <tr key={i} className={cx(l.kind === 'add' && 'bg-selected', l.kind === 'del' && 'text-text-muted')}>
                <td className="select-none text-right text-text-muted px-2 w-10 align-top">{l.a ?? ''}</td>
                <td className="select-none text-right text-text-muted px-2 w-10 align-top">{l.b ?? ''}</td>
                <td className="select-none px-2 w-4 align-top">
                  {l.kind === 'add' ? '+' : l.kind === 'del' ? '−' : ''}
                </td>
                <td className={cx('pr-4 whitespace-pre', l.kind === 'del' && 'line-through')}>{l.text || ' '}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
