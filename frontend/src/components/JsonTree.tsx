// A collapsible JSON view. Values are React text nodes only: log content is
// never interpreted as markup.
function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null;
}

function Leaf({ v }: { v: unknown }) {
  if (v === null) return <span className="text-text-muted">null</span>;
  if (typeof v === 'string') return <span className="break-all">"{v}"</span>;
  return <span>{String(v)}</span>;
}

export function JsonTree({ value, depth = 0 }: { value: unknown; depth?: number }) {
  if (!isObj(value)) return <Leaf v={value} />;
  const entries = Array.isArray(value) ? value.map((v, i) => [String(i), v] as const) : Object.entries(value);
  if (entries.length === 0)
    return <span className="text-text-muted font-mono text-code">{Array.isArray(value) ? '[]' : '{}'}</span>;
  return (
    <ul className="font-mono text-code space-y-0.5">
      {entries.map(([k, v]) => (
        <li key={k} className="min-w-0">
          {isObj(v) ? (
            <details open={depth < 1}>
              <summary className="cursor-pointer text-text-muted hover:text-text-primary select-none">
                {k}{' '}
                <span className="text-text-muted">
                  {Array.isArray(v) ? `[${v.length}]` : `{${Object.keys(v).length}}`}
                </span>
              </summary>
              <div className="pl-4 border-l border-border ml-1 mt-0.5">
                <JsonTree value={v} depth={depth + 1} />
              </div>
            </details>
          ) : (
            <div className="flex gap-2 min-w-0">
              <span className="text-text-muted shrink-0">{k}</span>
              <span className="min-w-0">
                <Leaf v={v} />
              </span>
            </div>
          )}
        </li>
      ))}
    </ul>
  );
}
