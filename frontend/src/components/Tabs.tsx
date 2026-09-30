import { cx } from './ui';

/** Segmented tabs inside a panel, styled as the masthead tabs: white label and a 2px bar when active. */
export function Tabs<T extends string>({
  value,
  onChange,
  tabs,
  label,
}: {
  value: T;
  onChange: (v: T) => void;
  tabs: { value: T; label: string }[];
  label: string;
}) {
  return (
    <div role="tablist" aria-label={label} className="flex gap-4 border-b border-border">
      {tabs.map((t) => (
        <button
          key={t.value}
          role="tab"
          type="button"
          aria-selected={value === t.value}
          onClick={() => onChange(t.value)}
          className={cx(
            'relative pb-2 text-ui font-bold',
            value === t.value ? 'text-text-primary' : 'text-text-muted hover:text-text-primary',
          )}
        >
          {t.label}
          {value === t.value && <span aria-hidden className="absolute inset-x-0 -bottom-px h-0.5 bg-text-primary" />}
        </button>
      ))}
    </div>
  );
}
