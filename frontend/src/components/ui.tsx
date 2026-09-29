// Primitives built exactly to DESIGN.md's component specifications. Screens
// compose these; they do not restyle them.
import {
  forwardRef,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
} from 'react';

export function cx(...c: (string | false | null | undefined)[]): string {
  return c.filter(Boolean).join(' ');
}

/** Card: #050607, 16px radius, 1px #333 border, 24px padding, no shadow. */
export function Card({
  children,
  className,
  pad = true,
  as: As = 'section',
  ...rest
}: { children: ReactNode; className?: string; pad?: boolean; as?: 'section' | 'div' | 'aside' } & Record<
  string,
  unknown
>) {
  return (
    <As className={cx('bg-card rounded-card border border-border', pad && 'p-card', className)} {...rest}>
      {children}
    </As>
  );
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary'; pressed?: boolean };

/**
 * Primary: white fill, black text, no border, 6px radius, 12px 24px, 14/700,
 * opacity 0.9 on hover. Secondary: card fill, muted text, 1px #333 border.
 */
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', pressed, className, ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type="button"
      aria-pressed={pressed}
      className={cx(
        'rounded-button whitespace-nowrap disabled:opacity-40',
        variant === 'primary'
          ? 'bg-text-primary text-canvas px-6 py-3 text-ui font-bold hover:opacity-90 disabled:hover:opacity-40'
          : cx(
              'bg-card border border-border px-4 py-2 text-body hover:text-text-primary disabled:hover:text-text-muted',
              pressed ? 'text-text-primary' : 'text-text-muted',
            ),
        className,
      )}
      {...rest}
    />
  );
});

/** Pill badge: never a coloured border; mint text only for verified states. */
export function Pill({
  children,
  tone = 'muted',
  className,
  title,
}: {
  children: ReactNode;
  tone?: 'muted' | 'verified' | 'primary';
  className?: string;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={cx(
        'inline-flex items-center gap-1.5 bg-card border border-border rounded-pill px-2.5 py-0.5 text-label font-medium uppercase tracking-label whitespace-nowrap',
        tone === 'verified' ? 'text-mint' : tone === 'primary' ? 'text-text-primary' : 'text-text-muted',
        className,
      )}
    >
      {children}
    </span>
  );
}

/** The live status dot. DESIGN.md allows one per screen: the masthead owns it. */
export function LiveDot({ className }: { className?: string }) {
  return (
    <span
      aria-hidden
      className={cx('inline-block size-2 shrink-0 rounded-pill bg-mint motion-safe:animate-pulse', className)}
    />
  );
}

export function Label({
  children,
  className,
  as: As = 'span',
  htmlFor,
}: {
  children: ReactNode;
  className?: string;
  as?: 'span' | 'label' | 'h3' | 'dt';
  htmlFor?: string;
}) {
  return (
    <As htmlFor={htmlFor} className={cx('text-label font-medium uppercase tracking-label text-text-muted', className)}>
      {children}
    </As>
  );
}

const field = 'bg-card border border-border rounded-button text-text-primary placeholder:text-text-muted';
// Field sizes. Pick one; never combine with another text-* or p* class.
const fieldSize = { md: 'text-body px-3 py-2' } as const;

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement> & { mono?: boolean }>(
  function Input({ className, mono, ...rest }, ref) {
    return <input ref={ref} className={cx(field, fieldSize.md, mono && 'font-mono', 'min-w-0', className)} {...rest} />;
  },
);

export function Select({
  className,
  children,
  compact,
  ...rest
}: SelectHTMLAttributes<HTMLSelectElement> & { compact?: boolean }) {
  return (
    <select
      className={cx(
        field,
        compact ? 'font-mono text-code pl-2 py-1' : 'text-body pl-3 py-2',
        'pr-8 appearance-none bg-no-repeat',
        className,
      )}
      style={{ backgroundImage: CHEVRON, backgroundPosition: 'right 10px center' }}
      {...rest}
    >
      {children}
    </select>
  );
}

// A muted chevron for native selects (inline SVG data URL: allowed by the CSP's img-src data:).
const CHEVRON = `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M1 1l4 4 4-4' fill='none' stroke='%23b3b3b3' stroke-width='1.5'/%3E%3C/svg%3E")`;

export function TextArea({ className, ...rest }: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={cx(field, 'font-mono text-code px-3 py-2', className)} {...rest} />;
}

/** Page section header: 34px Cormorant Garamond 300 over a muted line. */
export function PageHeader({ title, subtitle, children }: { title: string; subtitle: string; children?: ReactNode }) {
  return (
    <header className="h-section shrink-0 flex items-end justify-between gap-4">
      <div className="min-w-0">
        <h1 className="font-display font-light text-section tracking-normal truncate">{title}</h1>
        <p className="text-body text-text-muted truncate">{subtitle}</p>
      </div>
      {children}
    </header>
  );
}

/** Stat card: one of four in the 88px telemetry strip. */
export function StatCard({
  label,
  value,
  tone,
  sub,
  children,
  onClick,
  title,
}: {
  label: string;
  value: ReactNode;
  tone?: 'mint';
  sub?: ReactNode;
  children?: ReactNode;
  onClick?: () => void;
  title?: string;
}) {
  const body = (
    <>
      <div className="min-w-0 flex-1">
        <Label className="block truncate">{label}</Label>
        <div className="flex items-baseline gap-2 min-w-0">
          <span
            className={cx(
              'text-metric font-semibold whitespace-nowrap',
              tone === 'mint' ? 'text-mint' : 'text-text-primary',
            )}
          >
            {value}
          </span>
          {sub && <span className="text-label text-text-muted truncate">{sub}</span>}
        </div>
      </div>
      {children}
    </>
  );
  const cls =
    'h-telemetry min-w-0 bg-card rounded-card border border-border px-card py-card flex items-center gap-3 text-left';
  return onClick ? (
    <button type="button" className={cx(cls, 'hover:bg-hover')} onClick={onClick} title={title}>
      {body}
    </button>
  ) : (
    <div className={cls} title={title}>
      {body}
    </div>
  );
}

/** Eight lavender bars, 24px tall, 0.7 opacity (DESIGN.md "Sparkline Bar"). Each bar averages a slice of the samples. */
export function Sparkline({ samples, label }: { samples: number[]; label: string }) {
  const bars = 8;
  const per = Math.max(1, Math.ceil(samples.length / bars));
  const values = Array.from({ length: bars }, (_, i) => {
    const slice = samples.slice(Math.max(0, samples.length - (bars - i) * per), samples.length - (bars - i - 1) * per);
    return slice.length ? slice.reduce((a, b) => a + b, 0) / slice.length : 0;
  });
  const max = Math.max(...values, 1);
  return (
    <div role="img" aria-label={label} className="h-6 flex items-end gap-0.5 shrink-0">
      {values.map((v, i) => (
        <span
          key={i}
          className="w-1.5 rounded-bar bg-lavender opacity-70"
          style={{ height: `${Math.max(8, (v / max) * 100)}%` }}
        />
      ))}
    </div>
  );
}

/** Confidence or rate as a lavender fill in a hairline track. */
export function Meter({
  value,
  label,
  size = 'md',
  className,
}: {
  value: number;
  label: string;
  size?: 'sm' | 'md';
  className?: string;
}) {
  const v = Math.min(1, Math.max(0, value));
  return (
    <span
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={1}
      aria-valuenow={v}
      className={cx(
        'inline-block h-1.5 shrink-0 rounded-bar border border-border bg-canvas overflow-hidden align-middle',
        size === 'sm' ? 'w-10' : 'w-16',
        className,
      )}
    >
      <span className="block h-full bg-lavender opacity-70" style={{ width: `${v * 100}%` }} />
    </span>
  );
}

export function Table({ children, className }: { children: ReactNode; className?: string }) {
  return <table className={cx('w-full table-fixed border-collapse', className)}>{children}</table>;
}

/** Header cell: #000 fill, 11/500 uppercase, 0.08em, muted. */
export function Th({
  children,
  className,
  title,
  dense,
}: {
  children?: ReactNode;
  className?: string;
  title?: string;
  dense?: boolean;
}) {
  return (
    <th
      scope="col"
      title={title}
      className={cx(
        'bg-canvas text-left text-label font-medium uppercase tracking-label text-text-muted h-12 border-b border-border truncate',
        dense ? 'px-4' : 'px-card',
        className,
      )}
    >
      {children}
    </th>
  );
}

/** Props that make a clickable table row reachable and operable from the keyboard. */
export function rowActivate(onActivate: () => void) {
  return {
    tabIndex: 0,
    onClick: onActivate,
    onKeyDown: (e: React.KeyboardEvent) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        onActivate();
      }
    },
  };
}

/** Row striping per DESIGN.md: even #050607, odd #000; 48px; hover 3% white. */
export function rowClass(index: number, selected = false): string {
  return cx(
    'h-row border-b border-border text-body',
    selected ? 'bg-selected' : index % 2 === 0 ? 'bg-card' : 'bg-canvas',
    'hover:bg-hover cursor-pointer',
  );
}

/** `dense` (16px padding) is for tables in half-width cards. */
export function Td({
  children,
  className,
  title,
  dense,
}: {
  children?: ReactNode;
  className?: string;
  title?: string;
  dense?: boolean;
}) {
  return (
    <td title={title} className={cx('truncate', dense ? 'px-4' : 'px-card', className)}>
      {children}
    </td>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-1 py-12 px-card text-center">
      <p className="text-body text-text-primary">{title}</p>
      {children && <p className="text-body text-text-muted max-w-md">{children}</p>}
    </div>
  );
}

/** Mono key/value row, as in the Figma detail panels. */
export function KV({ k, v, title }: { k: string; v: ReactNode; title?: string }) {
  return (
    <div className="flex items-center justify-between gap-4 py-2 border-b border-border font-mono text-code min-w-0">
      <span className="text-text-muted truncate">{k}</span>
      <span className="text-text-primary truncate text-right" title={title}>
        {v}
      </span>
    </div>
  );
}

/** A mono block on the canvas colour, inside a card: raw text, YAML, signatures. */
export function CodeBlock({ children, className, label }: { children: ReactNode; className?: string; label?: string }) {
  return (
    <div className={cx('bg-canvas border border-border rounded-button px-4 py-3 min-w-0', className)}>
      {label && <Label className="block mb-1">{label}</Label>}
      <pre className="font-mono text-code text-text-primary whitespace-pre-wrap break-all">{children}</pre>
    </div>
  );
}

/** Verification states: mint only for a pass; a fail is white and says so in words. */
export function StateWord({ state }: { state: 'pass' | 'fail' | 'pending' | 'na' }) {
  const text = { pass: 'PASSED', fail: 'FAILED', pending: 'PENDING', na: 'N/A' }[state];
  return (
    <span
      className={cx(
        'text-label font-semibold tracking-label',
        state === 'pass'
          ? 'text-mint'
          : state === 'fail'
            ? 'text-text-primary underline decoration-dotted'
            : 'text-text-muted',
      )}
    >
      {text}
    </span>
  );
}
