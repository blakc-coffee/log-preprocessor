import { useEffect, useRef, useState } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { useHealth } from '../api/hooks';
import { utcPref } from '../lib/prefs';
import { cx, LiveDot } from './ui';
import { UtcContext } from './utc';

const TABS = [
  { to: '/', label: 'Lineage Explorer', end: true },
  { to: '/review', label: 'Review Queue' },
  { to: '/parsers', label: 'Parser Registry' },
  { to: '/identity', label: 'Identity' },
  { to: '/vault', label: 'Vault' },
];

/**
 * Masthead (56px, card fill, #333 hairline) with the brand, centred tabs and
 * the status pill, then the routed screen. The active tab is marked by a 2px
 * white bar under its label, as in the Figma artboards: an indicator element,
 * not a coloured border.
 */
export function Layout() {
  const health = useHealth();
  const [utc, setUtc] = useState(utcPref.get);
  const adminDown = health.isError || (health.data && health.data.admin !== 'reachable');

  return (
    <UtcContext.Provider value={utc}>
      <div className="h-full flex flex-col min-w-0">
        <header className="h-topbar shrink-0 bg-card border-b border-border px-page grid grid-cols-[1fr_auto_1fr] items-center gap-4">
          <span className="text-ui font-bold tracking-ui whitespace-nowrap">ULPF // NTRO</span>
          <nav aria-label="Screens" className="flex items-stretch h-full gap-1 xl:gap-4">
            {TABS.map((t) => (
              <NavLink
                key={t.to}
                to={t.to}
                end={t.end}
                className={({ isActive }) =>
                  cx(
                    'relative flex items-center px-2 text-ui whitespace-nowrap',
                    isActive ? 'text-text-primary' : 'text-text-muted hover:text-text-primary',
                  )
                }
              >
                {({ isActive }) => (
                  <>
                    {t.label}
                    {isActive && (
                      <span aria-hidden className="absolute left-2 right-2 bottom-3 h-0.5 bg-text-primary" />
                    )}
                  </>
                )}
              </NavLink>
            ))}
          </nav>
          <div className="flex justify-end items-center gap-2 min-w-0">
            <button
              type="button"
              onClick={() => {
                setUtc(!utc);
                utcPref.set(!utc);
              }}
              title="Show times in UTC or in this browser's time zone"
              className="text-label font-medium tracking-label text-text-muted hover:text-text-primary px-2 py-1 whitespace-nowrap"
            >
              {utc ? 'UTC' : 'LOCAL TIME'}
            </button>
            <StatusPill down={!!adminDown} checking={health.isPending} />
          </div>
        </header>
        {adminDown && (
          <div
            role="alert"
            className="shrink-0 bg-card border-b border-border px-page py-2 text-body text-text-primary"
          >
            The data plane admin API is not answering. Showing the last data received; this page retries every few
            seconds.
          </div>
        )}
        <main className="flex-1 min-h-0 flex flex-col px-page">
          <Outlet />
        </main>
      </div>
    </UtcContext.Provider>
  );
}

function StatusPill({ down, checking }: { down: boolean; checking: boolean }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', close);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('keydown', close);
    };
  }, [open]);

  return (
    <div ref={ref} className="relative min-w-0">
      <button
        type="button"
        aria-expanded={open}
        aria-label={`${down ? 'Admin API unreachable' : 'Connected'}. About this console`}
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 bg-card border border-border rounded-pill px-3 py-1.5 text-body text-text-muted hover:text-text-primary min-w-0"
      >
        {!down && !checking && <LiveDot />}
        <span className="uppercase truncate">
          {down ? 'Admin unreachable' : 'Air-gapped'}
          <span className="hidden xl:inline"> · {window.location.host}</span>
        </span>
      </button>
      {open && <About />}
    </div>
  );
}

function About() {
  return (
    <div
      role="dialog"
      aria-label="About this console"
      className="absolute right-0 top-full mt-2 z-50 w-96 bg-card border border-border rounded-card p-card text-body text-text-muted space-y-3"
    >
      <p className="text-text-primary font-semibold">About this console</p>
      <p>
        <span className="text-text-primary">No authentication (v1).</span> Anyone who can reach this address can approve
        parsers. Keep the control plane bound to loopback, as the default configuration does.
      </p>
      <p>
        <span className="text-text-primary">Approver names are recorded, not verified.</span> The name you enter is
        stored with each approval for the audit trail.
      </p>
      <p>
        <span className="text-text-primary">Nothing external is loaded.</span> Fonts and scripts are bundled; the
        Content-Security-Policy allows this origin only. "Air-gapped" describes this UI; the deployment's isolation is
        proven by the air-gap self-test.
      </p>
      <p>
        <span className="text-text-primary">Verification runs in your browser.</span> Hashes and Merkle proofs are
        recomputed from the raw bytes, not taken from the server.
      </p>
    </div>
  );
}
