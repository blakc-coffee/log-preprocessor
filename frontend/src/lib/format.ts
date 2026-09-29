// Display formatting. Times render in the viewer's zone unless UTC is chosen
// (Frontend PRD 3.8); the choice lives in lib/prefs.

const pad = (n: number, w = 2) => String(n).padStart(w, '0');

function parts(ts: string, utc: boolean) {
  const d = new Date(ts);
  return utc
    ? {
        y: d.getUTCFullYear(),
        mo: d.getUTCMonth() + 1,
        d: d.getUTCDate(),
        h: d.getUTCHours(),
        mi: d.getUTCMinutes(),
        s: d.getUTCSeconds(),
        ms: d.getUTCMilliseconds(),
      }
    : {
        y: d.getFullYear(),
        mo: d.getMonth() + 1,
        d: d.getDate(),
        h: d.getHours(),
        mi: d.getMinutes(),
        s: d.getSeconds(),
        ms: d.getMilliseconds(),
      };
}

/** 15:31:07.441, the explorer's timestamp column. */
export function fmtClock(ts: string | null, utc: boolean): string {
  if (!ts) return '—';
  const p = parts(ts, utc);
  return `${pad(p.h)}:${pad(p.mi)}:${pad(p.s)}.${pad(p.ms, 3)}`;
}

/** 2026-09-28 15:31:07 UTC (or local, with its offset). */
export function fmtDateTime(ts: string | null, utc: boolean): string {
  if (!ts) return '—';
  const p = parts(ts, utc);
  const base = `${p.y}-${pad(p.mo)}-${pad(p.d)} ${pad(p.h)}:${pad(p.mi)}:${pad(p.s)}`;
  if (utc) return `${base} UTC`;
  const off = -new Date(ts).getTimezoneOffset();
  const sign = off >= 0 ? '+' : '-';
  return `${base} ${sign}${pad(Math.floor(Math.abs(off) / 60))}:${pad(Math.abs(off) % 60)}`;
}

export function fmtInt(n: number): string {
  return Math.round(n).toLocaleString('en-US');
}

export function fmtRate(n: number): string {
  return n >= 100 ? fmtInt(n) : n.toLocaleString('en-US', { maximumFractionDigits: 1 });
}

export function fmtPct(x: number, digits = 0): string {
  return `${(x * 100).toFixed(digits)}%`;
}

export function fmtBytes(n: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i === 0 ? v : v.toFixed(1)} ${units[i]}`;
}

/** "11m", "3h 5m": the age of something relative to now. */
export function fmtAge(ts: string, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - Date.parse(ts)) / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d`;
}

export function shortHash(h: string, n = 12): string {
  return h.length > n ? `${h.slice(0, n)}…` : h;
}

// OCSF 1.1.0 enum captions for the fields the explorer shows.
const SEVERITY: Record<number, string> = {
  0: 'Unknown',
  1: 'Info',
  2: 'Low',
  3: 'Medium',
  4: 'High',
  5: 'Critical',
  6: 'Fatal',
  99: 'Other',
};
const ACTION: Record<number, string> = { 0: 'Unknown', 1: 'Allowed', 2: 'Denied', 99: 'Other' };

export const severityOptions = [1, 2, 3, 4, 5, 6].map((v) => ({ value: v, label: SEVERITY[v]! }));
export const actionOptions = [1, 2].map((v) => ({ value: v, label: ACTION[v]! }));

export function severityName(id: number | undefined): string {
  return id === undefined ? '—' : (SEVERITY[id] ?? String(id));
}

export function actionName(id: number | undefined): string {
  return id === undefined ? '—' : (ACTION[id] ?? String(id));
}

const PRODUCT: Record<string, string> = {
  'cisco/asa': 'Cisco ASA',
  'fortinet/fortigate': 'Fortinet',
  'oisf/suricata': 'Suricata',
  'palo_alto/pan-os': 'Palo Alto',
  'isc/dhcpd': 'ISC DHCP',
  'freeradius/radiusd': 'RADIUS',
};

export function productName(vendor: string, product: string): string {
  return PRODUCT[`${vendor}/${product}`] ?? `${vendorName(vendor)} ${product}`.trim();
}

const VENDOR: Record<string, string> = {
  cisco: 'Cisco',
  fortinet: 'Fortinet',
  oisf: 'OISF',
  palo_alto: 'Palo Alto',
  isc: 'ISC',
  freeradius: 'FreeRADIUS',
};

export function vendorName(v: string): string {
  return VENDOR[v] ?? titleCase(v);
}

export function titleCase(s: string): string {
  return s.replace(/[_-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}
