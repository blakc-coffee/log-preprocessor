// Build output checks (Frontend PRD 5): no external URLs, and the bundle
// budget (initial JS <= 300 KB gzipped, all static assets <= 2 MB).
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';

const dist = 'dist';
const all = [];
(function walk(d) {
  for (const f of readdirSync(d)) {
    const p = join(d, f);
    if (statSync(p).isDirectory()) walk(p);
    else all.push(p);
  }
})(dist);

let fail = 0;
// Inert strings a dependency ships: React's and React Router's warning text
// links to their docs, Tailwind's licence banner names its site, SVG uses
// the w3.org namespace. None is ever requested (and the CSP would block it).
const INERT = [
  /^http:\/\/localhost/,
  /^http:\/\/127\.0\.0\.1/,
  /^https?:\/\/www\.w3\.org\//,
  /^https:\/\/react\.dev\//,
  /^https:\/\/reactjs\.org\//,
  /^https:\/\/reactrouter\.com\//,
  /^https:\/\/tailwindcss\.com\/?$/,
];
// A URL in a loading position fails whatever its host.
const LOADING =
  /(?:src=|href=|url\(|fetch\(|import\(|new URL\(|XMLHttpRequest|WebSocket\(|EventSource\()\s*["'`]?https?:\/\//;
for (const f of all.filter((p) => /\.(js|css|html)$/.test(p))) {
  const text = readFileSync(f, 'utf8');
  if (LOADING.test(text)) {
    console.error(`${f}: loads a resource from an absolute URL`);
    fail++;
  }
  for (const m of text.matchAll(/https?:\/\/[^\s"'`)<>\\]+/g)) {
    if (!INERT.some((re) => re.test(m[0]))) {
      console.error(`external URL in ${f}: ${m[0]}`);
      fail++;
    }
  }
}

// Initial JS = the entry script(s) index.html loads directly plus their static imports.
const html = readFileSync(join(dist, 'index.html'), 'utf8');
const entry = [...html.matchAll(/(?:src|href)="\/(assets\/[^"]+\.js)"/g)].map((m) => m[1]);
const initial = new Set(entry);
for (const e of entry) {
  for (const m of readFileSync(join(dist, e), 'utf8').matchAll(/from"\.\/([^"]+\.js)"|import"\.\/([^"]+\.js)"/g))
    initial.add('assets/' + (m[1] ?? m[2]));
}
const initialGz = [...initial].reduce((n, f) => n + gzipSync(readFileSync(join(dist, f))).length, 0);
const total = all.reduce((n, f) => n + statSync(f).size, 0);
console.log(
  `check-dist: initial JS ${(initialGz / 1024).toFixed(1)} KB gz (budget 300), all assets ${(total / 1024).toFixed(0)} KB (budget 2048)`,
);
if (initialGz > 300 * 1024) {
  console.error('initial JS over budget');
  fail++;
}
if (total > 2 * 1024 * 1024) {
  console.error('static assets over budget');
  fail++;
}
if (fail) process.exit(1);
