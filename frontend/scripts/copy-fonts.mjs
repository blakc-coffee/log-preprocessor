// Copies the self-hosted WOFF2 files DESIGN.md requires into public/fonts/,
// with their licences (SIL OFL 1.1). Run after `npm ci` when a font package
// is upgraded; the copied files are committed so the build needs no network.
import { copyFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const out = 'public/fonts';
mkdirSync(out, { recursive: true });
const files = [
  ['@fontsource-variable/inter', 'inter-latin-wght-normal.woff2'],
  ['@fontsource-variable/inter', 'inter-latin-ext-wght-normal.woff2'],
  ['@fontsource-variable/jetbrains-mono', 'jetbrains-mono-latin-wght-normal.woff2'],
  ['@fontsource-variable/jetbrains-mono', 'jetbrains-mono-latin-ext-wght-normal.woff2'],
  ['@fontsource/cormorant-garamond', 'cormorant-garamond-latin-300-normal.woff2'],
];
for (const [pkg, file] of files) copyFileSync(join('node_modules', pkg, 'files', file), join(out, file));
for (const [pkg, name] of [
  ['@fontsource-variable/inter', 'Inter'],
  ['@fontsource-variable/jetbrains-mono', 'JetBrainsMono'],
  ['@fontsource/cormorant-garamond', 'CormorantGaramond'],
])
  copyFileSync(join('node_modules', pkg, 'LICENSE'), join(out, `LICENSE-${name}.txt`));
console.log(`fonts copied to ${out}`);
