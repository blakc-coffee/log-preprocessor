// Enforces DESIGN.md's non-negotiables on the source (Frontend PRD 3.2:
// "any spacing or colour literal in components is a review failure").
// Run by `npm run lint`. Exits 1 with file:line for each violation.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const RULES = [
  [/#[0-9a-fA-F]{3,8}\b/, 'colour literal: use a token from src/design/tokens.css'],
  [/\brgba?\(|\bhsla?\(/, 'colour function: use a token'],
  [/\bshadow-|box-shadow|drop-shadow/, 'shadows are banned (DESIGN.md rule 2)'],
  [/\bring-|\bring\b/, 'ring utilities are banned as focus indicators'],
  [/gradient/, 'gradients are banned'],
  [/backdrop-blur|backdrop-filter|blur\(/, 'glassmorphism is banned'],
  [/rounded-full|rounded-(sm|md|lg|xl|2xl|3xl)\b/, 'use rounded-card, rounded-button, rounded-pill or rounded-bar'],
  [/border-(mint|lavender)|outline-(mint|lavender)/, 'zero coloured borders'],
  [/text-lavender/, 'lavender is for data fills only, never text'],
  [
    /\b(?:p|px|py|pt|pb|pl|pr|m|mx|my|mt|mb|ml|mr|gap|w|h|text|leading|tracking|rounded|top|left|right|bottom|inset)-\[(?!80vh)[^\]]*\]/,
    'arbitrary value: add a token',
  ],
  [/font-(sans|serif)\b|fonts\.googleapis|fonts\.gstatic/, 'fonts come from tokens.css only'],
  [/https?:\/\/(?!www\.w3\.org)/, 'external URL in source'],
];

const files = [];
(function walk(d) {
  for (const f of readdirSync(d)) {
    const p = join(d, f);
    if (statSync(p).isDirectory()) walk(p);
    else if (/\.(tsx?|css)$/.test(f) && !/\.test\.tsx?$/.test(f) && !p.includes('/test/') && !p.endsWith('tokens.css'))
      files.push(p);
  }
})('src');

let bad = 0;
for (const f of files) {
  readFileSync(f, 'utf8')
    .split('\n')
    .forEach((line, i) => {
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) return; // comments explain the rules
      for (const [re, why] of RULES) {
        if (re.test(line)) {
          console.error(`${f}:${i + 1}: ${why}\n    ${line.trim().slice(0, 140)}`);
          bad++;
        }
      }
    });
}
if (bad) {
  console.error(`\ncheck-design: ${bad} violation(s)`);
  process.exit(1);
}
console.log(`check-design: ${files.length} files clean`);
