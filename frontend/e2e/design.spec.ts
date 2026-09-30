import { test, expect, type Page } from '@playwright/test';
import { resetMock, sealedEventId } from './helpers';

// Measures the running UI against DESIGN.md's numbers, one rule per line, so a
// regression names the rule it broke. Colours are computed RGB values.
const C = {
  canvas: 'rgb(0, 0, 0)',
  card: 'rgb(5, 6, 7)',
  white: 'rgb(255, 255, 255)',
  muted: 'rgb(179, 179, 179)',
  border: 'rgb(51, 51, 51)',
  mint: 'rgb(63, 203, 127)',
  lavender: 'rgb(153, 132, 216)',
};

type Rule = { what: string; ok: boolean; got: string };

async function measure(page: Page): Promise<Rule[]> {
  return page.evaluate((C) => {
    const out: { what: string; ok: boolean; got: string }[] = [];
    const px = (v: string) => Math.round(parseFloat(v));
    const cs = (el: Element | null) => (el ? getComputedStyle(el) : null);
    const check = (what: string, ok: boolean, got: unknown) => out.push({ what, ok, got: String(got) });
    const box = (el: Element) => el.getBoundingClientRect();

    // Page and type
    const body = cs(document.body)!;
    check('page background is #000000', body.backgroundColor === C.canvas, body.backgroundColor);
    check('UI font is Inter', body.fontFamily.startsWith('Inter'), body.fontFamily);
    check('UI tracking is -0.03em', Math.abs(parseFloat(body.letterSpacing) + 0.39) < 0.02, body.letterSpacing);
    check('Inter is loaded', document.fonts.check('400 13px Inter'), '');
    check('Cormorant Garamond 300 is loaded', document.fonts.check('300 34px "Cormorant Garamond"'), '');
    check('JetBrains Mono is loaded', document.fonts.check('400 12px "JetBrains Mono"'), '');

    // Masthead
    const mast = document.querySelector('body header');
    const m = cs(mast)!;
    check('masthead is 56px', px(m.height) === 56, m.height);
    check('masthead fill is #050607', m.backgroundColor === C.card, m.backgroundColor);
    check(
      'masthead has a 1px #333 bottom border',
      m.borderBottomWidth === '1px' && m.borderBottomColor === C.border,
      `${m.borderBottomWidth} ${m.borderBottomColor}`,
    );
    check(
      'masthead padding is 0 16px',
      m.paddingLeft === '16px' && m.paddingRight === '16px' && px(m.paddingTop) === 0,
      `${m.paddingTop} ${m.paddingLeft}`,
    );
    const brand = cs(mast!.firstElementChild)!;
    check(
      'brand is 14px / 700',
      brand.fontSize === '14px' && brand.fontWeight === '700',
      `${brand.fontSize} ${brand.fontWeight}`,
    );
    const nav = mast!.querySelector('nav')!;
    const nb = box(nav);
    check(
      'tabs are centred in the masthead',
      Math.abs(nb.left + nb.width / 2 - innerWidth / 2) < innerWidth * 0.08,
      nb.left + nb.width / 2,
    );

    // Live dot: mint, 8px, round, exactly one on screen
    const dots = [...document.querySelectorAll('span')].filter(
      (s) => cs(s)!.backgroundColor === C.mint && box(s).width > 0,
    );
    check('one live status dot per screen', dots.length <= 1, dots.length);
    for (const d of dots)
      check('live dot is 8×8', px(cs(d)!.width) === 8 && px(cs(d)!.height) === 8, `${cs(d)!.width}×${cs(d)!.height}`);

    // Section headline
    const h1 = document.querySelector('h1');
    if (h1) {
      const h = cs(h1)!;
      check(
        'headline font is Cormorant Garamond',
        h.fontFamily.startsWith('"Cormorant Garamond"') || h.fontFamily.startsWith('Cormorant Garamond'),
        h.fontFamily,
      );
      check('headline is 34px / 300', h.fontSize === '34px' && h.fontWeight === '300', `${h.fontSize} ${h.fontWeight}`);
      check(
        'section header band is 64px',
        px(cs(h1.closest('header'))!.height) === 64,
        cs(h1.closest('header'))!.height,
      );
    }

    // Stat cards (the telemetry strip)
    for (const strip of document.querySelectorAll('section[aria-label]')) {
      if (!strip.classList.contains('grid')) continue;
      for (const card of strip.children) {
        const c = cs(card)!;
        check('stat card is 88px', px(c.height) === 88, c.height);
        check('stat card radius is 16px', c.borderTopLeftRadius === '16px', c.borderTopLeftRadius);
        check('stat card fill is #050607', c.backgroundColor === C.card, c.backgroundColor);
        check(
          'stat card padding is 24px',
          c.paddingLeft === '24px' && c.paddingTop === '24px',
          `${c.paddingTop} ${c.paddingLeft}`,
        );
      }
    }

    // Filter bar, inputs, selects
    const search = document.querySelector('[role=search]');
    if (search) check('filter bar is 52px', px(cs(search)!.height) === 52, cs(search)!.height);
    for (const f of document.querySelectorAll('input:not([type=checkbox]), select, textarea')) {
      const s = cs(f)!;
      if (s.display === 'none') continue;
      check('field fill is #050607', s.backgroundColor === C.card, s.backgroundColor);
      check(
        'field border is 1px #333',
        s.borderTopWidth === '1px' && s.borderTopColor === C.border,
        `${s.borderTopWidth} ${s.borderTopColor}`,
      );
      check('field radius is 6px', s.borderTopLeftRadius === '6px', s.borderTopLeftRadius);
      check('field text is white', s.color === C.white, s.color);
    }

    // Buttons
    for (const b of document.querySelectorAll('button')) {
      const s = cs(b)!;
      if (s.display === 'none' || box(b).width === 0) continue;
      if (s.backgroundColor === C.white && b.getAttribute('role') !== 'tab') {
        const label = (b.textContent ?? '').trim();
        if (px(s.borderTopLeftRadius) >= 999) continue; // the "N new events" pill, not a CTA
        check(`primary "${label}": black text`, s.color === C.canvas, s.color);
        check(`primary "${label}": radius 6px`, s.borderTopLeftRadius === '6px', s.borderTopLeftRadius);
        check(`primary "${label}": no border`, s.borderTopWidth === '0px', s.borderTopWidth);
        check(
          `primary "${label}": 12px 24px`,
          s.paddingTop === '12px' && s.paddingLeft === '24px',
          `${s.paddingTop} ${s.paddingLeft}`,
        );
        check(
          `primary "${label}": 14px / 700`,
          s.fontSize === '14px' && s.fontWeight === '700',
          `${s.fontSize} ${s.fontWeight}`,
        );
      }
    }

    // Tables: header #000, 11/500 uppercase 0.08em muted; rows 48px, striped
    for (const hdr of document.querySelectorAll('th, [role=columnheader]')) {
      const s = cs(hdr)!;
      if (s.display === 'none') continue;
      const inPanel = hdr.closest('table:not(.table-fixed)'); // small tables inside detail panels use the label style only
      if (!inPanel) {
        const fill =
          hdr.getAttribute('role') === 'columnheader' ? cs(hdr.parentElement)!.backgroundColor : s.backgroundColor;
        check('table header fill is #000000', fill === C.canvas, fill);
      }
      check(
        'table header is 11px / 500',
        s.fontSize === '11px' && s.fontWeight === '500',
        `${s.fontSize} ${s.fontWeight}`,
      );
      check(
        'table header is uppercase, 0.08em',
        s.textTransform === 'uppercase' && Math.abs(parseFloat(s.letterSpacing) - 0.88) < 0.02,
        `${s.textTransform} ${s.letterSpacing}`,
      );
      check('table header is muted', s.color === C.muted, s.color);
    }
    const rows = [...document.querySelectorAll('tbody tr.h-row, [role=rowgroup] [role=row]')];
    rows.forEach((r, i) => {
      const s = cs(r)!;
      check('data row is 48px', px(s.height) === 48, s.height);
      if (r.getAttribute('aria-selected') !== 'true') {
        const want = i % 2 === 0 ? C.card : C.canvas;
        check(
          'rows alternate #050607 / #000000',
          s.backgroundColor === want || s.backgroundColor === 'rgba(255, 255, 255, 0.03)',
          s.backgroundColor,
        );
      }
    });

    // Pills
    for (const p of document.querySelectorAll('span.rounded-pill')) {
      const s = cs(p)!;
      if (box(p).width < 20) continue; // the live dot
      check('pill fill is #050607', s.backgroundColor === C.card, s.backgroundColor);
      check('pill border is 1px #333', s.borderTopWidth === '1px' && s.borderTopColor === C.border, s.borderTopColor);
      check('pill is 11px', s.fontSize === '11px', s.fontSize);
      check(
        'pill padding is 2px 10px',
        s.paddingTop === '2px' && s.paddingLeft === '10px',
        `${s.paddingTop} ${s.paddingLeft}`,
      );
    }

    // Accent colours: mint only for verified states; lavender only as a fill
    const mintOk = /^(100%|Intact|PASSED|approved|resolved|verified)$/i;
    for (const el of document.querySelectorAll('body *')) {
      const s = cs(el)!;
      if (s.display === 'none') continue;
      const own = [...el.childNodes]
        .filter((n) => n.nodeType === 3)
        .map((n) => n.textContent)
        .join('')
        .trim();
      if (own && s.color === C.mint) check(`mint text only for verified states ("${own}")`, mintOk.test(own), own);
      if (own && s.color === C.lavender) check(`lavender is never text ("${own}")`, false, own);
    }
    const bars = document.querySelectorAll('[role=img][aria-label*="Events per second"] > span');
    if (bars.length) {
      check('sparkline has 8 bars', bars.length === 8, bars.length);
      const b = cs(bars[0]!)!;
      check(
        'sparkline bars are lavender at 0.7',
        b.backgroundColor === C.lavender && b.opacity === '0.7',
        `${b.backgroundColor} ${b.opacity}`,
      );
      check('sparkline bar radius is 2px', b.borderTopLeftRadius === '2px', b.borderTopLeftRadius);
      check(
        'sparkline is 24px tall',
        px(cs(bars[0]!.parentElement)!.height) === 24,
        cs(bars[0]!.parentElement)!.height,
      );
    }

    // Monospace where DESIGN.md says so
    for (const el of document.querySelectorAll('.font-mono')) {
      const f = cs(el)!.fontFamily;
      check('code text is JetBrains Mono', f.startsWith('"JetBrains Mono"') || f.startsWith('JetBrains Mono'), f);
      break;
    }
    // Tab labels: 14px / 700 (masthead and in-panel tabs)
    for (const t of document.querySelectorAll('nav[aria-label=Screens] a, [role=tab]')) {
      const s = cs(t)!;
      check(
        `tab "${(t.textContent ?? '').trim()}" is 14px / 700`,
        s.fontSize === '14px' && s.fontWeight === '700',
        `${s.fontSize} ${s.fontWeight}`,
      );
    }
    // Secondary buttons: card fill, muted or white text, 1px #333, 6px, 8px 16px, 13px
    for (const b of document.querySelectorAll('button')) {
      const s = cs(b)!;
      if (s.display === 'none' || box(b).width === 0 || b.getAttribute('role') === 'tab') continue;
      if (s.backgroundColor !== C.card || s.borderTopWidth !== '1px' || px(s.borderTopLeftRadius) !== 6) continue;
      const label = (b.textContent ?? '').trim();
      check(
        `secondary "${label}": 8px 16px`,
        s.paddingTop === '8px' && s.paddingLeft === '16px',
        `${s.paddingTop} ${s.paddingLeft}`,
      );
      check(`secondary "${label}": 13px`, s.fontSize === '13px', s.fontSize);
      check(`secondary "${label}": #333 border`, s.borderTopColor === C.border, s.borderTopColor);
    }
    // Inputs and selects: Inter 13px, 8px 12px (the YAML textarea is code: 12px mono)
    for (const f of document.querySelectorAll('input:not([type=checkbox]), select')) {
      const s = cs(f)!;
      if (s.display === 'none') continue;
      check('field is 13px', s.fontSize === '13px', s.fontSize);
      check(
        'field padding is 8px 12px',
        s.paddingTop === '8px' && s.paddingLeft === '12px',
        `${s.paddingTop} ${s.paddingLeft}`,
      );
    }
    // Pills: #b3b3b3, or mint when verified; never white
    for (const p of document.querySelectorAll('span.rounded-pill')) {
      if (box(p).width < 20) continue;
      const c = cs(p)!.color;
      check(`pill "${(p.textContent ?? '').trim()}" is muted or verified mint`, c === C.muted || c === C.mint, c);
    }
    // SHA-256 strings: 11px mono (stat-card values excepted: they are metric values)
    for (const el of document.querySelectorAll('body *')) {
      const own = [...el.childNodes]
        .filter((n) => n.nodeType === 3)
        .map((n) => n.textContent)
        .join('')
        .trim();
      if (!/^[0-9a-f]{12,64}…?$/.test(own) || el.closest('.h-telemetry')) continue;
      const s = cs(el)!;
      check(
        `hash "${own.slice(0, 12)}" is 11px mono`,
        s.fontSize === '11px' && s.fontFamily.includes('JetBrains Mono'),
        `${s.fontSize} ${s.fontFamily.slice(0, 20)}`,
      );
    }
    return out;
  }, C);
}

function failures(rules: Rule[]) {
  return rules.filter((r) => !r.ok).map((r) => `${r.what} (got ${r.got})`);
}

test.beforeEach(async ({ request }) => resetMock(request));

for (const path of ['/', '/review', '/parsers', '/identity', '/vault']) {
  test(`DESIGN.md measurements: ${path}`, async ({ page }) => {
    await page.goto(path);
    await expect(page.locator('h1')).toBeVisible();
    await page.waitForTimeout(2500); // fonts, telemetry history and the first data
    const rules = await measure(page);
    expect(rules.length).toBeGreaterThan(20);
    expect(failures(rules)).toEqual([]);
  });
}

test('DESIGN.md measurements: forensic modal', async ({ page, request }, info) => {
  await page.goto(`/events/${encodeURIComponent(await sealedEventId(request))}`);
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  const m = await dialog.evaluate((d) => {
    const s = getComputedStyle(d);
    const r = d.getBoundingClientRect();
    const backdrop = getComputedStyle(d.parentElement!);
    const header = d.querySelector('header')!.getBoundingClientRect();
    const footer = d.querySelector('footer')!.getBoundingClientRect();
    const split = d.querySelector('.grid-cols-2')!;
    const [left, right] = [...split.children].map((c) => c.getBoundingClientRect());
    return {
      width: Math.round(r.width),
      height: Math.round(r.height),
      radius: s.borderTopLeftRadius,
      fill: s.backgroundColor,
      border: `${s.borderTopWidth} ${s.borderTopColor}`,
      shadow: s.boxShadow,
      backdrop: backdrop.backgroundColor,
      blur: backdrop.backdropFilter,
      header: Math.round(header.height),
      footer: Math.round(footer.height),
      cols: [Math.round(left!.width), Math.round(right!.width)],
      divider: getComputedStyle(split.children[0]!).borderRightColor,
      headingSize: getComputedStyle(d.querySelector('h2')!).fontSize,
      headingWeight: getComputedStyle(d.querySelector('h2')!).fontWeight,
    };
  });
  const vw = page.viewportSize()!;
  expect.soft(m.width, 'modal width is 1080px (or the viewport minus the gutter)').toBe(Math.min(1080, vw.width - 32));
  expect.soft(m.height, 'modal height is 640px (or 80vh)').toBe(Math.min(640, Math.floor(vw.height * 0.8)));
  expect.soft(m.radius, 'modal radius').toBe('16px');
  expect.soft(m.fill, 'modal fill').toBe(C.card);
  expect.soft(m.border, 'modal border').toBe(`1px ${C.border}`);
  expect.soft(m.shadow, 'modal shadow').toBe('none');
  expect.soft(m.backdrop, 'backdrop is black at 0.7').toBe('rgba(0, 0, 0, 0.7)');
  expect.soft(m.blur === 'none' || m.blur === '', 'backdrop is not blurred').toBe(true);
  expect.soft(m.header, 'modal header band').toBe(52);
  expect.soft(m.footer, 'modal footer band').toBe(52);
  expect.soft(Math.abs(m.cols[0]! - m.cols[1]!), 'two equal columns').toBeLessThanOrEqual(1);
  expect.soft(m.divider, '1px #333 divider').toBe(C.border);
  expect.soft(`${m.headingSize} ${m.headingWeight}`, 'modal heading 16/600').toBe('16px 600');
  await info.attach('measurements', { body: JSON.stringify(m, null, 2), contentType: 'application/json' });
});

// The same measurements in the states the default screens do not show:
// drift in the queue, each proposal tab, a finished replay, the versions drawer.
test('DESIGN.md measurements: interactive states', async ({ page, request }) => {
  await request.post('/mock/advance'); // drift
  const expectClean = async (state: string) => {
    await page.waitForTimeout(400);
    expect(failures(await measure(page)), state).toEqual([]);
  };
  await page.goto('/review');
  await page.getByRole('row', { name: /Patch fortinet/ }).click();
  await expectClean('queue with drift, typed fields');
  await page.getByRole('tab', { name: 'Parser YAML' }).click();
  await expectClean('YAML diff');
  await page.getByRole('button', { name: 'Edit' }).click();
  await expectClean('YAML editor');
  await page.getByRole('tab', { name: 'Dry run' }).click();
  await expectClean('dry run');
  await page.getByRole('textbox', { name: 'Recorded name' }).fill('Design Audit');
  await page.getByRole('button', { name: 'Approve & Replay from Vault' }).click();
  await expect(page.getByRole('button', { name: /View \d+ recovered events/ })).toBeVisible({ timeout: 30_000 });
  await expectClean('after approve and replay');
  await page.getByRole('row', { name: /keys renamed/ }).click();
  await expectClean('resolved drift alert');
  await page.getByRole('row', { name: /No parser matched/ }).click();
  await expectClean('quarantine cluster');
  await page.goto('/parsers/fortinet');
  await page.getByRole('button', { name: /Versions & history/ }).click();
  await page.getByRole('button', { name: 'Diff vs 1.0.1' }).click();
  await expectClean('versions drawer with diff');
  await page.getByRole('button', { name: 'Run verification' }).click();
  await expect(page.getByText(/samples parsed/)).toBeVisible();
  await expectClean('verification result');
});
