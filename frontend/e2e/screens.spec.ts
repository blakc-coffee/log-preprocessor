import { test, expect } from '@playwright/test';
import { auditLayout, resetMock, sealedEventId, watchErrors } from './helpers';

// Every screen, at both artboard sizes (see playwright.config.ts projects):
// renders, raises no console error, and passes the layout and design audit.
// A full-page screenshot of each is attached to the HTML report.
const SCREENS = [
  { path: '/', heading: 'Unified Lineage Explorer' },
  { path: '/review', heading: 'Review Queue' },
  { path: '/parsers', heading: 'Parser Registry' },
  { path: '/identity', heading: 'Identity Timeline' },
  { path: '/vault', heading: 'Vault & Chain' },
];

test.beforeEach(async ({ request }) => resetMock(request));

for (const s of SCREENS) {
  test(`${s.heading}: renders cleanly with nothing overlapping`, async ({ page }, info) => {
    const noErrors = watchErrors(page);
    await page.goto(s.path);
    await expect(page.getByRole('heading', { level: 1, name: s.heading })).toBeVisible();
    await page.waitForLoadState('networkidle').catch(() => {}); // live polling may never go idle
    await page.waitForTimeout(500);
    expect(await auditLayout(page)).toEqual([]);
    await info.attach(`${s.heading} (${info.project.name})`, {
      body: await page.screenshot(),
      contentType: 'image/png',
    });
    noErrors();
  });
}

test('forensic modal: layout audit', async ({ page, request }, info) => {
  const noErrors = watchErrors(page);
  await page.goto(`/events/${encodeURIComponent(await sealedEventId(request))}`);
  await expect(page.getByRole('dialog')).toBeVisible();
  await expect(page.getByLabel('Hex dump')).toContainText('00000000');
  expect(await auditLayout(page)).toEqual([]);
  await info.attach(`modal (${info.project.name})`, { body: await page.screenshot(), contentType: 'image/png' });
  noErrors();
});

test('masthead: tabs navigate and the About panel states the v1 limits', async ({ page }) => {
  await page.goto('/');
  for (const tab of ['Review Queue', 'Parser Registry', 'Identity', 'Vault', 'Lineage Explorer']) {
    await page.getByRole('link', { name: tab, exact: true }).click();
    await expect(page.getByRole('link', { name: tab, exact: true })).toHaveAttribute('aria-current', 'page');
  }
  await page.getByRole('button', { name: /About this console/ }).click();
  await expect(page.getByRole('dialog', { name: 'About this console' })).toContainText('No authentication (v1)');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog', { name: 'About this console' })).toBeHidden();
});

test('explorer: keyboard, search and live tail', async ({ page }) => {
  await page.goto('/');
  const rows = page.getByRole('rowgroup', { name: 'Event rows' }).getByRole('row');
  await expect(rows.first()).toBeVisible();

  // j moves the selection, Enter opens it, Escape closes.
  await page.keyboard.press('j');
  await expect(rows.nth(1)).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/\/events\//);
  await expect(page.getByRole('dialog')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toBeHidden();

  // "/" focuses search; an IP becomes an ip= filter and every row involves it.
  await page.keyboard.press('/');
  await expect(page.getByRole('searchbox', { name: 'Search events' })).toBeFocused();
  await page.keyboard.type('10.1.4.7');
  await expect(page.getByText('Search: ip = 10.1.4.7')).toBeVisible();
  await expect(rows.first()).toContainText('10.1.4.7');

  // The mock ingests every second: the loaded count grows while Live is on.
  await page.getByRole('searchbox', { name: 'Search events' }).fill('');
  const loaded = async () => Number((await page.getByText(/loaded of/).innerText()).split(' ')[0]!.replace(/,/g, ''));
  const before = await loaded();
  await expect.poll(loaded, { timeout: 10_000 }).toBeGreaterThan(before);
});
