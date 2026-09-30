import { readFileSync } from 'node:fs';
import { test, expect } from '@playwright/test';
import { resetMock, sealedEventId } from './helpers';

test.beforeEach(async ({ request }) => resetMock(request));

const footer = (page: import('@playwright/test').Page) => page.getByRole('group', { name: /Verification/ });

test('a sealed event passes all three checks computed in the browser', async ({ page, request }) => {
  await page.goto(`/events/${encodeURIComponent(await sealedEventId(request))}`);
  await expect(footer(page).getByText('PASSED')).toHaveCount(3);
  await expect(footer(page)).toContainText('chain link verified');
});

test('tampered raw bytes fail SHA-256 and Merkle, whatever the server claims', async ({ page, request }) => {
  const id = await sealedEventId(request);
  // Flip one byte of the raw record on its way to the browser, and keep the
  // server's own sha_match: true. The browser must not believe it.
  await page.route('**/api/events/*/raw', async (route) => {
    const res = await route.fetch();
    const body = await res.json();
    const bytes = Buffer.from(body.raw_base64, 'base64');
    bytes[5] ^= 1;
    await route.fulfill({ response: res, json: { ...body, raw_base64: bytes.toString('base64'), sha_match: true } });
  });
  await page.goto(`/events/${encodeURIComponent(id)}`);
  await expect(footer(page).getByText('FAILED')).toHaveCount(2);
});

test('the newest event is pending until its segment seals, then passes', async ({ page, request }) => {
  const r = await request.get('/api/events?limit=1');
  const id = (await r.json()).events[0].event_id as string;
  await page.goto(`/events/${encodeURIComponent(id)}`);
  const merkle = footer(page).locator('div', { hasText: 'Merkle inclusion + chain' }).first();
  await expect(merkle).toContainText(/PENDING|PASSED/);
  // The mock seals every 64 records (about 15 s at its ingest rate); the
  // lineage query polls every 3 s until the proof exists.
  await expect(merkle).toContainText('PASSED', { timeout: 45_000 });
});

test('the hex view downloads the exact raw bytes', async ({ page, request }) => {
  const id = await sealedEventId(request);
  await page.goto(`/events/${encodeURIComponent(id)}`);
  const [dl] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Download raw' }).click(),
  ]);
  const path = await dl.path();
  const got = readFileSync(path);
  const raw = await (await request.get(`/api/events/${encodeURIComponent(id)}/raw`)).json();
  expect(got.equals(Buffer.from(raw.raw_base64, 'base64'))).toBe(true);
});
