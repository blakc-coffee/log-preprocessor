import { test, expect } from '@playwright/test';
import { resetMock } from './helpers';

// The two-minute demo's self-healing beat, through the real UI:
// drift -> review the patch -> approve -> replay drains the quarantine ->
// the recovered events are in the explorer, and the approval is audited.
test('drift, approve and replay from the vault', async ({ page, request }) => {
  await resetMock(request);
  expect((await (await request.post('/mock/advance')).json()).scenario).toBe('drift');

  await page.goto('/review');
  const queue = page.getByRole('table').first();
  await queue.getByRole('row', { name: /Patch fortinet 1\.0\.0/ }).click();
  await expect(page.getByRole('heading', { name: 'Parser patch · fortinet' })).toBeVisible();

  // Typed fields: low-confidence rows are marked for review.
  await expect(page.getByRole('tab', { name: /Typed fields · 2 to check/ })).toBeVisible();

  // The diff against the active version shows the key renames.
  await page.getByRole('tab', { name: 'Parser YAML' }).click();
  await expect(page.getByRole('button', { name: 'Diff vs 1.0.0' })).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByText('- {from: src, to: src_endpoint.ip, type: ip}')).toBeVisible();

  // Approve needs a recorded name.
  const approve = page.getByRole('button', { name: 'Approve & Replay from Vault' });
  await expect(approve).toBeDisabled();
  await page.getByRole('textbox', { name: 'Recorded name' }).fill('E2E Reviewer');
  await page.getByRole('textbox', { name: 'Comment' }).fill('firmware layout change');
  await approve.click();

  // Replay drains the quarantine.
  const card = page
    .getByText(/Replay from vault · replay-/)
    .locator('..')
    .locator('..');
  await expect(card.getByText('PASSED')).toBeVisible({ timeout: 30_000 });
  await expect(card).toContainText('0 failed');
  const recovered = page.getByRole('button', { name: /View \d+ recovered events/ });
  await expect(recovered).toBeVisible();

  // The proposal is approved and the drift alert resolved.
  await expect(page.getByRole('heading', { name: 'Parser patch · fortinet' }).locator('..')).toContainText('approved');

  // Recovered events carry the new parser version.
  await recovered.click();
  await expect(page).toHaveURL(/q=source%3Afortinet/);
  await page.getByRole('rowgroup', { name: 'Event rows' }).getByRole('row').first().click();
  await expect(page.getByRole('dialog')).toContainText('fortinet@1.0.1');
  await page.keyboard.press('Escape');

  // The registry recorded who approved it.
  await page.goto('/parsers/fortinet');
  await page.getByRole('button', { name: /Versions & history/ }).click();
  await expect(page.getByLabel('Versions')).toContainText('approve by E2E Reviewer');
});
