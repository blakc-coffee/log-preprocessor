import { expect, type Page, type APIRequestContext } from '@playwright/test';

/** Rebuild the mock from its seed so every test starts from the same state. */
export async function resetMock(request: APIRequestContext) {
  expect((await request.post('/mock/reset')).ok()).toBeTruthy();
}

/** Collects console errors and failed requests; call the returned function to assert none happened. */
export function watchErrors(page: Page) {
  const errors: string[] = [];
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('requestfailed', (r) => errors.push(`request failed: ${r.url()}`));
  return () => expect(errors, errors.join('\n')).toEqual([]);
}

/**
 * Layout and design-rule audit, run in the page:
 *  - nothing makes the page, a table or a panel scroll sideways
 *  - no text spills out of its cell, button or label
 *  - every border is DESIGN.md's #333; no shadows, gradients or blur
 */
export async function auditLayout(page: Page) {
  return page.evaluate(() => {
    const issues: string[] = [];
    const doc = document.documentElement;
    if (doc.scrollWidth > doc.clientWidth + 1)
      issues.push(`page scrolls sideways (${doc.scrollWidth} > ${doc.clientWidth})`);
    const name = (el: Element) => `${el.tagName.toLowerCase()} "${(el.textContent ?? '').trim().slice(0, 40)}"`;
    for (const el of Array.from(document.querySelectorAll('*'))) {
      const cs = getComputedStyle(el);
      if (cs.display === 'none' || cs.visibility === 'hidden') continue;
      const code = el.closest('pre, [aria-label="Hex dump"]') || cs.fontFamily.includes('Mono');
      if (
        !code &&
        (cs.overflowX === 'auto' || cs.overflowX === 'scroll') &&
        el.scrollWidth > el.clientWidth + 1 &&
        el.clientWidth > 0
      )
        issues.push(`sideways scroll in ${name(el)} (${el.scrollWidth} > ${el.clientWidth})`);
      if (
        el.matches('td, th, [role=gridcell], [role=columnheader], button, dd, dt') &&
        cs.overflowX === 'visible' &&
        el.scrollWidth > el.clientWidth + 1
      )
        issues.push(`text spills out of ${name(el)}`);
      if (cs.boxShadow !== 'none') issues.push(`shadow on ${name(el)}`);
      if (cs.backgroundImage.includes('gradient')) issues.push(`gradient on ${name(el)}`);
      if (cs.backdropFilter && cs.backdropFilter !== 'none') issues.push(`backdrop filter on ${name(el)}`);
      for (const side of ['Top', 'Right', 'Bottom', 'Left'] as const) {
        const w = parseFloat(cs.getPropertyValue(`border-${side.toLowerCase()}-width`));
        const style = cs.getPropertyValue(`border-${side.toLowerCase()}-style`);
        const color = cs.getPropertyValue(`border-${side.toLowerCase()}-color`);
        if (w > 0 && style !== 'none' && color !== 'rgb(51, 51, 51)') {
          issues.push(`border ${color} on ${name(el)}`);
          break;
        }
      }
    }
    return Array.from(new Set(issues)).slice(0, 20);
  });
}

/** An event old enough to be in a sealed segment, so its Merkle proof exists. */
export async function sealedEventId(request: APIRequestContext): Promise<string> {
  const r = await request.get('/api/events?limit=500');
  const body = (await r.json()) as { events: { event_id: string }[] };
  return body.events[body.events.length - 1]!.event_id;
}
