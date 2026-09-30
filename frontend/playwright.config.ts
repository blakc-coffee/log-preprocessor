import { defineConfig } from '@playwright/test';

// End-to-end checks of the real, embedded UI against the mock admin API.
// Dev machine only (Frontend PRD 5): it drives the locally installed Google
// Chrome, downloads no browsers, and stays out of CI and the container.
//
//   make ui-e2e                 build the UI and binary, then run everything
//   npx playwright test --ui    interactive runner (after `make ui control-build`)
const PORT = 8765;

export default defineConfig({
  testDir: 'e2e',
  // One mock server with shared state: run tests in order, one at a time.
  workers: 1,
  fullyParallel: false,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    channel: 'chrome',
    colorScheme: 'dark',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'desktop-1440', use: { viewport: { width: 1440, height: 900 } } },
    { name: 'narrow-1024', use: { viewport: { width: 1024, height: 768 } } },
  ],
  webServer: {
    command: `../bin/control --mock --mock-seed 20260928 --registry-db :memory: --listen 127.0.0.1:${PORT}`,
    url: `http://127.0.0.1:${PORT}/healthz`,
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
