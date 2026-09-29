import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterAll, afterEach, beforeAll } from 'vitest';
import { server } from './server';

// jsdom has no layout. Give elements a size so the virtualized lists render
// rows, and stub ResizeObserver, which jsdom lacks.
Object.defineProperty(HTMLElement.prototype, 'offsetHeight', { configurable: true, get: () => 800 });
Object.defineProperty(HTMLElement.prototype, 'offsetWidth', { configurable: true, get: () => 1200 });
HTMLElement.prototype.getBoundingClientRect = function () {
  return {
    x: 0,
    y: 0,
    top: 0,
    left: 0,
    bottom: 800,
    right: 1200,
    width: 1200,
    height: 800,
    toJSON: () => ({}),
  } as DOMRect;
};
globalThis.ResizeObserver = class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver;

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => {
  cleanup();
  server.resetHandlers();
  localStorage.clear();
});
afterAll(() => server.close());
