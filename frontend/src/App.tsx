import { lazy, Suspense, type ComponentType } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { Layout } from './components/Layout';
import { ErrorBoundary } from './components/ErrorBoundary';
import { Explorer } from './screens/Explorer';

// The explorer and its forensic modal load first; the other screens (and the
// YAML library they need) are separate chunks.
//
// A tab left open across a new build still asks for the old chunk names,
// which no longer exist: reload once to pick up the new index.html.
function lazyScreen(load: () => Promise<{ default: ComponentType }>) {
  return lazy(() =>
    load()
      .then((m) => {
        try {
          sessionStorage.removeItem('ulpf.chunkReload');
        } catch {
          /* ignore */
        }
        return m;
      })
      .catch((e: unknown) => {
        let reloaded = false;
        try {
          reloaded = sessionStorage.getItem('ulpf.chunkReload') === '1';
          sessionStorage.setItem('ulpf.chunkReload', '1');
        } catch {
          reloaded = true; // storage blocked: cannot guard against a loop, so show the error instead
        }
        if (!reloaded) window.location.reload();
        throw e;
      }),
  );
}
const ReviewQueue = lazyScreen(() => import('./screens/ReviewQueue'));
const ParserRegistry = lazyScreen(() => import('./screens/ParserRegistry'));
const Identity = lazyScreen(() => import('./screens/Identity'));
const Vault = lazyScreen(() => import('./screens/Vault'));

const screen = (el: React.ReactNode) => (
  <ErrorBoundary>
    <Suspense fallback={null}>{el}</Suspense>
  </ErrorBoundary>
);

export function makeQueryClient() {
  // Keep the last good data while the admin API is down (PRD 3.3).
  return new QueryClient({
    defaultOptions: {
      queries: { staleTime: 1000, refetchOnWindowFocus: false, placeholderData: (prev: unknown) => prev },
    },
  });
}

const client = makeQueryClient();

export function AppRoutes() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={screen(<Explorer />)} />
        <Route path="events/:eventId" element={screen(<Explorer />)} />
        <Route path="review" element={screen(<ReviewQueue />)} />
        <Route path="review/:kind/:id" element={screen(<ReviewQueue />)} />
        <Route path="parsers" element={screen(<ParserRegistry />)} />
        <Route path="parsers/:parserId" element={screen(<ParserRegistry />)} />
        <Route path="identity" element={screen(<Identity />)} />
        <Route path="vault" element={screen(<Vault />)} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

export function App() {
  return (
    <QueryClientProvider client={client}>
      <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <AppRoutes />
      </BrowserRouter>
    </QueryClientProvider>
  );
}
