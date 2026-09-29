// A small fetch wrapper for the control API. Every failure becomes an
// ApiError carrying the server's stable error code, so screens can react to
// codes (admin_unreachable, stale_base_version) rather than to strings.

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }

  /** The data plane could not be reached or answered too slowly. */
  get adminDown(): boolean {
    return this.code === 'admin_unreachable' || this.code === 'admin_timeout' || this.code === 'network';
  }
}

type Query = Record<string, string | number | boolean | undefined | null>;

export function withQuery(path: string, q?: Query): string {
  if (!q) return path;
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v !== undefined && v !== null && v !== '') p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `${path}?${s}` : path;
}

async function request<T>(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    // Resolved against this page's origin: same request in the browser, and a
    // valid absolute URL for fetch in tests.
    res = await fetch(new URL(path, window.location.href), {
      method,
      signal,
      headers:
        body === undefined
          ? { Accept: 'application/json' }
          : { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    throw new ApiError(0, 'network', 'The control plane did not respond.');
  }
  const text = await res.text();
  if (!res.ok) {
    let code = 'http_' + res.status;
    let message = `Request failed with status ${res.status}.`;
    try {
      const j = JSON.parse(text) as { error?: { code?: string; message?: string } };
      if (j.error?.code) code = j.error.code;
      if (j.error?.message) message = j.error.message;
    } catch {
      /* not JSON: keep the generic message */
    }
    throw new ApiError(res.status, code, message);
  }
  const ct = res.headers.get('Content-Type') ?? '';
  if (!ct.includes('json')) return text as T;
  return JSON.parse(text) as T;
}

export const api = {
  get: <T>(path: string, q?: Query, signal?: AbortSignal) => request<T>('GET', withQuery(path, q), undefined, signal),
  post: <T>(path: string, body: unknown) => request<T>('POST', path, body),
};
