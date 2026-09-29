// Per-browser preferences. localStorage can throw (private windows, blocked
// site data), so every access is guarded and the UI works without it.

function read(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function write(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    /* not persisted; fine */
  }
}

/** The name recorded on approvals. Not an identity: there is no authentication in v1. */
export const recordedName = {
  get: () => read('ulpf.recordedName') ?? '',
  set: (v: string) => write('ulpf.recordedName', v.trim()),
};

export const utcPref = {
  get: () => read('ulpf.utc') === '1',
  set: (v: boolean) => write('ulpf.utc', v ? '1' : '0'),
};
