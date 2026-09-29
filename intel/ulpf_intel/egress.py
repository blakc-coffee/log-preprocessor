"""`--egress-check`: prove the sidecar's environment is air-gapped.

Tries a public DNS lookup and two outbound TCP connections. Every attempt is EXPECTED to fail;
the check exits non-zero if ANY succeeds (something can reach the internet).
"""
from __future__ import annotations

import socket
from typing import Callable

TARGETS = [("dns", "example.com", None), ("tcp", "1.1.1.1", 443), ("tcp", "8.8.8.8", 53)]


def attempts(timeout: float = 2.0,
             resolve: Callable = socket.getaddrinfo,
             connect: Callable = socket.create_connection) -> list[tuple[str, bool]]:
    """(description, succeeded) per attempt. Failure is the good outcome."""
    out = []
    for kind, host, port in TARGETS:
        try:
            if kind == "dns":
                socket.setdefaulttimeout(timeout)
                resolve(host, 443)
            else:
                connect((host, port), timeout=timeout).close()
            out.append((f"{kind} {host}{'' if port is None else ':' + str(port)}", True))
        except OSError:
            out.append((f"{kind} {host}{'' if port is None else ':' + str(port)}", False))
    return out


def run(**kw) -> int:
    res = attempts(**kw)
    for what, ok in res:
        print(f"{'REACHED (bad)' if ok else 'blocked (good)'}  {what}")
    leaked = [w for w, ok in res if ok]
    print("FAIL: outbound access exists" if leaked else "PASS: no outbound access")
    return 1 if leaked else 0
