# ULPF fixture corpus (SYNTHETIC)

**Every file in this directory is synthetic.** Nothing here is a real capture
from a real device or a real network. The log lines are faithful approximations
of the vendors' documented formats, written so parsers can be developed and
tested offline. All addresses come from the ranges reserved for documentation
(RFC 5737) and private use (RFC 1918). All user names are invented.

Regenerate with:

    make fixtures        # full profile
    make fixtures-sample # ~50 records per source

`make fixtures-check` proves the generator is deterministic.

| Field | Value |
|---|---|
| generator version | 1.0.0 |
| seed | 20260928 |
| profile | full |
| base time | 2026-09-28T09:00:00+05:30 |

Every timestamp is IST (+05:30). Formats that carry no zone of their own
(ASA, DHCP, RADIUS) declare it through `manifest.json` -> `generator.base_time`.

## Files

- `cisco_asa.log`
- `fortinet.log`
- `suricata.json`
- `manifest.json` — ground truth: byte ranges, SHA-256s and expected parse results.
