# Parser DSL

Normative. The Parsing engine implements it; the intelligence sidecar emits it; `dryrun` validates it.
Five complete examples live in `dsl/examples/` and are checked by `contracts/gen/dsl_test.go` against the real
fixtures in `testdata/sample/`. Where this document and an example disagree, the test that fails decides which is wrong.

A parser is one YAML document. It turns one raw record (bytes, never modified) into one `NormalizedEvent`.

## 1. Top level

| Key | Type | Req | Meaning |
|---|---|---|---|
| `id` | `[a-z0-9_]+` | yes | Stable parser id. Part of `event_id` and `template_id`. |
| `version` | semver | yes | `MAJOR.MINOR.PATCH`. Approval bumps PATCH of an existing id; the server does it, authors do not. |
| `vendor`, `product` | string | yes | Copied to the event. |
| `timezone` | `+HH:MM` | yes | Zone for timestamps that carry none. A per-source override in the data-plane config wins. |
| `match.signature` | RE2 | yes | Cheap detector, tried unanchored against the first 512 bytes. No match, no extraction attempt. |
| `match.hints` | list of `FormatHint` | no | Prefilter on the ingest hint. Omit when unsure: a wrong hint hides a parser. |
| `ocsf_defaults` | map | yes | Fields set on every event (`class_uid`, `category_uid`). |
| `extractors` | list | yes | Ordered. **First success wins per event.** |
| `identity` | map | no | Only for identity-source parsers (section 6). |

`type_uid` is never written by a parser: the engine sets it to `class_uid * 100 + activity_id`.
`metadata.version`, `metadata.product.vendor_name` and `metadata.product.name` are set by the engine from
`vendor`/`product` and the pinned OCSF version (`contracts/ocsf/VERSION`).

## 2. Extractors

Common keys: `id` (`[a-z0-9_]+`, unique in the parser), `kind`, `map`, `tests`, optional `render`.
`template_id` on the event is `<parser id>/<extractor id>`.

### 2.1 `regex`
`pattern` is **RE2** with named groups `(?P<name>...)`. No lookaround and no backreferences; alternatives:
a lookahead becomes a following literal plus an optional group, a backreference becomes two captures compared
after extraction (not supported in v1: split into two extractors). Anchor with `^...$`.

An optional group that did not participate has the empty string as its value and renders as empty.
Give every part of the line that varies its own **named** group, including NAT addresses, interface names and
optional prefixes: text inside an unnamed group counts as *uncovered* (section 5).

### 2.2 `kv`
Keys: `skip_prefix` (RE2, removed before tokenizing), `pair_sep` (default `" "`), `kv_sep` (default `"="`), `quote` (default `"`).
One left-to-right tokenizer. A quoted value may contain `pair_sep` and `kv_sep`. **A value is never re-scanned for keys**:
this is what stops a log line from injecting fields (`msg="a=b srcip=1.2.3.4"` yields one key). A token with no `kv_sep`
becomes a key with an empty value; an unterminated quote runs to the end of the record and sets `key_injection_suspect`.
`render: auto` re-emits pairs in original order with original quoting.

### 2.3 `json`
`map.from` is a dotted path (`alert.signature`). Optional `when: {path, equals}` or `when: {path, in: [...]}` routes by a
field such as `event_type`; extractors whose `when` is false are skipped. Arrays are addressed by index (`a.0.b`).
Nesting deeper than the limit sets `nested_too_deep`. No `render`.

### 2.4 `csv`
`sep`, `quote`, `min_columns`, `columns` (a name, or `_` to skip; a list shorter than the record leaves the tail
unnamed), optional `when: {column: N, equals|in}` (0-based). A record with fewer than `min_columns` fields fails the
extractor. Unnamed and `_` columns are kept in `unmapped` as `col_<N>` (0-based), which is also the name the typer
uses for headerless CSV. No `render`.

### 2.5 `cef`, `leef`
Built in; no `pattern` or `columns`.

**CEF.** `CEF:Version|Vendor|Product|DeviceVersion|SignatureID|Name|Severity|Extension`. Text before `CEF:` (a syslog
header) is ignored. The seven header fields are addressable as `cef.version`, `cef.vendor`, `cef.product`,
`cef.device_version`, `cef.signature_id`, `cef.name`, `cef.severity`; a `\|` or `\\` inside a header field is a literal.
A record with fewer than seven header fields does not match. The extension is `key=value` pairs where a value runs up to
the next ` key=`, so it may contain spaces; `\=` and `\\` in a value are literals. Extension keys are addressable by their own
names (`src`, `spt`, `msg`, `cs1`). The duplicate-key rule of `kv` applies.

**LEEF.** `LEEF:1.0|Vendor|Product|ProductVersion|EventID|` then attributes separated by a tab; `LEEF:2.0` adds a sixth
header field naming the delimiter (one character, or `xHH` for a hex code). Header fields are `leef.version`,
`leef.vendor`, `leef.product`, `leef.product_version`, `leef.event_id`; attributes are addressable by their own names.

Header fields and extension keys that no `map` entry reads go to `unmapped` under those names, like any other capture.

## 3. `map`

Each entry is `{from, to, type, ...}` or `{const, to}`. Several entries may read the same `from`.
`to` is a dotted OCSF path. An unknown `to` path is a load-time error (section 8).

`from` is a capture, key, path or column name. For `type: time` it may be a list, whose values are joined with one space
before parsing (`from: [date, time]`).

| `type` | Accepts | Notes |
|---|---|---|
| `string` | anything | `lower: true` lowercases. |
| `int`, `uint`, `float` | decimal | overflow is a normalize-stage failure, not a wrap. |
| `ip` | IPv4/IPv6 | stored canonical (`net/netip` String). |
| `port` | 0-65535 | |
| `mac` | `aa:bb:..`, `aa-bb-..`, `aabb.ccdd.eeff` | stored lowercase, colon separated. |
| `time` | `layout` (Go reference layout) or `epoch_s`, `epoch_ms`, `epoch_ns`, `rfc3339` | uses `timezone` when the layout has none; stored as UTC, OCSF `time` in epoch milliseconds. A layout with no year takes it from `received_at`, and a month more than one ahead of the receipt month means the previous year. A value that cannot be parsed leaves `time` unset, sets `time_unparseable`, and `time_from_receipt: true`. |
| `enum` | `enum: {captured text: value}`, `default: value` | keys are compared as strings. No `default` and no match is a normalize failure. |
| `bool`, `bytes`, `duration` | | `duration` takes `unit: s|ms|ns` (default `s`) and stores milliseconds. |

**A missing key is a mismatch, unless optional.** A map entry whose `from` does not exist in the record (a kv key, a JSON
path, a csv column past the end of the row, a regex group that is not defined) makes that extractor **not match**; the next
extractor is tried and, if none matches, the record is quarantined. This is deliberate: it is how a renamed key
(`srcip` -> `src`) becomes visible as drift instead of producing half-empty events. An entry marked `optional: true` is
skipped when its key is absent, and the extractor still matches. Empty is different: see next.

**Empty means absent.** An empty value (an empty csv field, `key=` in kv, an optional regex group that did not
participate) is treated as not present: its map entries are skipped, no error, and it is not added to `unmapped`.
Use this for optional columns such as a user name that is blank on some rows.

**Unmapped.** Every capture, key, path or column that no `map` entry reads goes to `unmapped` under its own name
(JSON: under its nested path). Nothing is discarded. `const` entries read nothing.

**Duplicate keys** (`kv`, `json`): the first occurrence maps; later ones go to `unmapped._dupes` (a list of
`{key, value}`), and the event gets `duplicate_key`.

**Limits** (defaults, configurable in the data-plane config): 512 fields, key 256 bytes, value 64 KiB, JSON depth 32.
Over a limit the engine truncates nothing silently: it sets `too_many_fields`, `oversize_field` or `nested_too_deep`
and keeps the event. It never crashes and never drops the record.

## 4. `render` (render-back)

Regex and kv extractors only. `render` is literal text with `{capture}` placeholders; `{{` and `}}` are literal braces.
The engine re-serializes **from the typed values** and compares the result byte for byte with the raw record:

- a capture with a `map` entry of type `int`, `uint`, `port`, `ip`, `mac`, `time` is rendered from its parsed value
  (decimal, canonical IP, colon MAC, the entry's `layout` in `timezone`);
- every other capture renders as its captured text, and the mapping-stage transforms (`enum`, `lower`, `const`) never
  affect rendering;
- an optional group that did not participate renders as empty.

A mismatch sets `render_back_mismatch` and `coverage.render_back_ok=false`. It is a signal, not a failure. It proves the
mapped fields plus the literals reproduce the record, which is what catches a regex that matched but mis-assigned a group.
It is **not** a claim that normalization is lossless: the OCSF mapping transforms the data, and `unmapped` plus
`coverage` show that nothing was dropped.

## 5. Coverage

Byte accounting per event, over the raw record: `mapped_bytes` (bytes of values that a `map` entry reads),
`unmapped_bytes` (bytes of captured values nothing reads), `constant_bytes` (pattern literals: everything the pattern
matched outside a capture; for kv the keys and separators; for json the structure), `uncovered_bytes` (bytes no
extractor accounted for). The four sum to the record length. An anchored regex written to section 2.1 has
`uncovered_bytes == 0`; a non-zero value is flagged in the UI. `mapped_fields` and `unmapped_fields` count map targets
and unmapped entries.

## 6. `identity` block

Only identity-source parsers (DHCP, RADIUS accounting, VPN). Produces the event's `identity` (`IdentityFact`, D8):

```yaml
identity:
  kind: dhcp                       # dhcp | radius | vpn
  when: {field: msgtype, in: [DHCPACK, DHCPRELEASE]}     # facts only for these records
  action: {field: msgtype, enum: {DHCPACK: bind, DHCPRELEASE: release}}   # or a literal: bind
  ip: ip                           # capture names; user/mac/host optional
  mac: mac
  host: hostname
  at: ts                           # a `time` capture, parsed as in section 3
```

Records failing `when` still normalize; they just carry no fact. The resolver (B7) consumes facts only and never sees raw text.

## 7. Tests

`tests:` vectors are `{raw, expect}`; `expect` maps OCSF paths to expected values. They run in unit tests and in
`dryrun`. The engine compares typed values (an `ip` compares canonically). Vectors must be real lines, not
invented ones; `contracts/gen/dsl_test.go` fails if an example's vector is not a line of the fixture corpus.

## 8. Errors

Every load-time error names the parser, the extractor and the field, in that order:

```
parser "cisco_asa" extractor "asa_302013" map[3] (from: src_ipp): capture "src_ipp" is not defined by the pattern
parser "fortinet" extractor "fgt_traffic" map[1] (to: severty_id): unknown OCSF path
parser "cisco_asa" extractor "asa_302013" pattern: RE2 does not support lookahead (?=
```

Load errors reject the parser; nothing half-loaded is ever active. Runtime errors are quarantine reasons
(`failure_stage`: `detect`, `extract`, `normalize`, `integrity`) and appear in `QuarantineRecord.error`.

## 9. Versioning and patches

A parser id has a linear version history. A **patch** proposal has the same `id`, `base_version` = the active version,
and a full replacement document; the server assigns `version = base + 0.0.1`. If the active version has moved on, approval
returns `409` and the proposal is marked `stale`. A drift patch keeps every unchanged mapping and only remaps what the
data plane observed changing; for Fortinet's drift (`srcip`->`src`, `srcport`->`sport`, `dstip`->`dst`,
`dstport`->`dport`, `date`+`time`->`eventtime` epoch nanoseconds) the changed entries are:

```yaml
      - {from: eventtime, to: time, type: time, layout: epoch_ns}
      - {from: src,   to: src_endpoint.ip,   type: ip}
      - {from: sport, to: src_endpoint.port, type: port}
      - {from: dst,   to: dst_endpoint.ip,   type: ip}
      - {from: dport, to: dst_endpoint.port, type: port}
```

## 10. Examples

| File | Kind | Shows |
|---|---|---|
| `dsl/examples/cisco_asa.yaml` | regex | two extractors, enum severity, NAT groups, render-back |
| `dsl/examples/fortinet.yaml` | kv | `skip_prefix`, list `from` for time, enum action, `render: auto` |
| `dsl/examples/palo_alto_traffic.yaml` | csv | headerless columns, `when` on a column, `min_columns` |
| `dsl/examples/suricata_eve.yaml` | json | dotted paths, `when` routing on `event_type` |
| `dsl/examples/isc_dhcpd.yaml` | regex + identity | year-less time, the `identity` block |

Two conventions the examples fix, because the fixtures' ground truth (`testdata/manifest.json`) fixes them:
for an ASA `Built ... for A to B` message, **A is the source and B the destination** whichever direction the
connection is called; and ASA severities map to OCSF `severity_id` through an enum (ASA 6 "informational" is OCSF 1,
not 6 "fatal").
