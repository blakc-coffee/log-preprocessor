# Vendored OCSF subset

Schema version: **1.1.0** (see `VERSION`). Fetched 2026-09-29 from
`https://schema.ocsf.io/api/1.1.0/{classes,objects,categories}/...`, unmodified.

| File | What |
|---|---|
| `class_network_activity.json` | class 4001, the class every v1 event maps to |
| `class_dhcp_activity.json`, `class_authentication.json` | identity-source event classes |
| `object_*.json` | objects those classes use (`network_endpoint`, `network_connection_info`, `network_traffic`, `metadata`, `product`, `user`, `device`, `endpoint`) |
| `category_network.json` | category 4 |

Enum values used by the mapper are taken from these files, not from memory:
`activity_id` 1 Open, 2 Close, 3 Reset, 4 Fail, 5 Refuse, 6 Traffic;
`action_id` 1 Allowed, 2 Denied; `disposition_id` 1 Allowed, 2 Blocked, 6 Dropped;
`severity_id` 1..6 Informational..Fatal. `type_uid = class_uid*100 + activity_id`.
DHCP Activity (4004): `activity_id` 5 Ack, 7 Release (1 is Discover, not Assign). Refresh only through a contract PR; the golden events depend on these values.
