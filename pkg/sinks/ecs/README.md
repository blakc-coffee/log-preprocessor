# ECS exporter

The exporter targets the ECS 8 field model and emits a checked subset as NDJSON
or Elasticsearch bulk NDJSON. ULPF lineage is stored under `labels.ulpf_*`.
Raw vault bytes are excluded unless explicitly enabled and are then exported as
base64 without decoding or normalization.

There is no official offline ECS validator in the runtime. Tests validate the
checked-in field allowlist and value types.

