# OCSF NDJSON

The exporter clones the OCSF object, adds lineage metadata, and writes one
object per line. Event IDs are deduplicated for the lifetime of the sink. Raw
vault bytes are disabled by default and, when explicitly enabled, remain
byte-exact through base64 encoding.

