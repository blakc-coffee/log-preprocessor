# Shared sink mapping

This internal package reads common fields from nested or dotted OCSF paths and
returns a typed projection. It never mutates the normalized event and keeps
remaining fields available to lossless exporter-specific payloads.

