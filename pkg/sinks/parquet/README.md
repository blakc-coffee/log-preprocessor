# Parquet lake sink

This package owns typed row projection, UTC date/vendor partitioning, rollover,
and atomic publication (`.tmp` + fsync + rename + directory fsync).

The repository owner has not yet pinned `github.com/parquet-go/parquet-go` in
`go.mod`, which is outside this workstream's ownership. `New` therefore requires
an `Encoder` that emits valid Apache Parquet. It intentionally has no JSON or
proprietary fallback carrying a misleading `.parquet` suffix. Once the module
is pinned, the production adapter should select zstd compression, 128k row
groups, and dictionary encoding for the low-cardinality columns listed in the
packaging PRD.

Lake consumers must deduplicate by `event_id`, keeping the newest
`parser_version` where replay creates multiple immutable rows.

