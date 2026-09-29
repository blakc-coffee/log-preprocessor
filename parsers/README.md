# Built-in parsers

The frozen built-in parser documents are embedded from `contracts/dsl/examples/` and activated by `cmd/dataplane` on first start. Approved versions are written to `data/parsers.d/<id>/<version>.yaml`; the adjacent `active` file is the sole activation pointer.

This directory is reserved for deployment-specific parser documents. Keeping the frozen examples under `contracts/` prevents runtime copies from drifting away from the conformance suite.
