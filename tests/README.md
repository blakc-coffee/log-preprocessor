# Packaging integration tests

`lossless_test.go` and `merkle_test.go` exercise the real durable vault on
Unix, where its `flock` implementation is supported. Windows reports these as
an explicit platform skip through build constraints; run the Linux container
for the release gate.

`replay_test.go` pins the 500-record Palo Alto fixture, validates the reference
parser YAML, and defines the exact real-system acceptance helper. It does not
use a mock or report an integration pass. Once `pkg/dataplane/app`, quarantine,
registry, and replay merge, a small adapter must invoke
`assertPaloAltoReplay` against those real components.

