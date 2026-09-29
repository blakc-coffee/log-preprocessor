# Packaging integration tests

`lossless_test.go` and `merkle_test.go` exercise the real durable vault on
Unix, where its `flock` implementation is supported. Windows reports these as
an explicit platform skip through build constraints; run the Linux container
for the release gate.

Replay tests depend on `pkg/dataplane/app`, quarantine, registry, and replay.
Those packages are not present on `feature/packaging` yet, so no mock test is
presented as an integration pass. Add `replay_test.go` when the data-plane
branch is merged.

