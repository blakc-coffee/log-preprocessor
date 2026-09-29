//go:build !linux && !darwin

package source

// getRecvBuffer is unavailable on this platform. Windows is unsupported
// anyway (no flock, no directory fsync), and reporting zero simply skips the
// clamp warning rather than failing to start.
func getRecvBuffer(uintptr) (int, error) { return 0, nil }
