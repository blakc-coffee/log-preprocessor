//go:build linux || darwin

package source

import "syscall"

// getRecvBuffer reads the socket's effective SO_RCVBUF.
//
// Linux reports double what was requested, because the value includes the
// kernel's own bookkeeping overhead. That is reported as-is rather than
// halved: the point of the number is to notice a clamp, and inventing an
// adjustment would make the logged value disagree with what `ss -m` shows.
func getRecvBuffer(fd uintptr) (int, error) {
	return syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
}
