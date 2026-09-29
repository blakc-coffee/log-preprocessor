//go:build linux

package source

import (
	"os"
	"strconv"
	"strings"
)

// kernelUDPDrops reads Udp: RcvbufErrors from /proc/net/snmp.
//
// This is the count of datagrams the kernel discarded because a receive buffer
// was full — traffic that reached the machine and never reached this process.
// It is process-wide rather than per-socket, which is the granularity the
// kernel offers; on a host running only ingestd that is the number that
// matters.
func kernelUDPDrops() (int64, bool) {
	raw, err := os.ReadFile("/proc/net/snmp")
	if err != nil {
		return 0, false
	}
	lines := strings.Split(string(raw), "\n")
	for i := 0; i+1 < len(lines); i++ {
		if !strings.HasPrefix(lines[i], "Udp:") {
			continue
		}
		keys := strings.Fields(lines[i])
		values := strings.Fields(lines[i+1])
		for j, k := range keys {
			if k == "RcvbufErrors" && j < len(values) {
				n, err := strconv.ParseInt(values[j], 10, 64)
				return n, err == nil
			}
		}
	}
	return 0, false
}
