//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

func peakRSS() (int64, string) {
	b, err := os.ReadFile("/proc/self/status")
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "VmHWM:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					kb, parseErr := strconv.ParseInt(fields[1], 10, 64)
					if parseErr == nil {
						return kb * 1024, "/proc/self/status VmHWM"
					}
				}
			}
		}
	}
	return fallbackMemory()
}
