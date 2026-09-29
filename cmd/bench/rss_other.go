//go:build !linux && !windows

package main

func peakRSS() (int64, string) { return fallbackMemory() }
