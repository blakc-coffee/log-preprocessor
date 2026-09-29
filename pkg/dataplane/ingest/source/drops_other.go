//go:build !linux

package source

// kernelUDPDrops is Linux-only: /proc/net/snmp is where the counter lives, and
// there is no portable equivalent. Reporting "unavailable" rather than zero
// matters — a hard zero would read as "no drops" on a platform that simply
// cannot tell, which is exactly the kind of quiet false assurance the UDP
// documentation is at pains to avoid.
func kernelUDPDrops() (int64, bool) { return 0, false }
