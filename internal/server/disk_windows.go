//go:build windows

package server

// diskUsage remains unavailable on Windows until Warden has a native volume
// sampler. Returning an empty pair keeps the monitor and alert engine explicit:
// disk percentage is zero instead of preventing the server from building.
func diskUsage(string) usagePair { return usagePair{} }
