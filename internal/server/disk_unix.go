//go:build !windows

package server

import "syscall"

func diskUsage(root string) usagePair {
	var result usagePair
	var stat syscall.Statfs_t
	if syscall.Statfs(root, &stat) == nil {
		result.Total = stat.Blocks * uint64(stat.Bsize)
		free := stat.Bavail * uint64(stat.Bsize)
		result.Used = result.Total - free
	}
	return result
}
