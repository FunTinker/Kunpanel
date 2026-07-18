//go:build !windows

package main

import "syscall"

func diskPercent(path string) float64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil || st.Blocks == 0 {
		return 0
	}
	return round2(float64(st.Blocks-st.Bavail) / float64(st.Blocks) * 100)
}
