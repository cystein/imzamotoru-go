//go:build linux

package main

import (
	"runtime"

	"golang.org/x/sys/unix"
)

func isletimSistemiBilgisi() map[string]any {
	surum := ""
	var u unix.Utsname
	if unix.Uname(&u) == nil {
		surum = unix.ByteSliceToString(u.Release[:])
	}
	return map[string]any{"ad": "linux", "surum": surum, "mimari": runtime.GOARCH}
}
