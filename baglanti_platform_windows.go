//go:build windows

package main

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

func isletimSistemiBilgisi() map[string]any {
	v := windows.RtlGetVersion()
	return map[string]any{"ad": "windows", "surum": fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber), "mimari": runtime.GOARCH}
}
