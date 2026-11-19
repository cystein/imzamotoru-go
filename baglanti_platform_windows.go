//go:build windows

package main

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

// gercekGozlemciFabrikasi: Windows ağ gözlemcisi (baglanti_gozlemci_windows.go). Henüz yazılmadı —
// yazılana kadar modül "desteklenmiyor" der (imza akışı etkilenmez).
func gercekGozlemciFabrikasi() func(t *btTest) btGozlemci { return nil }

func isletimSistemiBilgisi() map[string]any {
	v := windows.RtlGetVersion()
	return map[string]any{"ad": "windows", "surum": fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber), "mimari": runtime.GOARCH}
}
