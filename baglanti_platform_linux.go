//go:build linux

package main

import "runtime"

// Linux'ta gerçek gözlemci yok (saha Windows); yalnız --simule.
func gercekGozlemciFabrikasi() func(t *btTest) btGozlemci { return nil }

func isletimSistemiBilgisi() map[string]any {
	return map[string]any{"ad": "linux", "surum": "", "mimari": runtime.GOARCH}
}
