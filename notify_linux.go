//go:build linux

package main

import "log"

// Seviye, bildir() olaylarının önem derecesidir.
type Seviye string

const (
	SeviyeBilgi  Seviye = "Bilgi"
	SeviyeUyari  Seviye = "Uyari"
	SeviyeKritik Seviye = "Kritik"
)

// bildir, Linux geliştirme derlemesinde sadece loglar — sistem tepsisi ve uzak sunucuya
// bildirim Windows'a özgüdür (bkz. notify_windows.go); Linux tarafı zaten sadece yerel
// test/geliştirme amaçlı, saha dağıtımı Windows exe üzerinden yapılıyor.
func bildir(seviye Seviye, kod string, mesaj string) {
	log.Printf("[%s][%s] %s", seviye, kod, mesaj)
}
