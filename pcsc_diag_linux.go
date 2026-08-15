//go:build linux

package main

// pcsc_diag_windows.go ile aynı tip — Linux tarafında da tanımlı olması gerekiyor ki main.go
// hangi platformda derlenirse derlensin aynı imzayı kullanabilsin.
type PcscKategori int

const (
	PcscBilinmiyor PcscKategori = iota
	PcscKaynakYoneticisiKapali
	PcscOkuyucuYok
	PcscOkuyucuVarSurucuGerekli
)

// pcscTeshisi Linux geliştirme derlemesinde uygulanmadı — saha teşhisi yalnızca Windows'ta
// gerekli (bkz. pcsc_diag_windows.go). Linux build'in bildir() çağrısında bir sonuç üretebilmesi
// için boş bir yanıt döner.
func pcscTeshisi() (PcscKategori, string) {
	return PcscBilinmiyor, "PC/SC teşhisi bu platformda uygulanmadı"
}
