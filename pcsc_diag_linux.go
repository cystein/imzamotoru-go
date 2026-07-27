//go:build linux

package main

// pcscTeshisi Linux geliştirme derlemesinde uygulanmadı — saha teşhisi yalnızca Windows'ta
// gerekli (bkz. pcsc_diag_windows.go). Linux build'in bildir() çağrısında bir sonuç üretebilmesi
// için boş bir yanıt döner.
func pcscTeshisi() string {
	return "PC/SC teşhisi bu platformda uygulanmadı"
}
