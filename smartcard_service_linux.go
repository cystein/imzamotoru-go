//go:build linux

package main

// smartcard_service_windows.go'nun Linux karşılığı — Linux'ta Windows servis yöneticisi
// kavramı yok, bu yüzden hep no-op döner.
func scardSvrBaslatmayiDene() (basarili bool, detay string) {
	return false, "Bu platformda uygulanmadı"
}
