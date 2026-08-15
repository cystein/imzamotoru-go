//go:build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// scardSvrBaslatmayiDene, Windows'un Akıllı Kart Kaynak Yöneticisi (SCardSvr) servisi
// çalışmıyor görünüyorsa başlatmayı dener. Bu servis normalde bir okuyucu USB'ye takılınca
// Windows tarafından kendiliğinden ("trigger start") başlatılır — çalışmıyor olması genelde
// "şu an hiçbir okuyucu takılı değil" ya da "Hızlı Başlatma sonrası donanım durumu bayatlamış"
// anlamına gelir (bkz. pcsc_diag_windows.go, PcscKaynakYoneticisiKapali). Bu fonksiyon yönetici
// izni GEREKTİREBİLİR — başarısız olursa sessizce false döner, çağıran taraf zaten var olan
// "okuyucunuzu takıp bilgisayarı yeniden başlatın" mesajını göstermeye devam eder. Kaybedecek
// bir şey yok: servis zaten çalışıyorsa ya da okuyucu gerçekten takılı değilse bu deneme
// hiçbir şeyi bozmaz.
func scardSvrBaslatmayiDene() (basarili bool, detay string) {
	m, err := mgr.Connect()
	if err != nil {
		return false, fmt.Sprintf("SCM'ye bağlanılamadı (muhtemelen yetki yetersiz): %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService("SCardSvr")
	if err != nil {
		return false, fmt.Sprintf("SCardSvr servisi açılamadı: %v", err)
	}
	defer s.Close()

	durum, err := s.Query()
	if err == nil && durum.State == svc.Running {
		return true, "SCardSvr zaten çalışıyor"
	}

	if err := s.Start(); err != nil {
		return false, fmt.Sprintf("SCardSvr başlatılamadı: %v", err)
	}
	return true, "SCardSvr başlatma isteği gönderildi"
}
