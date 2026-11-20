//go:build windows

package main

// v2.0.3: Kendini otomatik güncelleyen kurulumlarda Windows'un "Yüklü uygulamalar" listesi ve Başlat
// menüsü eski adı/sürümü göstermeye devam ediyordu, çünkü otomatik güncelleme yalnız exe'yi değiştirir,
// Setup'ı (kayıt defteri kaydını, kısayolları yazan) hiç çalıştırmaz. Program her açılışta:
//   - kendi kaldırma kaydında (HKCU\...\Uninstall\{AppId}_is1, yönetici gerekmez) DisplayName'i
//     "Kolitakip Asistan", DisplayVersion'ı gerçek sürüm yapar — kayıt YOKSA oluşturmaz (Setup'sız
//     kopyalar listeye sahte kayıt eklemesin), kayıt başka klasördeki bir kuruluma aitse dokunmaz;
//   - Başlat menüsündeki eski "KolitakipIMZA" kısayolunu "Kolitakip Asistan" adıyla taşır.
// Otomatik güncelleme ve kaldırma bunlardan etkilenmez: ikisi de AppId'ye ve exe yoluna bağlı.

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const kaldirmaKaydi = `Software\Microsoft\Windows\CurrentVersion\Uninstall\{A4F72625-6C55-4645-B0B3-45AC71C607C9}_is1`

func kurulumKaydiniGuncelle() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[KURULUM] kayıt güncellemesi çöktü: %v", r)
		}
	}()
	exe, err := os.Executable()
	if err != nil {
		return
	}
	exeKlasoru := filepath.Dir(exe)

	k, err := registry.OpenKey(registry.CURRENT_USER, kaldirmaKaydi, registry.QUERY_VALUE|registry.SET_VALUE)
	if err == nil {
		konum, _, _ := k.GetStringValue("InstallLocation")
		if konum == "" || strings.EqualFold(filepath.Clean(konum), filepath.Clean(exeKlasoru)) {
			for ad, deger := range map[string]string{"DisplayName": APP_GORUNEN_AD, "DisplayVersion": APP_VERSION} {
				if eski, _, _ := k.GetStringValue(ad); eski != deger {
					if err := k.SetStringValue(ad, deger); err == nil {
						log.Printf("[KURULUM] kaldırma kaydı: %s %q → %q", ad, eski, deger)
					}
				}
			}
		}
		k.Close()
	}

	// Başlat menüsü: %APPDATA%\Microsoft\Windows\Start Menu\Programs\KolitakipIMZA\KolitakipIMZA.lnk
	programlar := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs")
	eskiKlasor := filepath.Join(programlar, "KolitakipIMZA")
	eskiKisayol := filepath.Join(eskiKlasor, "KolitakipIMZA.lnk")
	yeniKlasor := filepath.Join(programlar, APP_GORUNEN_AD)
	yeniKisayol := filepath.Join(yeniKlasor, APP_GORUNEN_AD+".lnk")
	if os.Getenv("APPDATA") == "" {
		return
	}
	if _, err := os.Stat(eskiKisayol); err == nil {
		if _, err := os.Stat(yeniKisayol); err == nil {
			os.Remove(eskiKisayol) // yeni Setup zaten yenisini kurmuş
		} else if os.MkdirAll(yeniKlasor, 0755) == nil {
			if err := os.Rename(eskiKisayol, yeniKisayol); err == nil {
				log.Printf("[KURULUM] Başlat menüsü kısayolu yeniden adlandırıldı: %s", yeniKisayol)
			}
		}
		os.Remove(eskiKlasor) // boşsa siler, değilse dokunmaz
	}
}
