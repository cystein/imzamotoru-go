//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/getlantern/systray"
)

// Seviye, bildir() olaylarının önem derecesidir.
type Seviye string

const (
	SeviyeBilgi  Seviye = "Bilgi"
	SeviyeUyari  Seviye = "Uyari"
	SeviyeKritik Seviye = "Kritik"
)

// mDurum, onTrayReady() içinde local scope'ta oluşturuluyordu; bildir()'in tepsi menüsünü
// dışarıdan (farklı goroutine'lerden — cardWorker, update kontrolü) güncelleyebilmesi için
// paket seviyesine taşındı. onTrayReady() atar, bildir() okur/günceller.
var mDurum *systray.MenuItem

// bildirHttpClient, olay-bildir POST'u için ayrı, kısa zaman aşımlı bir istemçi — main.go'daki
// httpClient (30sn) PDF indirme/yükleme gibi daha uzun işlerle meşgul olabilir; bir bildirim
// bunları beklemeden/engellemeden gitmeli.
var bildirHttpClient = &http.Client{Timeout: 8 * time.Second}

type olayBildirimi struct {
	Seviye   string `json:"seviye"`
	Kod      string `json:"kod"`
	Mesaj    string `json:"mesaj"`
	Surum    string `json:"surum"`
	ZamanUTC string `json:"zaman_utc"`
}

// bildir, uygulama genelinde TEK merkezi olay bildirim noktasıdır:
//  1. Her zaman yerel loga yazar.
//  2. Uyarı/Kritik seviyede sistem tepsisi başlığını ve tooltip'ini kalıcı olarak günceller —
//     eczacı programın simgesinin üzerine gelip "neden imza atamıyorum" sorusuna hemen cevap
//     bulabilsin diye (programda arayüz penceresi yok, tek görünür yüzey tepsi ikonu).
//  3. Uyarı/Kritik seviyedeki olayları NODE_API_URL + /imza-motoru/olay-bildir adresine POST
//     eder — bizim aday listemizde olmayan bir sürücü/okuyucu ya da bir güvenlik olayından
//     (sahte güncelleme reddi gibi) haberimiz olsun, saha genelinde toplu güncelleme kararı
//     alabilelim diye. Bilgi seviyesi (ör. sürücü sonradan başarıyla bağlandı) sadece loglanır,
//     sunucuya gönderilmez — gürültü olmasın diye.
//
// tepsiIcinKisalt, tepsi menüsü başlığını/bildirim balonunu taşırıp tasarımı bozan uzun
// mesajları kısaltır (ör. PC/SC teşhisli sürücü hataları kolayca 200+ karakter oluyordu).
// Tam detay zaten app.log'a ve bildir()'in kendi POST'uyla sunucuya gidiyor — tepside kısa
// bir özet yeterli. rune bazlı kesiliyor ki Türkçe karakterler (ç, ğ, ı, ş, ü) bölünmesin.
func tepsiIcinKisalt(mesaj string, maxRune int) string {
	r := []rune(mesaj)
	if len(r) <= maxRune {
		return mesaj
	}
	return string(r[:maxRune]) + "…"
}

func bildir(seviye Seviye, kod string, mesaj string) {
	log.Printf("[%s][%s] %s", seviye, kod, mesaj)

	if mDurum != nil {
		kisaMesaj := tepsiIcinKisalt(mesaj, 80)
		switch seviye {
		case SeviyeKritik:
			mDurum.SetTitle(fmt.Sprintf("⛔ %s", kisaMesaj))
			systray.SetTooltip(fmt.Sprintf("%s v%s — ⛔ %s", APP_NAME, APP_VERSION, kisaMesaj))
		case SeviyeUyari:
			mDurum.SetTitle(fmt.Sprintf("⚠️ %s", kisaMesaj))
			systray.SetTooltip(fmt.Sprintf("%s v%s — ⚠️ %s", APP_NAME, APP_VERSION, kisaMesaj))
		default:
			// Sürüm bilgisi artık ayrıca sabit bir tepsi menü satırında (mSurum, bkz.
			// main_windows.go) HER durumda görünür kalıyor — burada tekrar etmeye gerek yok.
			mDurum.SetTitle("Durum: Çalışıyor")
			systray.SetTooltip(fmt.Sprintf("%s çalışıyor (v%s)", APP_NAME, APP_VERSION))
		}
	}

	if seviye == SeviyeBilgi {
		return
	}

	go func() {
		govde, _ := json.Marshal(olayBildirimi{
			Seviye:   string(seviye),
			Kod:      kod,
			Mesaj:    mesaj,
			Surum:    APP_VERSION,
			ZamanUTC: time.Now().UTC().Format(time.RFC3339),
		})
		resp, err := bildirHttpClient.Post(NODE_API_URL+"/imza-motoru/olay-bildir", "application/json", bytes.NewReader(govde))
		if err != nil {
			log.Printf("⚠️ [BİLDİR] Uzak sunucuya olay bildirilemedi: %v", err)
			return
		}
		defer resp.Body.Close()
	}()
}
