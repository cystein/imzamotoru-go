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
func bildir(seviye Seviye, kod string, mesaj string) {
	log.Printf("[%s][%s] %s", seviye, kod, mesaj)

	if mDurum != nil {
		switch seviye {
		case SeviyeKritik:
			mDurum.SetTitle(fmt.Sprintf("⛔ %s", mesaj))
			systray.SetTooltip(fmt.Sprintf("%s — ⛔ %s", APP_NAME, mesaj))
		case SeviyeUyari:
			mDurum.SetTitle(fmt.Sprintf("⚠️ %s", mesaj))
			systray.SetTooltip(fmt.Sprintf("%s — ⚠️ %s", APP_NAME, mesaj))
		default:
			mDurum.SetTitle(fmt.Sprintf("Durum: Çalışıyor (v%s)", APP_VERSION))
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
