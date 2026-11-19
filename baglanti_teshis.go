package main

// Saha doğrulaması için teşhis modu (test matrisi, PROTOKOL §12'nin gerçek donanım karşılığı):
//   KolitakipIMZA-teshis.exe --teshis [--hedef 81.214.22.92] [--sure 900] [--son-izleme 60]
// Gerçek Windows gözlemcisini çalıştırır, olayları ekrana canlı yazar, Enter'a basılınca testi bitirir
// ve raporu (sunucuya GÖNDERMEDEN) masaüstüne kaydeder. Kurulu KolitakipIMZA'ya ve porta dokunmaz.

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type teshisIstemci struct {
	mu     sync.Mutex
	bitti  chan map[string]any
	sonYaz time.Time
}

func (c *teshisIstemci) Yaz(v any) error {
	m, _ := v.(map[string]any)
	if m == nil {
		b, _ := json.Marshal(v)
		json.Unmarshal(b, &m)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	saat := time.Now().Format("15:04:05")
	switch m["tip"] {
	case "on_kontrol":
		b, _ := json.MarshalIndent(m["on_kontrol"], "  ", "  ")
		fmt.Printf("\n[%s] ÖN KONTROL  engeller=%v\n  %s\n\n", saat, m["engeller"], b)
		fmt.Println(">>> İzleme başladı. Test adımını şimdi yapın. Bitirmek için Enter'a basın. <<<")
	case "olay":
		o, _ := m["olay"].(btOlay)
		if o.Kod == "" {
			b, _ := json.Marshal(m["olay"])
			json.Unmarshal(b, &o)
		}
		fmt.Printf("[%s] +%6.1f sn  %-26s %v\n", saat, float64(o.MonoMs)/1000, o.Kod, o.Veri)
	case "durum":
		if time.Since(c.sonYaz) >= 5*time.Second {
			c.sonYaz = time.Now()
			fmt.Printf("[%s]   durum: kart=%v ag_gecidi=%v (arp=%v tcp=%v) kart_kapali=%vms ag_kayip=%vms asama=%v\n",
				saat, m["kart"], m["ag_gecidi"], m["arp"], m["tcp"], m["kart_kapali_suresi_ms"], m["ag_gecidi_kayip_suresi_ms"], m["asama"])
		}
	case "rapor_durumu":
		if d := m["durum"]; d == "vazgecildi" || d == "gonderildi" || d == "reddedildi" {
			c.bitti <- m
		}
	case "hata":
		fmt.Printf("[%s] HATA %v: %v\n", saat, m["kod"], m["mesaj"])
		c.bitti <- m
	}
	return nil
}

func teshisCalistir(args []string) {
	fs := flag.NewFlagSet("teshis", flag.ExitOnError)
	hedef := fs.String("hedef", "81.214.22.92", "yol ölçümü için sunucu IPv4'ü")
	sure := fs.Int("sure", 900, "azami izleme süresi (sn)")
	sonIzleme := fs.Int("son-izleme", 60, "Enter'dan sonra izleme süresi (sn)")
	fs.Parse(args)

	fab := gercekGozlemciFabrikasi()
	if fab == nil {
		fmt.Println("Bu platformda gerçek gözlemci yok (yalnız Windows). Simülatör için --simule kullanın.")
		return
	}
	gon := yeniBtGonderici(false, 1)
	if f, err := os.OpenFile(filepath.Join(gon.dizin, "teshis.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err == nil {
		log.SetOutput(f) // ayrıntılı günlük dosyaya; ekranda yalnız okunabilir özet
		defer f.Close()
	}
	btYon = &btYonetici{aboneler: map[btIstemci]string{}, saatHizi: 1, gozlemci: fab, gonderici: gon,
		hedefler: map[string]string{"canli": ""}} // boş hedef: rapor gönderilmez, yalnız arşivlenir
	c := &teshisIstemci{bitti: make(chan map[string]any, 4)}
	id := "teshis_" + time.Now().Format("20060102_150405")
	istek, _ := json.Marshal(map[string]any{"modul": btModul, "protokol": btProtokol, "tip": "test_basla", "test_id": id,
		"nonce": "teshis-" + fmt.Sprint(time.Now().UnixNano()), "olcum_hedefi": *hedef, "beklenen_baglanti": "modem",
		"rapor_hedefi": "canli", "parametreler": map[string]any{"test_azami_suresi_ms": *sure * 1000, "son_izleme_suresi_ms": *sonIzleme * 1000}})
	fmt.Printf("KolitakipIMZA %s — bağlantı testi teşhis modu (test: %s)\nÖn kontrol yapılıyor...\n", APP_VERSION, id)
	btYon.mesajIsle(c, istek)

	go func() {
		bufio.NewReader(os.Stdin).ReadString('\n')
		fmt.Printf("\n>>> Bitirildi. %d sn daha izleniyor (son izleme)... <<<\n", *sonIzleme)
		btYon.mesajIsle(c, []byte(fmt.Sprintf(`{"modul":"%s","protokol":%d,"tip":"test_bitir","test_id":"%s"}`, btModul, btProtokol, id)))
	}()
	<-c.bitti

	// Arşivlenen raporu masaüstüne kopyala.
	girdiler, _ := filepath.Glob(filepath.Join(gon.dizin, "raporlar", "*_"+id+".json"))
	masaustu := filepath.Join(os.Getenv("USERPROFILE"), "Desktop")
	if st, err := os.Stat(masaustu); err != nil || !st.IsDir() {
		masaustu, _ = os.Getwd()
	}
	for _, g := range girdiler {
		b, _ := os.ReadFile(g)
		hedefYol := filepath.Join(masaustu, "kolitakip_baglanti_"+strings.TrimPrefix(id, "teshis_")+".json")
		if os.WriteFile(hedefYol, b, 0644) == nil {
			fmt.Printf("\nRapor kaydedildi: %s\nBu dosyayı Kolitakip'e gönderin.\n", hedefYol)
		}
	}
	fmt.Println("Kapatmak için Enter'a basın.")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
