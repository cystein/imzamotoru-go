package main

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// Sunucu tarafının yapacağı doğrulamanın aynısı: imza, gelen ham baytlar üzerinden.
type sahteSunucu struct {
	mu       sync.Mutex
	raporlar []map[string]any
	hatalar  []string
}

func (s *sahteSunucu) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	var istek struct {
		TestID    string `json:"test_id"`
		AnahtarNo int    `json:"anahtar_no"`
		GovdeB64  string `json:"govde_b64"`
		Imza      string `json:"imza"`
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := json.Unmarshal(b, &istek); err != nil {
		s.hatalar = append(s.hatalar, "json: "+err.Error())
		w.WriteHeader(400)
		return
	}
	govde, err := base64.StdEncoding.DecodeString(istek.GovdeB64)
	if err != nil {
		s.hatalar = append(s.hatalar, "b64")
		w.WriteHeader(400)
		return
	}
	var rapor map[string]any
	json.Unmarshal(govde, &rapor)
	nonce, _ := rapor["nonce"].(string)
	beklenen := btImza([]byte(btTestAnahtari), nonce, govde)
	if !hmac.Equal([]byte(beklenen), []byte(istek.Imza)) || istek.AnahtarNo != 0 {
		s.hatalar = append(s.hatalar, "imza tutmuyor")
		w.WriteHeader(401)
		return
	}
	if len(istek.GovdeB64) > btAzamiGovdeB64 {
		s.hatalar = append(s.hatalar, "gövde sınırı aşıldı")
	}
	s.raporlar = append(s.raporlar, rapor)
	w.Write([]byte(`{"ok":true}`))
}

type senaryoBeklentisi struct {
	olaylar     []string // raporda olması gereken olay kodları
	olmamali    []string
	engel       string
	acilma      int64 // ilk kesintinin açılma aralığı (±1500 ms); -1 = bakma
	raporTuru   string
	kalpKesilir bool
}

var beklentiler = map[string]senaryoBeklentisi{
	"d1_modem_guc":          {olaylar: []string{"kart_dustu", "kart_geldi", "ag_gecidi_kayip", "ag_gecidi_geri", "son_izleme_bitti"}, acilma: 40000, raporTuru: "nihai"},
	"d2_kablo_cek":          {olaylar: []string{"kart_dustu", "kart_geldi", "ag_gecidi_geri"}, acilma: 1000, raporTuru: "nihai"},
	"d3_wifi_kes":           {olaylar: []string{"kart_dustu", "kart_geldi"}, acilma: 2000, raporTuru: "nihai"},
	"d3b_kart_devre_disi":   {olaylar: []string{"kart_dustu"}, acilma: 2000, raporTuru: "nihai"},
	"d4_router_arkasi":      {olaylar: []string{"ag_gecidi_hic_kaybolmadi", "upnp_baglanti_durumu"}, olmamali: []string{"ag_gecidi_kayip", "kart_dustu"}, acilma: -1, raporTuru: "nihai"},
	"d5_hotspot_ucus":       {olaylar: []string{"kart_dustu", "ag_gecidi_geri"}, engel: "HOTSPOT_IPUCU", acilma: 4000, raporTuru: "nihai"},
	"d5b_usb_rndis":         {olaylar: []string{"kart_dustu"}, engel: "HOTSPOT_IPUCU", acilma: 2000, raporTuru: "nihai"},
	"d6_vpn":                {olaylar: []string{"kart_dustu"}, engel: "VPN_VARSAYILAN_YOLDA", acilma: 1000, raporTuru: "nihai"},
	"d6_coklu_kart":         {olaylar: []string{"yol_degisti", "ag_gecidi_hic_kaybolmadi"}, engel: "COKLU_AKTIF_ARAYUZ", acilma: -1, raporTuru: "nihai"},
	"d6_uyku":               {olaylar: []string{"uyku", "uyanma", "yoklama_boslugu"}, acilma: -1, raporTuru: "nihai"},
	"d6_program_kapatildi":  {olaylar: []string{"kart_dustu", "program_yeniden_baslatildi"}, acilma: -1, raporTuru: "yarim", kalpKesilir: true},
	"son_izleme_dalgalanma": {olaylar: []string{"son_izleme_basladi", "ag_gecidi_kayip", "son_izleme_bitti"}, acilma: 40000, raporTuru: "nihai"},
	"rapor_kuyrukta":        {olaylar: []string{"kart_dustu"}, acilma: 1000, raporTuru: "nihai"},
	"upnp_sifirlandi":       {olaylar: []string{"upnp_uptime_sifirlandi"}, olmamali: []string{"upnp_dis_ip_degisti"}, acilma: 40000, raporTuru: "nihai"},
	"upnp_dis_ip_degisti":   {olaylar: []string{"upnp_uptime_sifirlandi", "upnp_dis_ip_degisti"}, acilma: 40000, raporTuru: "nihai"},
}

func TestSimulatorSenaryolari(t *testing.T) {
	if len(beklentiler) != len(simSenaryolar) {
		t.Fatalf("her senaryonun beklentisi olmalı: %d beklenti, %d senaryo", len(beklentiler), len(simSenaryolar))
	}
	const hiz = 50.0
	for ad := range simSenaryolar {
		ad := ad
		t.Run(ad, func(t *testing.T) { senaryoyuCalistir(t, ad, hiz) })
	}
}

func senaryoyuCalistir(t *testing.T, ad string, hiz float64) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	s := simSenaryolar[ad]
	sunucu := &sahteSunucu{}
	raporSrv := httptest.NewServer(sunucu)
	defer raporSrv.Close()

	gon := yeniBtGonderici(true, hiz)
	btYon = &btYonetici{aboneler: map[btIstemci]string{}, saatHizi: hiz, simulasyon: ad, gonderici: gon,
		hedefler: map[string]string{"canli": raporSrv.URL}}
	btYon.gozlemci = func(tt *btTest) btGozlemci {
		gon.simHata = s.simHata
		return &simGozlemci{s: s, saat: func() *btSaat { return tt.saat }, bitirFn: func() {
			select {
			case tt.bitirC <- "test_bitir":
			default:
			}
		}}
	}
	wsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { wsIsleyici(w, r, true) }))
	defer wsSrv.Close()
	h := http.Header{}
	h.Set("Origin", "https://sgkkolitakip.web.tr")
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(wsSrv.URL, "http")+"/ws", h)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	c.WriteJSON(map[string]any{"modul": "baglanti_testi", "protokol": 1, "tip": "merhaba"})
	c.WriteJSON(map[string]any{"modul": "baglanti_testi", "protokol": 1, "tip": "test_basla", "test_id": "t_" + ad,
		"nonce": "nonce-" + ad + "-0123456789", "olcum_hedefi": "203.0.113.10", "beklenen_baglanti": "modem",
		"rapor_hedefi": "canli", "parametreler": map[string]any{"son_izleme_suresi_ms": 30000}})
	// İkinci test reddedilmeli
	c.WriteJSON(map[string]any{"modul": "baglanti_testi", "protokol": 1, "tip": "test_basla", "test_id": "t_ikinci_test",
		"nonce": "nonce-ikinci-0123456789", "olcum_hedefi": "203.0.113.10", "beklenen_baglanti": "modem", "rapor_hedefi": "canli"})

	var engeller []any
	var sonDurum time.Time
	enUzunBosluk := time.Duration(0)
	ikinciReddedildi, durumSayisi := false, 0
	bitis := time.Now().Add(30 * time.Second)
	c.SetReadDeadline(bitis)
	for {
		var m map[string]any
		if err := c.ReadJSON(&m); err != nil {
			t.Fatalf("okuma: %v (rapor gelmedi)", err)
		}
		switch m["tip"] {
		case "on_kontrol":
			engeller, _ = m["engeller"].([]any)
		case "hata":
			if m["kod"] == "TEST_ZATEN_CALISIYOR" {
				ikinciReddedildi = true
			} else {
				t.Errorf("beklenmeyen hata: %v", m)
			}
		case "durum":
			durumSayisi++
			if !sonDurum.IsZero() {
				if b := time.Since(sonDurum); b > enUzunBosluk {
					enUzunBosluk = b
				}
			}
			sonDurum = time.Now()
		}
		if m["tip"] == "rapor_durumu" && m["durum"] == "hazirlaniyor" && !sonDurum.IsZero() {
			if b := time.Since(sonDurum); b > enUzunBosluk { // son kalp atışından rapora kadar
				enUzunBosluk = b
			}
			sonDurum = time.Time{}
		}
		if m["tip"] == "rapor_durumu" && (m["durum"] == "gonderildi" || m["durum"] == "reddedildi" || m["durum"] == "vazgecildi") {
			if m["durum"] != "gonderildi" {
				t.Fatalf("rapor gönderilemedi: %v; sunucu hataları: %v", m, sunucu.hatalar)
			}
			break
		}
	}
	if !ikinciReddedildi {
		t.Error("ikinci test_basla reddedilmedi")
	}
	if durumSayisi < 5 {
		t.Errorf("çok az kalp atışı: %d", durumSayisi)
	}
	durumAraligi := time.Duration(float64(time.Second) / hiz)
	if b := beklentiler[ad]; b.kalpKesilir != (enUzunBosluk > 3*durumAraligi+20*time.Millisecond) {
		t.Errorf("kalp atışı boşluğu %v (aralık %v), kesilmesi bekleniyor mu: %v", enUzunBosluk, durumAraligi, b.kalpKesilir)
	}

	sunucu.mu.Lock()
	defer sunucu.mu.Unlock()
	if len(sunucu.hatalar) > 0 || len(sunucu.raporlar) != 1 {
		t.Fatalf("sunucu: %d rapor, hatalar %v", len(sunucu.raporlar), sunucu.hatalar)
	}
	r := sunucu.raporlar[0]
	b := beklentiler[ad]
	if r["rapor_turu"] != b.raporTuru {
		t.Errorf("rapor_turu %v, beklenen %s", r["rapor_turu"], b.raporTuru)
	}
	if exe := r["exe"].(map[string]any); exe["simulasyon"] != ad {
		t.Errorf("exe.simulasyon = %v", exe["simulasyon"])
	}
	kodlar := map[string]bool{}
	for _, o := range r["olaylar"].([]any) {
		kodlar[o.(map[string]any)["kod"].(string)] = true
	}
	for _, k := range b.olaylar {
		if !kodlar[k] {
			t.Errorf("olay eksik: %s (olanlar: %v)", k, kodlar)
		}
	}
	for _, k := range b.olmamali {
		if kodlar[k] {
			t.Errorf("olmaması gereken olay: %s", k)
		}
	}
	if b.engel != "" {
		bulundu := false
		for _, e := range engeller {
			bulundu = bulundu || e == b.engel
		}
		if !bulundu {
			t.Errorf("engel %s yok: %v", b.engel, engeller)
		}
	}
	if b.acilma >= 0 {
		kes, _ := r["kesintiler"].([]any)
		if len(kes) == 0 {
			t.Fatalf("kesinti yok")
		}
		a, _ := kes[0].(map[string]any)["acilma_araligi_ms"].(float64)
		if d := int64(a) - b.acilma; d < -1500 || d > 1500 {
			t.Errorf("açılma aralığı %v ms, beklenen ~%d", a, b.acilma)
		}
	}
	t.Logf("%s: %d olay, açılma=%v, en uzun kalp boşluğu %v", ad, len(r["olaylar"].([]any)),
		func() any {
			if k, _ := r["kesintiler"].([]any); len(k) > 0 {
				return k[0].(map[string]any)["acilma_araligi_ms"]
			}
			return nil
		}(), enUzunBosluk)
}

func TestImzaVeBoyut(t *testing.T) {
	// Bilinen vektör: sunucu tarafı aynı değeri üretmeli (PROTOKOL §8.2).
	got := btImza([]byte("anahtar"), "nonce123", []byte(`{"a":1}`))
	if len(got) != 64 {
		t.Fatal(got)
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Fatal(err)
	}
	t.Logf("test vektörü: HMAC-SHA256(\"anahtar\", \"nonce123\\n{\\\"a\\\":1}\") = %s", got)

	// 15 dk sürekli dalgalanan bağlantı: gövde sınırın altına inmeli.
	var arp []btYoklamaDizisi
	sonuclar := []string{"cevap", "yok", "zaman_asimi"}
	for i := int64(0); i < 200000; i++ {
		arp = append(arp, btYoklamaDizisi{Bas: i * 500, Bit: i * 500, Sonuc: sonuclar[i%3], Adet: 1, Onbellek: "stale"})
	}
	r := btRapor{Protokol: 1, Yoklamalar: map[string]any{"arp": arp}}
	b := raporBaytlari(r, arp, nil)
	if base64.StdEncoding.EncodedLen(len(b)) > btAzamiGovdeB64 {
		t.Fatalf("gövde sınırı aşıldı: %d", base64.StdEncoding.EncodedLen(len(b)))
	}
}

func TestParametreSinirlari(t *testing.T) {
	p := btParametreleriUygula(json.RawMessage(`{"yoklama_araligi_ms":1,"test_azami_suresi_ms":99999999,"tcp_portlari":[80,0,70000,443,53,22,8080,8443],"bilinmeyen":5}`))
	if p.YoklamaAraligiMs != 100 || p.TestAzamiSuresiMs != 900000 || len(p.TCPPortlari) != 5 || p.YoklamaZamanAsimiMs > p.YoklamaAraligiMs {
		t.Fatalf("%+v", p)
	}
}

func TestImzaKaynagiAyrimi(t *testing.T) {
	if kaynakIzinli("https://kotu.example") || !kaynakIzinli("https://sgkkolitakip.web.tr") {
		t.Fatal("origin listesi")
	}
	if imzaKaynaklari["https://sgkkolitakip.web.tr"] {
		t.Fatal("eczane sitesi imza başlatabilmemeli")
	}
}

// Sahte UPnP IGD: aygıt açıklaması (iç içe WANDevice → WANConnectionDevice) + SOAP yanıtları.
func TestUPnPOkuma(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/igd.xml":
			w.Write([]byte(`<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
<serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<controlURL>/ctl/IPConn</controlURL></service></serviceList></device></deviceList></device></deviceList></device></root>`))
		case r.URL.Path == "/ctl/IPConn" && strings.Contains(r.Header.Get("SOAPAction"), "GetStatusInfo"):
			w.Write([]byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetStatusInfoResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewConnectionStatus>Connected</NewConnectionStatus><NewLastConnectionError>ERROR_NONE</NewLastConnectionError><NewUptime>4242</NewUptime></u:GetStatusInfoResponse></s:Body></s:Envelope>`))
		case r.URL.Path == "/ctl/IPConn" && strings.Contains(r.Header.Get("SOAPAction"), "GetExternalIPAddress"):
			w.Write([]byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewExternalIPAddress>198.51.100.20</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	igd, err := upnpAciklamaOku(ctx, srv.URL+"/igd.xml")
	if err != nil {
		t.Fatal(err)
	}
	v, err := igd.oku(ctx)
	if err != nil || v["uptime_s"] != float64(4242) || v["baglanti"] != "Connected" || v["dis_ip"] != "198.51.100.20" {
		t.Fatalf("%v %v", v, err)
	}
	if _, err := upnpAciklamaOku(ctx, "http://8.8.8.8/igd.xml"); err == nil {
		t.Fatal("yerel olmayan IGD adresi reddedilmeli")
	}
}

// Saha raporu (2026-11-19, SGK deneme eczanesi) örüntüsü: modem portları her TCP turunda gidip
// geliyor, ARP sağlam; ARP "atlandi" turu kayıp sayılmamalı; önyükleyici MAC'i geçici.
func TestSahaOruntusu(t *testing.T) {
	tt := &btTest{ID: "t_saha", P: btParametreleriUygula(nil), saat: yeniBtSaat(1), asama: "izleme",
		tcpRLE: map[int][]btYoklamaDizisi{}, agHicKaybolmadi: true, kartAcik: true, agVar: true, arpVar: true, tcpVar: true,
		sonOUI: "7C:77:16", ilkOUI: "7C:77:16"}
	sayac := map[string]int{}
	isle := func(g btGozlem) {
		for _, o := range tt.isle(g) {
			sayac[o.Kod]++
		}
	}
	for i := 0; i < 100; i++ { // modem açık: ARP cevap, TCP her turda dönüşümlü
		isle(btGozlem{Tur: "yoklama", ARP: "cevap", Onbellek: "reachable"})
		if i%4 == 0 {
			s := map[bool]string{true: "acik", false: "zaman_asimi"}[i%8 == 0]
			isle(btGozlem{Tur: "yoklama", TCP: map[int]string{80: s, 443: s, 53: s}})
		}
		if i%10 == 5 {
			isle(btGozlem{Tur: "yoklama", ARP: "atlandi", Onbellek: "reachable"})
		}
	}
	if sayac["ag_gecidi_kayip"] != 0 {
		t.Fatalf("ARP sağlamken ağ geçidi kaybı üretildi: %v", sayac)
	}
	if sayac["tcp_kayip"] > 13 || sayac["tcp_geri"] > 13 {
		t.Fatalf("TCP olayları port başına değil birleşik olmalı: %v", sayac)
	}
	// Modem kapanır (ARP + TCP yok), önyükleyici MAC'iyle döner, sonra gerçek MAC.
	isle(btGozlem{Tur: "yoklama", ARP: "zaman_asimi", Onbellek: "reachable", TCP: map[int]string{80: "zaman_asimi"}})
	isle(btGozlem{Tur: "mac", Veri: map[string]any{"oui": "7E:70:16"}})
	isle(btGozlem{Tur: "yoklama", ARP: "cevap"})
	isle(btGozlem{Tur: "mac", Veri: map[string]any{"oui": "7C:77:16"}})
	if sayac["ag_gecidi_kayip"] != 1 || sayac["ag_gecidi_geri"] != 1 || sayac["ag_gecidi_mac_degisti"] != 2 {
		t.Fatalf("%v", sayac)
	}
	son := tt.olaylar[len(tt.olaylar)-1]
	if son.Kod != "ag_gecidi_mac_degisti" || son.Veri["ilk_oui_ye_dondu"] != true {
		t.Fatalf("son olay: %+v", son)
	}
	for _, o := range tt.olaylar {
		if o.Kod == "ag_gecidi_mac_degisti" && o.Veri["yeni_oui"] == "7E:70:16" && o.Veri["yeni_yerel_yonetimli"] != true {
			t.Fatalf("önyükleyici MAC'i yerel yönetimli işaretlenmeli: %+v", o)
		}
	}
}
