package main

// ============================================================================
// BAĞLANTI TESTİ MODÜLÜ (v1.6.0, docs/baglanti_testi/PROTOKOL.md)
// ============================================================================
//
// Kolitakip'in "statik IP" testinde bilgisayar tarafı gözlemci. İLKE: exe karar vermez, yalnız ham
// gözlemleri zaman damgalı raporlar; tüm eşikler sunucudan gelir. Bu dosya platformdan bağımsızdır:
// protokol, olay motoru, kalp atışı, rapor. Ağ gözlemi bir "gozlemci" arayüzünün arkasındadır —
// Windows'ta gerçek gözlemci, --simule modunda senaryo oynatıcısı takılır. Böylece simülatör,
// gözlemci dışındaki TÜM gerçek kodu çalıştırır.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"regexp"
	"sort"
	"sync"
	"time"
)

const (
	btModul    = "baglanti_testi"
	btProtokol = 1
)

var btDesteklenenProtokoller = []int{1}

// ---------------------------------------------------------------------------
// Parametreler
// ---------------------------------------------------------------------------

type btParametreler struct {
	YoklamaAraligiMs         int64 `json:"yoklama_araligi_ms"`
	YoklamaZamanAsimiMs      int64 `json:"yoklama_zaman_asimi_ms"`
	DurumAraligiMs           int64 `json:"durum_araligi_ms"`
	OnKontrolYoklamaSayisi   int   `json:"on_kontrol_yoklama_sayisi"`
	TCPPortlari              []int `json:"tcp_portlari"`
	UPnP                     bool  `json:"upnp"`
	UPnPAraligiMs            int64 `json:"upnp_araligi_ms"`
	TestAzamiSuresiMs        int64 `json:"test_azami_suresi_ms"`
	SonIzlemeSuresiMs        int64 `json:"son_izleme_suresi_ms"`
	RaporYenidenDenemeSuresi int64 `json:"rapor_yeniden_deneme_suresi_ms"`
	BoslukEsigiMs            int64 `json:"bosluk_esigi_ms"`
}

func sinirla(v, en, cok int64) int64 {
	if v < en {
		return en
	}
	if v > cok {
		return cok
	}
	return v
}

// btParametreleriUygula, sunucudan gelen ham parametre nesnesini varsayılanlar ve güvenlik
// sınırlarıyla birleştirir. Bilinmeyen alanlar yok sayılır; tür hatası olan alan varsayılana düşer.
func btParametreleriUygula(ham json.RawMessage) btParametreler {
	p := btParametreler{
		YoklamaAraligiMs: 500, YoklamaZamanAsimiMs: 400, DurumAraligiMs: 1000, OnKontrolYoklamaSayisi: 6,
		TCPPortlari: []int{80, 443, 53}, UPnP: true, UPnPAraligiMs: 5000, TestAzamiSuresiMs: 900000,
		SonIzlemeSuresiMs: 60000, RaporYenidenDenemeSuresi: 900000,
	}
	var m map[string]json.RawMessage
	if len(ham) > 0 {
		json.Unmarshal(ham, &m)
	}
	sayi := func(ad string, hedef *int64) {
		if v, ok := m[ad]; ok {
			var f float64
			if json.Unmarshal(v, &f) == nil {
				*hedef = int64(f)
			}
		}
	}
	sayi("yoklama_araligi_ms", &p.YoklamaAraligiMs)
	sayi("yoklama_zaman_asimi_ms", &p.YoklamaZamanAsimiMs)
	sayi("durum_araligi_ms", &p.DurumAraligiMs)
	var oky int64 = int64(p.OnKontrolYoklamaSayisi)
	sayi("on_kontrol_yoklama_sayisi", &oky)
	sayi("upnp_araligi_ms", &p.UPnPAraligiMs)
	sayi("test_azami_suresi_ms", &p.TestAzamiSuresiMs)
	sayi("son_izleme_suresi_ms", &p.SonIzlemeSuresiMs)
	sayi("rapor_yeniden_deneme_suresi_ms", &p.RaporYenidenDenemeSuresi)
	sayi("bosluk_esigi_ms", &p.BoslukEsigiMs)
	if v, ok := m["upnp"]; ok {
		var b bool
		if json.Unmarshal(v, &b) == nil {
			p.UPnP = b
		}
	}
	if v, ok := m["tcp_portlari"]; ok {
		var portlar []int
		if json.Unmarshal(v, &portlar) == nil {
			p.TCPPortlari = nil
			for _, port := range portlar {
				if port > 0 && port < 65536 && len(p.TCPPortlari) < 5 {
					p.TCPPortlari = append(p.TCPPortlari, port)
				}
			}
		}
	}
	p.YoklamaAraligiMs = sinirla(p.YoklamaAraligiMs, 100, 5000)
	p.YoklamaZamanAsimiMs = sinirla(p.YoklamaZamanAsimiMs, 50, 3000)
	if p.YoklamaZamanAsimiMs > p.YoklamaAraligiMs {
		p.YoklamaZamanAsimiMs = p.YoklamaAraligiMs
	}
	p.DurumAraligiMs = sinirla(p.DurumAraligiMs, 250, 5000)
	p.OnKontrolYoklamaSayisi = int(sinirla(oky, 1, 50))
	p.UPnPAraligiMs = sinirla(p.UPnPAraligiMs, 2000, 60000)
	p.TestAzamiSuresiMs = sinirla(p.TestAzamiSuresiMs, 60000, 900000)
	p.SonIzlemeSuresiMs = sinirla(p.SonIzlemeSuresiMs, 0, 600000)
	p.RaporYenidenDenemeSuresi = sinirla(p.RaporYenidenDenemeSuresi, 600000, 86400000)
	if p.BoslukEsigiMs <= 0 {
		p.BoslukEsigiMs = 3 * p.YoklamaAraligiMs
	}
	p.BoslukEsigiMs = sinirla(p.BoslukEsigiMs, p.YoklamaAraligiMs, 600000)
	if p.TCPPortlari == nil {
		p.TCPPortlari = []int{}
	}
	return p
}

// ---------------------------------------------------------------------------
// Gözlemci arayüzü
// ---------------------------------------------------------------------------

// btGozlem, gözlemcinin motora ilettiği tek bir ham gözlemdir. Motor zaman damgasını kendi
// monotonik saatiyle basar.
type btGozlem struct {
	Tur string // kart | ipv4 | yoklama | arayuz | yol | vpn | guc | upnp | mac | program_kapat (yalnız sim)

	KartAcik bool
	Neden    string

	ARP      string         // cevap | yok | zaman_asimi | hata | atlandi | yok_destek
	Onbellek string         // ARP çağrısı öncesi önbellek durumu
	TCP      map[int]string // port → acik | reddedildi | zaman_asimi | hata

	Veri map[string]any
}

// btOnKontrol, gözlemcinin ön kontrol sonucu.
type btOnKontrol struct {
	Bilgi    map[string]any // PROTOKOL §4.2 "on_kontrol" nesnesi (olcum_zamani motor tarafından eklenir)
	Engeller []string
	KartAcik bool
	AgVar    bool
}

type btGozlemci interface {
	OnKontrol(ctx context.Context, p btParametreler, hedef string) (btOnKontrol, error)
	// Izle, ctx bitene kadar gözlemleri cikis'a yazar.
	Izle(ctx context.Context, p btParametreler, cikis chan<- btGozlem)
}

// ---------------------------------------------------------------------------
// Saat (simülatörde hızlandırılabilir)
// ---------------------------------------------------------------------------

type btSaat struct {
	bas      time.Time
	basDuvar time.Time
	hiz      float64
}

func yeniBtSaat(hiz float64) *btSaat {
	if hiz <= 0 {
		hiz = 1
	}
	s := time.Now()
	return &btSaat{bas: s, basDuvar: s, hiz: hiz}
}

// ms, test başlangıcından beri geçen monotonik süre (time.Since monotonik saati kullanır).
func (s *btSaat) ms() int64 { return int64(float64(time.Since(s.bas).Milliseconds()) * s.hiz) }

// duvar, ms anına karşılık gelen duvar saati (simülatörde sanal).
func (s *btSaat) duvar(ms int64) string {
	return s.basDuvar.Add(time.Duration(ms) * time.Millisecond).UTC().Format("2006-01-02T15:04:05.000Z")
}

// gercek, senaryo/test süresini gerçek bekleme süresine çevirir.
func (s *btSaat) gercek(ms int64) time.Duration {
	d := time.Duration(float64(ms)/s.hiz) * time.Millisecond
	if d < time.Millisecond {
		d = time.Millisecond
	}
	return d
}

// ---------------------------------------------------------------------------
// Olaylar, yoklama özetleri, kesintiler
// ---------------------------------------------------------------------------

type btOlay struct {
	Sira   int            `json:"sira"`
	MonoMs int64          `json:"mono_ms"`
	Duvar  string         `json:"duvar"`
	Kod    string         `json:"kod"`
	Veri   map[string]any `json:"veri,omitempty"`
}

type btYoklamaDizisi struct {
	Bas      int64  `json:"bas"`
	Bit      int64  `json:"bit"`
	Sonuc    string `json:"sonuc"`
	Adet     int    `json:"adet"`
	Onbellek string `json:"onbellek_once,omitempty"`
}

func rleEkle(liste []btYoklamaDizisi, ms int64, sonuc, onbellek string) []btYoklamaDizisi {
	if n := len(liste); n > 0 && liste[n-1].Sonuc == sonuc && liste[n-1].Onbellek == onbellek {
		liste[n-1].Bit = ms
		liste[n-1].Adet++
		return liste
	}
	return append(liste, btYoklamaDizisi{Bas: ms, Bit: ms, Sonuc: sonuc, Adet: 1, Onbellek: onbellek})
}

type btKesinti struct {
	KartDustu       *int64 `json:"kart_dustu"`
	KartGeldi       *int64 `json:"kart_geldi"`
	AgGecidiKayip   *int64 `json:"ag_gecidi_kayip"`
	AgGecidiGeri    *int64 `json:"ag_gecidi_geri"`
	KartKapaliMs    *int64 `json:"kart_kapali_ms"`
	AgGecidiKayipMs *int64 `json:"ag_gecidi_kayip_ms"`
	AcilmaAraligiMs *int64 `json:"acilma_araligi_ms"`
	Asama           string `json:"asama"` // izleme | son_izleme
}

func i64(v int64) *int64 { return &v }

// ---------------------------------------------------------------------------
// Test oturumu
// ---------------------------------------------------------------------------

var (
	btTestIDDeseni = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	btNonceDeseni  = regexp.MustCompile(`^[A-Za-z0-9_\-+/=.]{16,128}$`)
)

type btTest struct {
	mu sync.Mutex

	ID, Nonce, BeklenenBaglanti, RaporHedefi, OlcumHedefi string
	Istenen                                               json.RawMessage
	P                                                     btParametreler
	saat                                                  *btSaat
	simulasyon                                            string

	asama     string // on_kontrol | izleme | son_izleme | rapor | bitti
	raporTuru string // nihai | iptal | yarim

	onKontrol btOnKontrol
	olaylar   []btOlay
	durumSira int

	kartAcik, agVar, arpVar, tcpVar bool
	kartDustuMs, agKayipMs          int64
	toplamKartKapali, toplamAgKayip int64
	sonYoklamaMs                    int64
	agHicKaybolmadi                 bool
	sonOUI                          string
	upnpUptime                      float64
	upnpDisIP, upnpBaglanti         string
	upnpBilgi                       map[string]any

	arpRLE   []btYoklamaDizisi
	tcpRLE   map[int][]btYoklamaDizisi
	tcpPortV map[int]bool

	kesintiler []btKesinti
	acikKes    *btKesinti

	izlemeBitisMs         int64
	sonIzlemeBas          int64
	sayfaKopma            int
	bosluklar             int
	uyku, vpn, yolDegisti bool

	iptal  context.CancelFunc
	bitirC chan string // test_bitir isteği (kaynak)
}

const btAzamiOlay = 5000

func (t *btTest) olayEkle(kod string, veri map[string]any) btOlay {
	ms := t.saat.ms()
	if len(t.olaylar) >= btAzamiOlay { // sürekli dalgalanan bağlantıda rapor şişmesin; son kayıt işaret olur
		o := btOlay{Sira: len(t.olaylar) + 1, MonoMs: ms, Duvar: t.saat.duvar(ms), Kod: "olay_siniri_asildi"}
		if t.olaylar[len(t.olaylar)-1].Kod != "olay_siniri_asildi" {
			t.olaylar = append(t.olaylar, o)
		}
		return o
	}
	o := btOlay{Sira: len(t.olaylar) + 1, MonoMs: ms, Duvar: t.saat.duvar(ms), Kod: kod, Veri: veri}
	t.olaylar = append(t.olaylar, o)
	log.Printf("[BAĞLANTI] %s +%dms %s %v", t.ID, ms, kod, veri)
	return o
}

// kesintiAc/kesintiKapat: kart düşmesi ya da ağ geçidi kaybıyla başlayan, ikisi de düzelince biten aralık.
func (t *btTest) kesinti() *btKesinti {
	if t.acikKes == nil {
		t.acikKes = &btKesinti{Asama: t.asama}
	}
	return t.acikKes
}

func (t *btTest) kesintiyiKapatGerekirse() {
	k := t.acikKes
	if k == nil || !t.kartAcik || !t.agVar {
		return
	}
	if k.KartDustu != nil && k.KartGeldi != nil {
		k.KartKapaliMs = i64(*k.KartGeldi - *k.KartDustu)
	}
	if k.AgGecidiKayip != nil && k.AgGecidiGeri != nil {
		k.AgGecidiKayipMs = i64(*k.AgGecidiGeri - *k.AgGecidiKayip)
	}
	if k.KartGeldi != nil && k.AgGecidiGeri != nil {
		k.AcilmaAraligiMs = i64(*k.AgGecidiGeri - *k.KartGeldi)
	}
	t.kesintiler = append(t.kesintiler, *k)
	t.acikKes = nil
}

// isle, tek bir gözlemi işler ve üretilen olayları döndürür (çağıran yayınlar). t.mu tutulmalı.
func (t *btTest) isle(g btGozlem) []btOlay {
	var yeni []btOlay
	ekle := func(kod string, veri map[string]any) { yeni = append(yeni, t.olayEkle(kod, veri)) }
	ms := t.saat.ms()
	switch g.Tur {
	case "kart":
		if g.KartAcik == t.kartAcik {
			return nil
		}
		t.kartAcik = g.KartAcik
		if !g.KartAcik {
			t.kartDustuMs = ms
			t.kesinti().KartDustu = i64(ms)
			v := map[string]any{"neden": g.Neden}
			for k, d := range g.Veri {
				v[k] = d
			}
			ekle("kart_dustu", v)
		} else {
			t.toplamKartKapali += ms - t.kartDustuMs
			k := t.kesinti()
			k.KartGeldi = i64(ms)
			ekle("kart_geldi", g.Veri)
			t.kesintiyiKapatGerekirse()
		}
	case "ipv4":
		if v, _ := g.Veri["var"].(bool); v {
			ekle("ipv4_geldi", map[string]any{"adres": g.Veri["adres"]})
		} else {
			ekle("ipv4_kayboldu", map[string]any{"adres": g.Veri["adres"]})
		}
	case "yoklama":
		if t.sonYoklamaMs > 0 && ms-t.sonYoklamaMs > t.P.BoslukEsigiMs {
			t.bosluklar++
			ekle("yoklama_boslugu", map[string]any{"bas_mono_ms": t.sonYoklamaMs, "bit_mono_ms": ms})
		}
		t.sonYoklamaMs = ms
		arpCevap := g.ARP == "cevap"
		if g.ARP != "" {
			t.arpRLE = rleEkle(t.arpRLE, ms, g.ARP, g.Onbellek)
			if g.ARP != "atlandi" && g.ARP != "yok_destek" && arpCevap != t.arpVar {
				t.arpVar = arpCevap
				if arpCevap {
					ekle("arp_geri", nil)
				} else {
					ekle("arp_kayip", nil)
				}
			}
		}
		tcpCanli := false
		portlar := make([]int, 0, len(g.TCP))
		for port := range g.TCP {
			portlar = append(portlar, port)
		}
		sort.Ints(portlar)
		for _, port := range portlar {
			s := g.TCP[port]
			t.tcpRLE[port] = rleEkle(t.tcpRLE[port], ms, s, "")
			canli := s == "acik" || s == "reddedildi"
			tcpCanli = tcpCanli || canli
			if onceki, ok := t.tcpPortV[port]; !ok || onceki != canli {
				if ok {
					if canli {
						ekle("tcp_geri", map[string]any{"port": port})
					} else {
						ekle("tcp_kayip", map[string]any{"port": port})
					}
				}
				t.tcpPortV[port] = canli
			}
		}
		t.tcpVar = tcpCanli
		agVar := arpCevap || tcpCanli
		if agVar != t.agVar {
			t.agVar = agVar
			if !agVar {
				t.agKayipMs = ms
				t.agHicKaybolmadi = false
				t.kesinti().AgGecidiKayip = i64(ms)
				ekle("ag_gecidi_kayip", map[string]any{"son_cevap_mono_ms": t.sonCevapOncesi(ms)})
			} else {
				sure := ms - t.agKayipMs
				t.toplamAgKayip += sure
				kaynak := "tcp"
				if arpCevap {
					kaynak = "arp"
				}
				t.kesinti().AgGecidiGeri = i64(ms)
				ekle("ag_gecidi_geri", map[string]any{"kaynak": kaynak, "kayip_suresi_ms": sure})
				t.kesintiyiKapatGerekirse()
			}
		}
	case "mac":
		oui, _ := g.Veri["oui"].(string)
		if oui != "" && t.sonOUI != "" && oui != t.sonOUI {
			ekle("ag_gecidi_mac_degisti", map[string]any{"onceki_oui": t.sonOUI, "yeni_oui": oui})
		}
		if oui != "" {
			t.sonOUI = oui
		}
	case "yol":
		t.yolDegisti = true
		ekle("yol_degisti", g.Veri)
	case "arayuz":
		ekle("arayuz_degisti", g.Veri)
	case "vpn":
		if v, _ := g.Veri["var"].(bool); v {
			t.vpn = true
			ekle("vpn_belirdi", map[string]any{"aciklama": g.Veri["aciklama"]})
		} else {
			ekle("vpn_kayboldu", map[string]any{"aciklama": g.Veri["aciklama"]})
		}
	case "guc":
		tur, _ := g.Veri["tur"].(string)
		if tur == "uyanma" {
			ekle("uyanma", g.Veri)
		} else {
			t.uyku = true
			ekle("uyku", g.Veri)
		}
	case "upnp":
		uptime, _ := g.Veri["uptime_s"].(float64)
		disIP, _ := g.Veri["dis_ip"].(string)
		bag, _ := g.Veri["baglanti"].(string)
		if t.upnpBilgi == nil {
			t.upnpBilgi = map[string]any{"durum": "var", "ilk": g.Veri}
		} else {
			if uptime > 0 && t.upnpUptime > 0 && uptime < t.upnpUptime {
				ekle("upnp_uptime_sifirlandi", map[string]any{"onceki_s": t.upnpUptime, "yeni_s": uptime})
			}
			if disIP != "" && t.upnpDisIP != "" && disIP != t.upnpDisIP {
				ekle("upnp_dis_ip_degisti", map[string]any{"onceki": t.upnpDisIP, "yeni": disIP})
			}
			if bag != "" && t.upnpBaglanti != "" && bag != t.upnpBaglanti {
				ekle("upnp_baglanti_durumu", map[string]any{"durum": bag})
			}
		}
		if uptime > 0 {
			t.upnpUptime = uptime
		}
		if disIP != "" {
			t.upnpDisIP = disIP
		}
		if bag != "" {
			t.upnpBaglanti = bag
		}
	case "ic_hata":
		ekle("ic_hata", g.Veri)
	}
	return yeni
}

func (t *btTest) sonCevapOncesi(ms int64) int64 {
	if n := len(t.arpRLE); n > 0 {
		for i := n - 1; i >= 0; i-- {
			if t.arpRLE[i].Sonuc == "cevap" {
				return t.arpRLE[i].Bit
			}
		}
	}
	return ms
}

// durumMesaji, canlı ekran / kalp atışı mesajı. t.mu tutulmalı.
func (t *btTest) durumMesaji() map[string]any {
	ms := t.saat.ms()
	t.durumSira++
	kart, ag := "acik", "var"
	if !t.kartAcik {
		kart = "kapali"
	}
	if !t.agVar {
		ag = "yok"
	}
	vy := func(b bool) string {
		if b {
			return "var"
		}
		return "yok"
	}
	var kartSure, agSure int64
	topKart, topAg := t.toplamKartKapali, t.toplamAgKayip
	if !t.kartAcik {
		kartSure = ms - t.kartDustuMs
		topKart += kartSure
	}
	if !t.agVar {
		agSure = ms - t.agKayipMs
		topAg += agSure
	}
	kalan := int64(0)
	switch t.asama {
	case "izleme":
		kalan = t.P.TestAzamiSuresiMs - ms
	case "son_izleme":
		kalan = t.sonIzlemeBas + t.P.SonIzlemeSuresiMs - ms
	}
	if kalan < 0 {
		kalan = 0
	}
	return map[string]any{
		"modul": btModul, "protokol": btProtokol, "tip": "durum", "test_id": t.ID,
		"sira": t.durumSira, "mono_ms": ms, "asama": t.asama,
		"kart": kart, "ag_gecidi": ag, "arp": vy(t.arpVar), "tcp": vy(t.tcpVar),
		"kart_kapali_suresi_ms": kartSure, "ag_gecidi_kayip_suresi_ms": agSure,
		"toplam_kart_kapali_ms": topKart, "toplam_ag_gecidi_kayip_ms": topAg,
		"kalan_ms": kalan,
	}
}

// ---------------------------------------------------------------------------
// Rapor (imzalanan JSON). Alan sırası struct sırasıdır → aynı içerik aynı baytlar.
// ---------------------------------------------------------------------------

type btRapor struct {
	Protokol         int            `json:"protokol"`
	RaporTuru        string         `json:"rapor_turu"`
	TestID           string         `json:"test_id"`
	Nonce            string         `json:"nonce"`
	Exe              map[string]any `json:"exe"`
	BeklenenBaglanti string         `json:"beklenen_baglanti"`
	Parametreler     map[string]any `json:"parametreler"`
	Zaman            map[string]any `json:"zaman"`
	OnKontrol        map[string]any `json:"on_kontrol"`
	Engeller         []string       `json:"engeller"`
	Olaylar          []btOlay       `json:"olaylar"`
	Yoklamalar       map[string]any `json:"yoklamalar"`
	Kesintiler       []btKesinti    `json:"kesintiler"`
	Ozet             map[string]any `json:"ozet"`
	SonIzleme        map[string]any `json:"son_izleme"`
	UPnP             map[string]any `json:"upnp"`
}

// raporOlustur, t.mu tutulmalı.
func (t *btTest) raporOlustur() btRapor {
	ms := t.saat.ms()
	kesintiler := append([]btKesinti{}, t.kesintiler...)
	if t.acikKes != nil { // kapanmamış kesinti: olduğu gibi (açık uçlu) raporlanır
		kesintiler = append(kesintiler, *t.acikKes)
	}
	tcp := map[string]any{}
	for port, liste := range t.tcpRLE {
		tcp[fmt.Sprint(port)] = liste
	}
	var istenen any = map[string]any{}
	if len(t.Istenen) > 0 {
		json.Unmarshal(t.Istenen, &istenen)
	}
	sonIzleme := map[string]any{"bas": nil, "bit": nil, "ag_gecidi_kayip_sayisi": 0, "kart_dustu_sayisi": 0, "yol_degisti": false}
	if t.sonIzlemeBas > 0 {
		agK, kartD, yol := 0, 0, false
		for _, o := range t.olaylar {
			if o.MonoMs < t.sonIzlemeBas {
				continue
			}
			switch o.Kod {
			case "ag_gecidi_kayip":
				agK++
			case "kart_dustu":
				kartD++
			case "yol_degisti":
				yol = true
			}
		}
		sonIzleme = map[string]any{"bas": t.sonIzlemeBas, "bit": ms, "ag_gecidi_kayip_sayisi": agK, "kart_dustu_sayisi": kartD, "yol_degisti": yol}
	}
	upnp := t.upnpBilgi
	if upnp == nil {
		upnp = map[string]any{"durum": "yok"}
	} else {
		upnp["son"] = map[string]any{"uptime_s": t.upnpUptime, "dis_ip": t.upnpDisIP, "baglanti": t.upnpBaglanti}
	}
	exe := map[string]any{"surum": APP_VERSION, "isletim_sistemi": isletimSistemiBilgisi(), "simulasyon": nil}
	if t.simulasyon != "" {
		exe["simulasyon"] = t.simulasyon
	}
	engeller := t.onKontrol.Engeller
	if engeller == nil {
		engeller = []string{}
	}
	return btRapor{
		Protokol: btProtokol, RaporTuru: t.raporTuru, TestID: t.ID, Nonce: t.Nonce, Exe: exe,
		BeklenenBaglanti: t.BeklenenBaglanti,
		Parametreler:     map[string]any{"istenen": istenen, "uygulanan": t.P},
		Zaman: map[string]any{"baslangic_duvar": t.saat.duvar(0), "bitis_mono_ms": ms,
			"izleme_bitis_mono_ms": t.izlemeBitisMs},
		OnKontrol: t.onKontrol.Bilgi, Engeller: engeller, Olaylar: t.olaylar,
		Yoklamalar: map[string]any{"arp": t.arpRLE, "tcp": tcp},
		Kesintiler: kesintiler,
		Ozet: map[string]any{
			"ag_gecidi_hic_kaybolmadi": t.agHicKaybolmadi, "toplam_kart_kapali_ms": t.toplamKartKapali,
			"toplam_ag_gecidi_kayip_ms": t.toplamAgKayip, "yoklama_bosluklari": t.bosluklar,
			"uyku": t.uyku, "vpn": t.vpn, "yol_degisti": t.yolDegisti, "sayfa_koptu": t.sayfaKopma,
		},
		SonIzleme: sonIzleme, UPnP: upnp,
	}
}

// ---------------------------------------------------------------------------
// Modül yöneticisi: tek aktif test, abone bağlantılar, uzaktan kapatma
// ---------------------------------------------------------------------------

// btIstemci, bir WebSocket bağlantısına mesaj yazabilen nesne (wsBaglanti).
type btIstemci interface {
	Yaz(v any) error
}

type btYonetici struct {
	mu         sync.Mutex
	aktif      *btTest
	aboneler   map[btIstemci]string       // istemci → izlediği test_id
	gozlemci   func(t *btTest) btGozlemci // nil → platform desteklemiyor
	saatHizi   float64
	simulasyon string
	gonderici  *btGonderici
	hedefler   map[string]string // rapor_hedefi anahtarı → URL
}

var btYon *btYonetici

// btModulKapali, latest.json "moduller.baglanti_testi.acik=false" ile uzaktan kapatma (update tarafı ayarlar).
var btModulKapali sync.Map // "baglanti_testi" → true

func (y *btYonetici) yayinla(testID string, v any) {
	y.mu.Lock()
	var hedef []btIstemci
	for c, id := range y.aboneler {
		if id == testID {
			hedef = append(hedef, c)
		}
	}
	y.mu.Unlock()
	for _, c := range hedef {
		if err := c.Yaz(v); err != nil {
			y.ayril(c)
		}
	}
}

func (y *btYonetici) ayril(c btIstemci) {
	y.mu.Lock()
	id, vardi := y.aboneler[c]
	delete(y.aboneler, c)
	aktif := y.aktif
	y.mu.Unlock()
	if vardi && aktif != nil && aktif.ID == id {
		aktif.mu.Lock()
		if aktif.asama == "izleme" || aktif.asama == "son_izleme" {
			aktif.sayfaKopma++
			o := aktif.olayEkle("sayfa_koptu", nil)
			aktif.mu.Unlock()
			y.yayinla(id, btOlayMesaji(id, o))
			return
		}
		aktif.mu.Unlock()
	}
}

func btOlayMesaji(testID string, o btOlay) map[string]any {
	return map[string]any{"modul": btModul, "protokol": btProtokol, "tip": "olay", "test_id": testID, "olay": o}
}

func btHata(istekNo any, kod, mesaj string) map[string]any {
	m := map[string]any{"modul": btModul, "protokol": btProtokol, "tip": "hata", "kod": kod, "mesaj": mesaj}
	if istekNo != nil {
		m["istek_no"] = istekNo
	}
	return m
}

type btIstek struct {
	Modul            string          `json:"modul"`
	Protokol         int             `json:"protokol"`
	Tip              string          `json:"tip"`
	IstekNo          any             `json:"istek_no"`
	TestID           string          `json:"test_id"`
	Nonce            string          `json:"nonce"`
	OlcumHedefi      string          `json:"olcum_hedefi"`
	BeklenenBaglanti string          `json:"beklenen_baglanti"`
	RaporHedefi      string          `json:"rapor_hedefi"`
	Parametreler     json.RawMessage `json:"parametreler"`
}

// mesajIsle, bağlantı testi modülüne gelen bir WebSocket mesajını işler.
func (y *btYonetici) mesajIsle(c btIstemci, ham []byte) {
	var m btIstek
	if err := json.Unmarshal(ham, &m); err != nil {
		c.Yaz(btHata(nil, "GECERSIZ_MESAJ", "JSON çözülemedi"))
		return
	}
	cevap := func(v map[string]any) {
		if m.IstekNo != nil {
			v["istek_no"] = m.IstekNo
		}
		c.Yaz(v)
	}
	if !protokolDestekleniyor(m.Protokol) {
		cevap(btHata(m.IstekNo, "PROTOKOL_DESTEKLENMIYOR", fmt.Sprintf("protokol %d desteklenmiyor", m.Protokol)))
		return
	}
	switch m.Tip {
	case "merhaba":
		cevap(y.merhaba())
	case "test_basla":
		y.testBasla(c, m, cevap)
	case "test_bitir", "test_iptal":
		y.mu.Lock()
		t := y.aktif
		y.mu.Unlock()
		if t == nil || t.ID != m.TestID {
			cevap(btHata(m.IstekNo, "TEST_YOK", "bu test_id ile aktif test yok"))
			return
		}
		if m.Tip == "test_iptal" {
			t.mu.Lock()
			t.raporTuru = "iptal"
			t.mu.Unlock()
		}
		select {
		case t.bitirC <- m.Tip:
		default:
		}
		cevap(map[string]any{"modul": btModul, "protokol": btProtokol, "tip": m.Tip + "_yanit", "test_id": t.ID,
			"son_izleme_ms": map[bool]int64{true: 0, false: t.P.SonIzlemeSuresiMs}[m.Tip == "test_iptal"]})
	case "test_baglan":
		y.mu.Lock()
		t := y.aktif
		if t != nil && t.ID == m.TestID {
			y.aboneler[c] = t.ID
		}
		y.mu.Unlock()
		if t == nil || t.ID != m.TestID {
			cevap(btHata(m.IstekNo, "TEST_YOK", "bu test_id ile aktif test yok"))
			return
		}
		t.mu.Lock()
		o := t.olayEkle("sayfa_baglandi", nil)
		olaylar := append([]btOlay{}, t.olaylar...)
		t.mu.Unlock()
		cevap(map[string]any{"modul": btModul, "protokol": btProtokol, "tip": "test_baglan_yanit", "test_id": t.ID,
			"olaylar": olaylar})
		y.yayinla(t.ID, btOlayMesaji(t.ID, o))
	default:
		cevap(btHata(m.IstekNo, "GECERSIZ_MESAJ", "bilinmeyen tip: "+m.Tip))
	}
}

func protokolDestekleniyor(p int) bool {
	for _, d := range btDesteklenenProtokoller {
		if d == p {
			return true
		}
	}
	return false
}

func (y *btYonetici) modulDurumu() string {
	if y.gozlemci == nil {
		return "desteklenmiyor"
	}
	if v, ok := btModulKapali.Load(btModul); ok && v.(bool) {
		return "kapali_uzaktan"
	}
	return "acik"
}

func (y *btYonetici) merhaba() map[string]any {
	durum := y.modulDurumu()
	y.mu.Lock()
	var aktif any
	if y.aktif != nil {
		y.aktif.mu.Lock()
		aktif = map[string]any{"test_id": y.aktif.ID, "asama": y.aktif.asama}
		y.aktif.mu.Unlock()
	}
	y.mu.Unlock()
	m := map[string]any{
		"modul": btModul, "protokol": btProtokol, "tip": "merhaba_yanit",
		"hazir": durum == "acik", "exe_surum": APP_VERSION, "desteklenen_protokoller": btDesteklenenProtokoller,
		"modul_durumu": durum, "isletim_sistemi": isletimSistemiBilgisi(),
		"yetenekler": []string{"arp", "tcp_yoklama", "arayuz_olaylari", "guc_olaylari", "upnp"},
		"aktif_test": aktif,
	}
	switch durum {
	case "kapali_uzaktan":
		m["neden"] = "MODUL_KAPALI"
	case "desteklenmiyor":
		m["neden"] = "PLATFORM_DESTEKLENMIYOR"
	}
	if y.simulasyon != "" {
		m["simulasyon"] = y.simulasyon
	}
	return m
}

func (y *btYonetici) testBasla(c btIstemci, m btIstek, cevap func(map[string]any)) {
	switch y.modulDurumu() {
	case "kapali_uzaktan":
		cevap(btHata(m.IstekNo, "MODUL_KAPALI", "bağlantı testi uzaktan kapatıldı"))
		return
	case "desteklenmiyor":
		cevap(btHata(m.IstekNo, "PLATFORM_DESTEKLENMIYOR", "bu platformda bağlantı testi yok"))
		return
	}
	if !btTestIDDeseni.MatchString(m.TestID) || !btNonceDeseni.MatchString(m.Nonce) {
		cevap(btHata(m.IstekNo, "GECERSIZ_PARAMETRE", "test_id veya nonce biçimi geçersiz"))
		return
	}
	if ip := net.ParseIP(m.OlcumHedefi); ip == nil || ip.To4() == nil {
		cevap(btHata(m.IstekNo, "GECERSIZ_PARAMETRE", "olcum_hedefi bir IPv4 adresi olmalı"))
		return
	}
	if _, ok := y.hedefler[m.RaporHedefi]; !ok {
		cevap(btHata(m.IstekNo, "GECERSIZ_PARAMETRE", "rapor_hedefi bilinmiyor: "+m.RaporHedefi))
		return
	}
	if m.BeklenenBaglanti != "modem" && m.BeklenenBaglanti != "hotspot" {
		cevap(btHata(m.IstekNo, "GECERSIZ_PARAMETRE", "beklenen_baglanti modem ya da hotspot olmalı"))
		return
	}
	if y.gonderici.nonceKullanildi(m.Nonce) {
		cevap(btHata(m.IstekNo, "NONCE_TEKRAR", "bu nonce daha önce kullanıldı"))
		return
	}
	y.mu.Lock()
	if y.aktif != nil {
		y.mu.Unlock()
		cevap(btHata(m.IstekNo, "TEST_ZATEN_CALISIYOR", "zaten çalışan bir test var"))
		return
	}
	ctx, iptal := context.WithCancel(context.Background())
	t := &btTest{
		ID: m.TestID, Nonce: m.Nonce, BeklenenBaglanti: m.BeklenenBaglanti, RaporHedefi: m.RaporHedefi,
		OlcumHedefi: m.OlcumHedefi, Istenen: m.Parametreler, P: btParametreleriUygula(m.Parametreler),
		saat: yeniBtSaat(y.saatHizi), simulasyon: y.simulasyon, asama: "on_kontrol", raporTuru: "nihai",
		tcpRLE: map[int][]btYoklamaDizisi{}, tcpPortV: map[int]bool{}, agHicKaybolmadi: true,
		iptal: iptal, bitirC: make(chan string, 2),
	}
	y.aktif = t
	y.aboneler[c] = t.ID
	y.mu.Unlock()
	y.gonderici.nonceKaydet(m.Nonce)
	go y.testiYurut(ctx, t, y.gozlemci(t), cevap)
}

// testiYurut: ön kontrol → izleme → son izleme → rapor.
func (y *btYonetici) testiYurut(ctx context.Context, t *btTest, g btGozlemci, cevap func(map[string]any)) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("💥 [BAĞLANTI] test %s çöktü: %v", t.ID, r)
			t.mu.Lock()
			t.olayEkle("ic_hata", map[string]any{"mesaj": fmt.Sprint(r)})
			t.raporTuru = "yarim"
			t.mu.Unlock()
			y.raporuGonder(t)
		}
	}()
	defer t.iptal()

	ok, err := g.OnKontrol(ctx, t.P, t.OlcumHedefi)
	t.mu.Lock()
	if err != nil {
		ok.Engeller = append(ok.Engeller, "IC_HATA")
		if ok.Bilgi == nil {
			ok.Bilgi = map[string]any{}
		}
		ok.Bilgi["hata"] = err.Error()
	}
	if ok.Bilgi == nil {
		ok.Bilgi = map[string]any{}
	}
	if ok.Engeller == nil {
		ok.Engeller = []string{}
	}
	ok.Bilgi["olcum_zamani"] = map[string]any{"mono_ms": t.saat.ms(), "duvar": t.saat.duvar(t.saat.ms())}
	ok.Bilgi["beklenen_baglanti"] = t.BeklenenBaglanti
	t.onKontrol = ok
	t.kartAcik, t.agVar, t.arpVar = ok.KartAcik, ok.AgVar, ok.AgVar
	if oui, _ := ok.Bilgi["ag_gecidi"].(map[string]any); oui != nil {
		t.sonOUI, _ = oui["oui"].(string)
	}
	t.asama = "izleme"
	o := t.olayEkle("izleme_basladi", map[string]any{"kart_acik": ok.KartAcik, "ag_gecidi_var": ok.AgVar})
	t.mu.Unlock()
	cevap(map[string]any{"modul": btModul, "protokol": btProtokol, "tip": "on_kontrol", "test_id": t.ID,
		"engeller": ok.Engeller, "on_kontrol": ok.Bilgi, "uygulanan_parametreler": t.P})
	y.yayinla(t.ID, btOlayMesaji(t.ID, o))

	gozlemler := make(chan btGozlem, 64)
	izCtx, izIptal := context.WithCancel(ctx)
	defer izIptal()
	go g.Izle(izCtx, t.P, gozlemler)

	durumT := time.NewTicker(t.saat.gercek(t.P.DurumAraligiMs))
	defer durumT.Stop()
	azami := time.NewTimer(t.saat.gercek(t.P.TestAzamiSuresiMs))
	defer azami.Stop()
	var sonIzlemeC <-chan time.Time
	donmus := false // simülatör "program_kapat"

	sonIzlemeyeGec := func(kaynak string) {
		t.mu.Lock()
		if t.asama != "izleme" {
			t.mu.Unlock()
			return
		}
		ms := t.saat.ms()
		t.izlemeBitisMs = ms
		var olaylar []btOlay
		olaylar = append(olaylar, t.olayEkle("test_bitir_istendi", map[string]any{"kaynak": kaynak}))
		if t.agHicKaybolmadi {
			olaylar = append(olaylar, t.olayEkle("ag_gecidi_hic_kaybolmadi", nil))
		}
		sure := t.P.SonIzlemeSuresiMs
		if t.raporTuru == "iptal" {
			sure = 0
		} else {
			t.asama = "son_izleme"
			t.sonIzlemeBas = ms
			olaylar = append(olaylar, t.olayEkle("son_izleme_basladi", map[string]any{"sure_ms": sure}))
		}
		t.mu.Unlock()
		for _, o := range olaylar {
			y.yayinla(t.ID, btOlayMesaji(t.ID, o))
		}
		sonIzlemeC = time.After(t.saat.gercek(sure))
	}

	for {
		select {
		case g := <-gozlemler:
			if g.Tur == "program_kapat" { // yalnız simülatör: süreç öldürülmüş gibi davran
				donmus = true
				sure, _ := g.Veri["sure_ms"].(float64)
				go func() {
					time.Sleep(t.saat.gercek(int64(sure)))
					t.mu.Lock()
					t.raporTuru = "yarim"
					t.olayEkle("program_yeniden_baslatildi", map[string]any{"son_bilinen_mono_ms": t.saat.ms() - int64(sure)})
					t.mu.Unlock()
					select {
					case t.bitirC <- "yeniden_baslatma":
					default:
					}
				}()
				continue
			}
			if donmus {
				continue
			}
			t.mu.Lock()
			yeni := t.isle(g)
			t.mu.Unlock()
			for _, o := range yeni {
				y.yayinla(t.ID, btOlayMesaji(t.ID, o))
			}
		case <-durumT.C:
			if donmus {
				continue
			}
			t.mu.Lock()
			d := t.durumMesaji()
			var goruntu *btAnlikGoruntu
			if t.durumSira%5 == 1 { // ~5 sn'de bir: program kapanırsa yarım rapor için
				goruntu = &btAnlikGoruntu{Rapor: t.raporOlustur(), YenidenMs: t.P.RaporYenidenDenemeSuresi}
			}
			t.mu.Unlock()
			if goruntu != nil && t.simulasyon == "" {
				y.mu.Lock()
				goruntu.URL = y.hedefler[t.RaporHedefi]
				y.mu.Unlock()
				y.gonderici.anlikGoruntuYaz(*goruntu)
			}
			y.yayinla(t.ID, d)
		case <-azami.C:
			sonIzlemeyeGec("zaman_asimi")
		case kaynak := <-t.bitirC:
			if kaynak == "yeniden_baslatma" {
				izIptal()
				y.raporuGonder(t)
				return
			}
			if kaynak == "test_iptal" {
				t.mu.Lock()
				t.olayEkle("test_iptal", nil)
				t.mu.Unlock()
			}
			sonIzlemeyeGec("sayfa")
		case <-sonIzlemeC:
			t.mu.Lock()
			if t.asama == "son_izleme" {
				t.olayEkle("son_izleme_bitti", nil)
			}
			t.mu.Unlock()
			izIptal()
			y.raporuGonder(t)
			return
		}
	}
}

// raporuGonder, testi kapatır, raporu imzalar ve gönderim kuyruğuna koyar.
func (y *btYonetici) raporuGonder(t *btTest) {
	t.mu.Lock()
	t.asama = "rapor"
	r := t.raporOlustur()
	arp := append([]btYoklamaDizisi{}, t.arpRLE...)
	tcp := map[int][]btYoklamaDizisi{}
	for k, v := range t.tcpRLE {
		tcp[k] = append([]btYoklamaDizisi{}, v...)
	}
	t.mu.Unlock()
	govde := raporBaytlari(r, arp, tcp)
	y.gonderici.anlikGoruntuSil()
	y.mu.Lock()
	if y.aktif == t {
		y.aktif = nil
	}
	url := y.hedefler[t.RaporHedefi]
	y.mu.Unlock()
	y.gonderici.kuyrugaEkle(t.ID, t.Nonce, url, govde, t.P.RaporYenidenDenemeSuresi, t.saat, func(d map[string]any) {
		d["modul"], d["protokol"], d["tip"], d["test_id"] = btModul, btProtokol, "rapor_durumu", t.ID
		y.yayinla(t.ID, d)
	})
}
