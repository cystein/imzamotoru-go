package main

// Bağlantı testi simülatörü (PROTOKOL.md §12). Gerçek protokol kodunu (WebSocket işleyici, olay motoru,
// kalp atışı, rapor, imza, POST, kuyruk) çalıştırır; yalnız ağ gözlemcisinin yerine senaryo oynatıcısı
// takılır. Gerçek donanım olmadan D1–D6 senaryolarını üretir; Linux'ta da çalışır.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// simDurum: senaryonun o anki "ağ gerçeği".
type simDurum struct {
	kart   bool // test arayüzü up mı
	ag     bool // ağ geçidi canlı mı (ARP + TCP cevap verir)
	arpYok bool // arayüz ARP kullanmıyor
	uyuyor bool // sistem uykuda: yoklama yok
	upnp   bool
	uptime float64
	disIP  string
}

type simAdim struct {
	t  int64 // senaryo ms (izleme başlangıcına göre)
	fn func(d *simDurum) []btGozlem
}

type simSenaryo struct {
	ad, aciklama string
	onKontrol    func() btOnKontrol
	baslangic    simDurum
	adimlar      []simAdim
	bitir        int64 // bu ms'de test_bitir (0 = sayfa bitirir)
	simHata      int   // ilk N rapor POST'u ağ hatası
}

func onKontrolKablolu(agGecidi, oui string) btOnKontrol {
	return btOnKontrol{KartAcik: true, AgVar: true, Engeller: []string{}, Bilgi: map[string]any{
		"yol": map[string]any{"hedef": "(olcum_hedefi)", "bulundu": true, "arayuz_no": 12, "ag_gecidi": agGecidi, "metrik": 35},
		"test_arayuzu": map[string]any{"no": 12, "ad": "Ethernet", "aciklama": "Realtek PCIe GbE Family Controller",
			"tur": "ethernet", "if_type": 6, "medya": "802.3", "hiz_bps": 1000000000, "durum": "up",
			"ipv4": []string{"192.168.1.34/24"}, "dhcp": true, "dhcp_kira_suresi_s": 86400, "dhcp_kira_baslangic": "(duvar)"},
		"ag_gecidi":           map[string]any{"ipv4": agGecidi, "oui": oui, "ozel_aralik": true},
		"arp":                 map[string]any{"deneme": 6, "cevap": 6, "sureler_ms": []int{2, 1, 1, 1, 1, 1}, "onbellek_durumu_once": "reachable"},
		"tcp":                 map[string]any{"80": map[string]any{"deneme": 6, "acik": 6}, "443": map[string]any{"deneme": 6, "reddedildi": 6}, "53": map[string]any{"deneme": 6, "acik": 6}},
		"aktif_arayuzler":     []any{map[string]any{"no": 12, "tur": "ethernet", "aciklama": "Realtek PCIe GbE Family Controller", "ag_gecidi": agGecidi, "varsayilan_yol": true, "metrik": 35}},
		"vpn":                 map[string]any{"var": false, "varsayilan_yol_vpn": false, "arayuzler": []string{}},
		"hotspot_ipuclari":    []string{},
		"ikinci_yonlendirici": map[string]any{"ipucu": "yok", "ikinci_atlama": "85.105.1.1", "ikinci_atlama_ozel": false},
		"upnp":                map[string]any{"durum": "yok"},
	}}
}

func onKontrolWifi(agGecidi, oui string) btOnKontrol {
	o := onKontrolKablolu(agGecidi, oui)
	o.Bilgi["test_arayuzu"] = map[string]any{"no": 18, "ad": "Wi-Fi", "aciklama": "Intel(R) Wi-Fi 6 AX201 160MHz",
		"tur": "wifi", "if_type": 71, "medya": "802.11", "hiz_bps": 433300000, "durum": "up",
		"ipv4": []string{"192.168.1.35/24"}, "dhcp": true, "dhcp_kira_suresi_s": 86400, "dhcp_kira_baslangic": "(duvar)"}
	o.Bilgi["aktif_arayuzler"] = []any{map[string]any{"no": 18, "tur": "wifi", "aciklama": "Intel(R) Wi-Fi 6 AX201 160MHz", "ag_gecidi": agGecidi, "varsayilan_yol": true, "metrik": 55}}
	return o
}

// Yardımcı adımlar
func kartDus(neden string) func(d *simDurum) []btGozlem {
	return func(d *simDurum) []btGozlem {
		d.kart, d.ag = false, false
		return []btGozlem{{Tur: "kart", KartAcik: false, Neden: neden},
			{Tur: "ipv4", Veri: map[string]any{"var": false, "adres": "192.168.1.34"}}}
	}
}
func kartGel(d *simDurum) []btGozlem {
	d.kart = true
	return []btGozlem{{Tur: "kart", KartAcik: true}}
}
func agGel(d *simDurum) []btGozlem {
	d.ag = true
	return []btGozlem{{Tur: "ipv4", Veri: map[string]any{"var": true, "adres": "192.168.1.34"}}}
}
func agGit(d *simDurum) []btGozlem { d.ag = false; return nil }

var simSenaryolar = map[string]simSenaryo{}

func init() {
	ekle := func(s simSenaryo) { simSenaryolar[s.ad] = s }
	kablolu := func() btOnKontrol { return onKontrolKablolu("192.168.1.1", "A4:2B:B0") }
	wifi := func() btOnKontrol { return onKontrolWifi("192.168.1.1", "A4:2B:B0") }
	acik := simDurum{kart: true, ag: true}

	ekle(simSenaryo{ad: "d1_modem_guc", aciklama: "Kablolu; modem elektriği ~2 dk kesilir; kart geldikten ~40 sn sonra ağ geçidi döner (uzun açılma aralığı)",
		onKontrol: kablolu, baslangic: acik, bitir: 230000, adimlar: []simAdim{
			{10000, kartDus("medya_baglantisi_yok")}, {130000, kartGel}, {170000, agGel}}})
	ekle(simSenaryo{ad: "d2_kablo_cek", aciklama: "Kablolu; bilgisayar kablosu ~20 sn çekilir; ağ geçidi ~1 sn içinde döner",
		onKontrol: kablolu, baslangic: acik, bitir: 60000, adimlar: []simAdim{
			{10000, kartDus("medya_baglantisi_yok")}, {30000, kartGel}, {31000, agGel}}})
	ekle(simSenaryo{ad: "d3_wifi_kes", aciklama: "Wi-Fi bağlantısı kesilip yeniden bağlanır; kısa aralık",
		onKontrol: wifi, baslangic: acik, bitir: 60000, adimlar: []simAdim{
			{10000, kartDus("medya_baglantisi_yok")}, {25000, kartGel}, {27000, agGel}}})
	ekle(simSenaryo{ad: "d3b_kart_devre_disi", aciklama: "Ağ kartı devre dışı bırakılıp etkinleştirilir; kısa aralık",
		onKontrol: kablolu, baslangic: acik, bitir: 60000, adimlar: []simAdim{
			{10000, kartDus("devre_disi")}, {28000, kartGel}, {30000, agGel}}})
	ekle(simSenaryo{ad: "d4_router_arkasi", aciklama: "Modemin arkasında router; yalnız modem kapatılır: kart ve ağ geçidi hiç kaybolmaz, UPnP dış IP özel aralıkta",
		onKontrol: func() btOnKontrol {
			o := kablolu()
			o.Bilgi["upnp"] = map[string]any{"durum": "var", "uptime_s": 500000, "baglanti": "Connected", "dis_ip": "192.168.0.10"}
			o.Bilgi["ikinci_yonlendirici"] = map[string]any{"ipucu": "olasi", "kanit": []string{"upnp_dis_ip_ozel", "ikinci_atlama_ozel"}, "ikinci_atlama": "192.168.0.1", "ikinci_atlama_ozel": true}
			return o
		}, baslangic: simDurum{kart: true, ag: true, upnp: true, uptime: 500000, disIP: "192.168.0.10"}, bitir: 150000,
		adimlar: []simAdim{{20000, func(d *simDurum) []btGozlem { d.disIP = ""; return nil }}, {140000, func(d *simDurum) []btGozlem { d.disIP = "192.168.0.10"; return nil }}}})
	ekle(simSenaryo{ad: "d5_hotspot_ucus", aciklama: "Telefon hotspot (192.168.43.1); telefonda uçuş modu: Wi-Fi düşer, ağ geçidi kaybolur",
		onKontrol: func() btOnKontrol {
			o := onKontrolWifi("192.168.43.1", "02:1A:11")
			o.Engeller = []string{"HOTSPOT_IPUCU"}
			o.Bilgi["hotspot_ipuclari"] = []string{"AG_GECIDI_BILINEN_HOTSPOT_ADRESI"}
			return o
		}, baslangic: acik, bitir: 90000, adimlar: []simAdim{
			{20000, kartDus("medya_baglantisi_yok")}, {60000, kartGel}, {64000, agGel}}})
	ekle(simSenaryo{ad: "d5b_usb_rndis", aciklama: "USB ile telefon bağlantısı (RNDIS, ağ geçidi 192.168.42.129)",
		onKontrol: func() btOnKontrol {
			o := onKontrolKablolu("192.168.42.129", "9E:4F:12")
			ti := o.Bilgi["test_arayuzu"].(map[string]any)
			ti["aciklama"], ti["ad"] = "Remote NDIS based Internet Sharing Device", "Ethernet 3"
			o.Engeller = []string{"HOTSPOT_IPUCU"}
			o.Bilgi["hotspot_ipuclari"] = []string{"ARAYUZ_RNDIS", "AG_GECIDI_BILINEN_HOTSPOT_ADRESI"}
			return o
		}, baslangic: acik, bitir: 60000, adimlar: []simAdim{
			{15000, kartDus("medya_baglantisi_yok")}, {35000, kartGel}, {37000, agGel}}})
	ekle(simSenaryo{ad: "d6_vpn", aciklama: "Ön kontrolde VPN varsayılan yolda; ardından d2 gibi",
		onKontrol: func() btOnKontrol {
			o := kablolu()
			o.Engeller = []string{"VPN_VARSAYILAN_YOLDA", "VPN_ARAYUZU_VAR"}
			o.Bilgi["vpn"] = map[string]any{"var": true, "varsayilan_yol_vpn": true, "arayuzler": []string{"TAP-Windows Adapter V9"}}
			return o
		}, baslangic: acik, bitir: 60000, adimlar: []simAdim{
			{10000, kartDus("medya_baglantisi_yok")}, {30000, kartGel}, {31000, agGel}}})
	ekle(simSenaryo{ad: "d6_coklu_kart", aciklama: "Wi-Fi + kablo birlikte açık; kablo çekilince yol Wi-Fi'ye geçer, ağ geçidi hiç kaybolmaz",
		onKontrol: func() btOnKontrol {
			o := kablolu()
			o.Engeller = []string{"COKLU_AKTIF_ARAYUZ"}
			o.Bilgi["aktif_arayuzler"] = []any{
				map[string]any{"no": 12, "tur": "ethernet", "aciklama": "Realtek PCIe GbE Family Controller", "ag_gecidi": "192.168.1.1", "varsayilan_yol": true, "metrik": 35},
				map[string]any{"no": 18, "tur": "wifi", "aciklama": "Intel(R) Wi-Fi 6 AX201 160MHz", "ag_gecidi": "192.168.1.1", "varsayilan_yol": true, "metrik": 55}}
			return o
		}, baslangic: acik, bitir: 60000, adimlar: []simAdim{
			{10000, func(d *simDurum) []btGozlem {
				return []btGozlem{{Tur: "kart", KartAcik: false, Neden: "medya_baglantisi_yok"},
					{Tur: "yol", Veri: map[string]any{"onceki": map[string]any{"arayuz_no": 12, "ag_gecidi": "192.168.1.1"}, "yeni": map[string]any{"arayuz_no": 18, "ag_gecidi": "192.168.1.1"}}}}
			}}, {30000, func(d *simDurum) []btGozlem {
				return []btGozlem{{Tur: "kart", KartAcik: true},
					{Tur: "yol", Veri: map[string]any{"onceki": map[string]any{"arayuz_no": 18, "ag_gecidi": "192.168.1.1"}, "yeni": map[string]any{"arayuz_no": 12, "ag_gecidi": "192.168.1.1"}}}}
			}}}})
	ekle(simSenaryo{ad: "d6_uyku", aciklama: "İzleme sırasında bilgisayar 40 sn uyur (kapak kapatma): uyku/uyanma + yoklama boşluğu",
		onKontrol: kablolu, baslangic: acik, bitir: 90000, adimlar: []simAdim{
			{20000, func(d *simDurum) []btGozlem {
				d.uyuyor = true
				return []btGozlem{{Tur: "guc", Veri: map[string]any{"tur": "uyku", "neden": "kapak_kapatildi"}}}
			}},
			{60000, func(d *simDurum) []btGozlem {
				d.uyuyor = false
				return []btGozlem{{Tur: "guc", Veri: map[string]any{"tur": "uyanma"}}}
			}}}})
	ekle(simSenaryo{ad: "d6_program_kapatildi", aciklama: "Test sürerken program kapatılır: kalp atışı 15 sn kesilir, yeniden açılışta yarım rapor",
		onKontrol: kablolu, baslangic: acik, adimlar: []simAdim{
			{10000, kartDus("medya_baglantisi_yok")},
			{20000, func(d *simDurum) []btGozlem {
				return []btGozlem{{Tur: "program_kapat", Veri: map[string]any{"sure_ms": float64(15000)}}}
			}}}})
	ekle(simSenaryo{ad: "son_izleme_dalgalanma", aciklama: "d1 + son izleme penceresinde ağ geçidi 3 sn kaybolup gelir",
		onKontrol: kablolu, baslangic: acik, bitir: 200000, adimlar: []simAdim{
			{10000, kartDus("medya_baglantisi_yok")}, {130000, kartGel}, {170000, agGel},
			{215000, agGit}, {218000, agGel}}})
	ekle(simSenaryo{ad: "rapor_kuyrukta", aciklama: "d2 + ilk 3 rapor POST'u ağ hatası, sonra başarı (üstel geri çekilme)",
		onKontrol: kablolu, baslangic: acik, bitir: 60000, simHata: 3, adimlar: []simAdim{
			{10000, kartDus("medya_baglantisi_yok")}, {30000, kartGel}, {31000, agGel}}})
	ekle(simSenaryo{ad: "upnp_sifirlandi", aciklama: "d1 + UPnP açık: modem açılınca Uptime sıfırlanır, dış IP aynı kalır",
		onKontrol: func() btOnKontrol {
			o := kablolu()
			o.Bilgi["upnp"] = map[string]any{"durum": "var", "uptime_s": 86400, "baglanti": "Connected", "dis_ip": "81.214.10.20"}
			return o
		}, baslangic: simDurum{kart: true, ag: true, upnp: true, uptime: 86400, disIP: "81.214.10.20"}, bitir: 230000, adimlar: []simAdim{
			{10000, kartDus("medya_baglantisi_yok")}, {130000, kartGel},
			{170000, func(d *simDurum) []btGozlem { d.ag = true; d.uptime = 15; return agGel(d) }}}})
	ekle(simSenaryo{ad: "upnp_dis_ip_degisti", aciklama: "d1 + UPnP: modem açılınca dış IP değişir (statik değil)",
		onKontrol: func() btOnKontrol {
			o := kablolu()
			o.Bilgi["upnp"] = map[string]any{"durum": "var", "uptime_s": 86400, "baglanti": "Connected", "dis_ip": "81.214.10.20"}
			return o
		}, baslangic: simDurum{kart: true, ag: true, upnp: true, uptime: 86400, disIP: "81.214.10.20"}, bitir: 230000, adimlar: []simAdim{
			{10000, kartDus("medya_baglantisi_yok")}, {130000, kartGel},
			{170000, func(d *simDurum) []btGozlem { d.ag = true; d.uptime = 15; d.disIP = "78.188.44.55"; return agGel(d) }}}})
}

func simSenaryoListesi() string {
	var adlar []string
	for ad := range simSenaryolar {
		adlar = append(adlar, ad)
	}
	sort.Strings(adlar)
	var b strings.Builder
	for _, ad := range adlar {
		fmt.Fprintf(&b, "  %-24s %s\n", ad, simSenaryolar[ad].aciklama)
	}
	return b.String()
}

// simGozlemci, bir senaryoyu oynatan btGozlemci.
type simGozlemci struct {
	s       simSenaryo
	saat    func() *btSaat // aktif testin saati (izleme başlangıcı = senaryo 0)
	bitirFn func()         // senaryo bitir zamanı geldiğinde
}

func (g *simGozlemci) OnKontrol(ctx context.Context, p btParametreler, hedef string) (btOnKontrol, error) {
	o := g.s.onKontrol()
	if y, ok := o.Bilgi["yol"].(map[string]any); ok {
		y["hedef"] = hedef
	}
	if ti, ok := o.Bilgi["test_arayuzu"].(map[string]any); ok {
		ti["dhcp_kira_baslangic"] = time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339)
	}
	select {
	case <-time.After(300 * time.Millisecond): // gerçek ön kontrol de bir süre alır
	case <-ctx.Done():
	}
	return o, nil
}

func (g *simGozlemci) Izle(ctx context.Context, p btParametreler, cikis chan<- btGozlem) {
	saat := g.saat()
	d := g.s.baslangic
	adimlar := append([]simAdim{}, g.s.adimlar...)
	bas := saat.ms()
	yolla := func(gl btGozlem) bool {
		select {
		case cikis <- gl:
			return true
		case <-ctx.Done():
			return false
		}
	}
	yoklamaT := time.NewTicker(saat.gercek(p.YoklamaAraligiMs))
	defer yoklamaT.Stop()
	upnpT := time.NewTicker(saat.gercek(p.UPnPAraligiMs))
	defer upnpT.Stop()
	if d.upnp && p.UPnP {
		yolla(btGozlem{Tur: "upnp", Veri: map[string]any{"uptime_s": d.uptime, "dis_ip": d.disIP, "baglanti": "Connected"}})
	}
	bitirildi := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-upnpT.C:
			if d.upnp && p.UPnP && d.ag {
				d.uptime += float64(p.UPnPAraligiMs) / 1000
				bag := "Connected"
				if d.disIP == "" {
					bag = "Disconnected"
				}
				if !yolla(btGozlem{Tur: "upnp", Veri: map[string]any{"uptime_s": d.uptime, "dis_ip": d.disIP, "baglanti": bag}}) {
					return
				}
			}
		case <-yoklamaT.C:
			simdi := saat.ms() - bas
			for len(adimlar) > 0 && adimlar[0].t <= simdi {
				for _, gl := range adimlar[0].fn(&d) {
					if !yolla(gl) {
						return
					}
				}
				adimlar = adimlar[1:]
			}
			if g.s.bitir > 0 && simdi >= g.s.bitir && !bitirildi {
				bitirildi = true
				g.bitirFn()
			}
			if d.uyuyor {
				continue
			}
			arp, onb := "yok", "unreachable"
			tcp := map[int]string{}
			canli := d.kart && d.ag
			if canli {
				arp, onb = "cevap", "reachable"
			}
			if d.arpYok {
				arp, onb = "yok_destek", ""
			}
			for _, port := range p.TCPPortlari {
				switch {
				case !canli:
					tcp[port] = "zaman_asimi"
				case port == 443:
					tcp[port] = "reddedildi"
				default:
					tcp[port] = "acik"
				}
			}
			if !yolla(btGozlem{Tur: "yoklama", ARP: arp, Onbellek: onb, TCP: tcp}) {
				return
			}
		}
	}
}
