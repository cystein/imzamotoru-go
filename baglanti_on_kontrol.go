package main

// Ön kontrolün platformdan bağımsız son adımı (v2.1.0, PROTOKOL §4.2–4.5):
//   - beklenen_arayuz (sayfada eczacının seçtiği: ethernet | wifi | hotspot) ile bulunan bağlantı türünü
//     karşılaştırır → uyuşmazsa ARAYUZ_UYUSMAZ;
//   - her engel için eczacıya gösterilebilecek sade Türkçe mesaj üretir (engel_mesajlari), bağlantı
//     adlarıyla birlikte ("Ethernet (Realtek…) ve Wi-Fi (Intel…)").
// Karar yine sunucuda: hangi engellerin testi durduracağını sunucu parametreler.durduran_engeller ile söyler.

import (
	"fmt"
	"strings"
)

var beklenenArayuzDegerleri = map[string]bool{"ethernet": true, "wifi": true, "hotspot": true}

func turAdi(tur string) string {
	switch tur {
	case "ethernet":
		return "Ethernet (kablo)"
	case "wifi":
		return "Wi-Fi"
	case "mobil":
		return "mobil geniş bant"
	case "hotspot":
		return "telefon internet paylaşımı (hotspot)"
	case "tunel":
		return "VPN"
	case "sanal":
		return "sanal bağlantı"
	}
	return "bilinmeyen bağlantı"
}

func dizi(v any) []string {
	var s []string
	switch x := v.(type) {
	case []string:
		s = x
	case []any:
		for _, e := range x {
			if t, ok := e.(string); ok {
				s = append(s, t)
			}
		}
	}
	return s
}

// bulunanArayuz: test arayüzünün eczacının seçimiyle karşılaştırılabilir türü.
func bulunanArayuz(bilgi map[string]any) string {
	if len(dizi(bilgi["hotspot_ipuclari"])) > 0 {
		return "hotspot"
	}
	ti, _ := bilgi["test_arayuzu"].(map[string]any)
	tur, _ := ti["tur"].(string)
	if tur == "mobil" {
		return "hotspot"
	}
	if tur == "" {
		return "bilinmiyor"
	}
	return tur
}

// arayuzEtiketi: "Wi-Fi (Intel(R) Wi-Fi 6 AX201)" gibi okunur ad.
func arayuzEtiketi(a map[string]any) string {
	tur, _ := a["tur"].(string)
	ad, _ := a["aciklama"].(string)
	if ad == "" {
		ad, _ = a["ad"].(string)
	}
	kisa := map[string]string{"ethernet": "Ethernet", "wifi": "Wi-Fi", "mobil": "mobil geniş bant"}[tur]
	if kisa == "" {
		kisa = turAdi(tur)
	}
	if ad == "" {
		return kisa
	}
	return fmt.Sprintf("%s (%s)", kisa, ad)
}

func engelEkle(o *btOnKontrol, kod string) {
	for _, e := range o.Engeller {
		if e == kod {
			return
		}
	}
	o.Engeller = append(o.Engeller, kod)
}

// onKontrolTamamla: beklenen arayüz denetimi + engel mesajları. o.Bilgi dolu olmalı.
func onKontrolTamamla(o *btOnKontrol, beklenen string) {
	bulunan := bulunanArayuz(o.Bilgi)
	o.Bilgi["bulunan_arayuz"] = bulunan
	if beklenen != "" {
		o.Bilgi["beklenen_arayuz"] = beklenen
		if bulunan != beklenen {
			engelEkle(o, "ARAYUZ_UYUSMAZ")
		}
	}
	mesajlar := map[string]string{}
	var fiziksel []string
	if l, ok := o.Bilgi["aktif_arayuzler"].([]any); ok {
		for _, e := range l {
			if a, ok := e.(map[string]any); ok {
				fiziksel = append(fiziksel, arayuzEtiketi(a))
			}
		}
	}
	for _, kod := range o.Engeller {
		switch kod {
		case "COKLU_AKTIF_ARAYUZ":
			adlar := strings.Join(fiziksel, " ve ")
			if adlar == "" {
				adlar = "birden fazla bağlantı"
			}
			mesajlar[kod] = fmt.Sprintf("Bilgisayarınız aynı anda %s ile bağlı. Test için yalnızca birini açık bırakın: Ethernet kablosunu çıkarın ya da Wi-Fi'yi kapatın, sonra yeniden kontrol edin.", adlar)
		case "ARAYUZ_UYUSMAZ":
			mesajlar[kod] = fmt.Sprintf("%s seçtiniz ama bilgisayarınız %s ile bağlı. Seçiminizi düzeltin ya da bilgisayarı seçtiğiniz bağlantıya geçirin, sonra yeniden kontrol edin.",
				turAdi(beklenen), turAdi(bulunan))
		case "VPN_VARSAYILAN_YOLDA":
			mesajlar[kod] = "İnternet trafiğiniz bir VPN programı üzerinden gidiyor. Test için VPN'i kapatın (programın simgesinden bağlantıyı kesin), sonra yeniden kontrol edin."
		case "VPN_ARAYUZU_VAR":
			vpn, _ := o.Bilgi["vpn"].(map[string]any)
			adlar := strings.Join(dizi(vpn["arayuzler"]), ", ")
			mesajlar[kod] = fmt.Sprintf("Bilgisayarda açık bir VPN bağlantısı var (%s). Test için bağlantısını kesin, sonra yeniden kontrol edin.", adlar)
		case "SANAL_ARAYUZ":
			mesajlar[kod] = "Bilgisayarınız internete sanal bir bağlantı üzerinden çıkıyor. Testi gerçek ağ bağlantısıyla (kablo ya da Wi-Fi) yapın."
		case "HOTSPOT_IPUCU":
			mesajlar[kod] = "Bilgisayarınız bir cep telefonunun internet paylaşımına bağlı görünüyor."
		case "AG_GECIDI_ERISILEMEZ":
			mesajlar[kod] = "Modeminize ulaşılamıyor. İnternet bağlantınızı kontrol edip yeniden deneyin."
		case "VARSAYILAN_YOL_YOK", "AG_GECIDI_YOK", "IPV4_YOK":
			mesajlar[kod] = "Bilgisayarınızın internet bağlantısı bulunamadı. Bağlantınızı kontrol edip yeniden deneyin."
		case "ARP_DESTEKLENMIYOR":
			mesajlar[kod] = "Bu bağlantı türünde modem doğrudan izlenemiyor; ölçüm daha sınırlı olacak."
		}
	}
	o.Bilgi["engel_mesajlari"] = mesajlar
}

// durduranEngeller: sunucunun "testi başlatma" dediği engellerden bu ön kontrolde bulunanlar.
func durduranEngeller(o btOnKontrol, liste []string) []string {
	var d []string
	for _, k := range liste {
		for _, e := range o.Engeller {
			if e == k {
				d = append(d, k)
			}
		}
	}
	return d
}
