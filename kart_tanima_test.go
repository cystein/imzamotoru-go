package main

import "testing"

// Sahadan (imza-motoru-olaylar.log, 2026-08..11) toplanan gerçek ATR'ler.
func TestKartAilesiBul(t *testing.T) {
	durumlar := []struct {
		atr, okuyucu string
		bekle        KartAilesi
	}{
		{"3B 9F 96 81 31 FE 45 80 67 55 45 4B 41 45 12 93 31 80 73 B3 A1 80 6B", "ACS ACR39U ICC Reader 0", KartAKIS},
		{"3B 9F 96 81 31 FE 45 80 67 55 45 4B 41 45 12 92 31 80 73 B3 A1 80 6A", "ACS ACR39U ICC Reader 0", KartAKIS},
		{"3B 9F 97 81 31 FE 45 80 65 54 43 D3 23 02 31 C0 73 F6 21 80 81 05 52", "ACS CCID USB Reader 0", KartAKIS},
		{"3B 9F 97 81 31 FE 45 80 65 54 43 D2 21 08 31 C0 73 F6 21 80 81 05 5B", "Feitian SCR301 0", KartAKIS},
		{"3B 9F 97 81 31 FE 45 80 65 54 43 D3 22 82 31 C0 73 F6 21 80 81 05 D3", "ACS ACR39U ICC Reader 0", KartAKIS},
		{"3B D5 18 00 81 31 FE 7D 80 73 C8 21 10 F4", "AKS ifdh 0", KartSafeNet},
		{"3B D5 18 00 81 31 FE 7D 80 73 C8 21 10 F4", "Başka Okuyucu 0", KartSafeNet},
		{"3B 00", "Aladdin Token JC 0", KartSafeNet},
		{"3B F8 18 00 FF 81 31 FE 45 4A 43 4F 50 76 32 34 31 43", "ARKSIGNER ARK-IMZA 0", KartJCOP},
		{"3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 01 00 00 00 00 6A", "ACS ACR39U ICC Reader 0", KartBilinmiyor},
	}
	for _, d := range durumlar {
		if g := kartAilesiBul(atrCoz(d.atr), d.okuyucu); g != d.bekle {
			t.Errorf("%s / %s: beklenen %s, gelen %s", d.atr, d.okuyucu, d.bekle, g)
		}
	}
}

func TestSurucuOnerisi(t *testing.T) {
	akis := OkuyucuDurumu{Ad: "ACS ACR39U ICC Reader 0", ATR: "3B 9F ...", KartVar: true, Aile: KartAKIS}
	safenet := OkuyucuDurumu{Ad: "AKS ifdh 0", KartVar: true, Aile: KartSafeNet}
	bos := OkuyucuDurumu{Ad: "AKS VR 0"}
	kart := func(o ...OkuyucuDurumu) PcscSonuc { return PcscSonuc{Kategori: PcscOkuyucuVarSurucuGerekli, Okuyucular: o} }
	kod := func(o *SurucuOnerisi) string {
		if o == nil {
			return ""
		}
		return o.Kod
	}
	durumlar := []struct {
		ad    string
		s     PcscSonuc
		yuklu []string
		bekle string
	}{
		{"hizmet kapalı", PcscSonuc{Kategori: PcscKaynakYoneticisiKapali}, nil, OneriServisKapali},
		{"okuyucu yok", PcscSonuc{Kategori: PcscOkuyucuYok}, nil, OneriOkuyucuYok},
		{"linux", PcscSonuc{Kategori: PcscBilinmiyor}, nil, ""},
		{"okuyucu var kart yok", kart(bos), nil, OneriKartYok},
		{"AKİS kart, sürücü yok", kart(bos, akis), nil, OneriAkisYok},
		{"AKİS kart, yalnız SafeNet yüklü", kart(akis), []string{`C:\Windows\System32\eTPKCS11.dll`}, OneriAkisYok},
		{"AKİS kart, AKİS yüklü", kart(akis), []string{`C:\Windows\System32\akisp11.dll`}, ""},
		{"SafeNet, yalnız AKİS yüklü", kart(safenet), []string{`C:\Windows\System32\akisp11.dll`}, OneriSafeNetYok},
		{"SafeNet, SafeNet yüklü", kart(safenet), []string{`C:\Windows\System32\eTPKCS11.dll`}, ""},
		{"bilinmeyen kart", kart(OkuyucuDurumu{Ad: "X", KartVar: true, Aile: KartBilinmiyor}), nil, OneriBilinmeyenKart},
		{"tanınan kart bilinmeyenden önce", kart(OkuyucuDurumu{Ad: "X", KartVar: true, Aile: KartBilinmiyor}, akis), nil, OneriAkisYok},
	}
	for _, d := range durumlar {
		o := surucuOnerisiBelirle(d.s, d.yuklu)
		if kod(o) != d.bekle {
			t.Errorf("%s: beklenen %q, gelen %q", d.ad, d.bekle, kod(o))
		}
		if o != nil && o.Mesaj == "" {
			t.Errorf("%s: mesaj boş", d.ad)
		}
	}
}
