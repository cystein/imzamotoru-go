//go:build windows

package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ebfe/scard"
)

// PcscKategori, pcscTeshisi()'nin ürettiği serbest metin teşhisi makine tarafından da
// ayırt edilebilsin diye (kullanıcıya doğru mesajı seçmek, dedup kararı vermek için)
// döndürdüğü durumlardan biridir.
type PcscKategori int

const (
	PcscBilinmiyor PcscKategori = iota
	PcscKaynakYoneticisiKapali
	PcscOkuyucuYok
	PcscOkuyucuVarSurucuGerekli
)

// pcscTeshisi, PKCS#11 DLL'i hiç bulunamadığında/başlatılamadığında bile Windows'a gömülü
// PC/SC servisi (winscard.dll, ayrı bir işletim sistemi katmanı — PKCS#11 sürücüsüne ihtiyaç
// duymaz) üzerinden okuyucu adlarını ve takılı kartın ATR'sini okumayı dener. Bu sayede
// "sürücü yok" bildiriminde şu ayrımı da yapabiliyoruz: okuyucu hiç bağlı değil mi, okuyucu
// bağlı ama kart takılı değil mi, yoksa kart takılı ve PC/SC seviyesinde okunabiliyor ama
// bizim aday listemizde olmayan bir PKCS#11 sürücüsü mü gerekiyor.
func pcscTeshisi() (PcscKategori, string) {
	s := pcscTara()
	return s.Kategori, s.Detay
}

// pcscTara, pcscTeshisi'nin yapılandırılmış hâlidir (v1.5.0): okuyucu başına ATR ve kartın
// ATR'den tanınan ailesi (kart_tanima.go) de döner — sürücü önerisi buradan üretiliyor.
func pcscTara() PcscSonuc {
	ctx, err := scard.EstablishContext()
	if err != nil {
		// Windows 8+ okuyucu takılı değilken Akıllı Kart hizmetini kendiliğinden durdurabiliyor;
		// bu durumda da buraya düşülür. Kullanıcı mesajı ikisini birlikte anıyor.
		return PcscSonuc{Kategori: PcscKaynakYoneticisiKapali, Detay: fmt.Sprintf("PC/SC bağlamı kurulamadı: %v", err)}
	}
	defer ctx.Release()

	okuyucular, err := ctx.ListReaders()
	if err != nil {
		// 0x8010002E SCARD_E_NO_READERS_AVAILABLE "okuyucu yok" demek, hizmet kapalı DEĞİL.
		// v1.4.1'e kadar bu da "hizmet kapalı" sayılıyor ve eczacıya yanlış mesaj gidiyordu.
		if errors.Is(err, scard.ErrNoReadersAvailable) {
			return PcscSonuc{Kategori: PcscOkuyucuYok, Detay: fmt.Sprintf("Sistemde hiçbir akıllı kart okuyucu görünmüyor (%v)", err)}
		}
		return PcscSonuc{Kategori: PcscKaynakYoneticisiKapali, Detay: fmt.Sprintf("PC/SC okuyucu listesi alınamadı: %v", err)}
	}
	if len(okuyucular) == 0 {
		return PcscSonuc{Kategori: PcscOkuyucuYok, Detay: "Sistemde hiçbir akıllı kart okuyucu görünmüyor (PC/SC seviyesinde)"}
	}

	sonuc := PcscSonuc{Kategori: PcscOkuyucuVarSurucuGerekli}
	var satirlar []string
	for _, ad := range okuyucular {
		kart, err := ctx.Connect(ad, scard.ShareShared, scard.ProtocolAny)
		if err != nil {
			satirlar = append(satirlar, fmt.Sprintf("%s: kart bağlanamadı (%v) — okuyucu bağlı, kart takılı olmayabilir", ad, err))
			sonuc.Okuyucular = append(sonuc.Okuyucular, OkuyucuDurumu{Ad: ad})
			continue
		}
		durum, err := kart.Status()
		kart.Disconnect(scard.LeaveCard)
		if err != nil {
			satirlar = append(satirlar, fmt.Sprintf("%s: bağlandı ama durum okunamadı (%v)", ad, err))
			sonuc.Okuyucular = append(sonuc.Okuyucular, OkuyucuDurumu{Ad: ad})
			continue
		}
		aile := kartAilesiBul(durum.Atr, ad)
		satirlar = append(satirlar, fmt.Sprintf("%s: ATR=% X [kart: %s]", ad, durum.Atr, aile))
		sonuc.Okuyucular = append(sonuc.Okuyucular, OkuyucuDurumu{Ad: ad, ATR: fmt.Sprintf("% X", durum.Atr), KartVar: true, Aile: aile})
	}
	sonuc.Detay = strings.Join(satirlar, " | ")
	return sonuc
}
