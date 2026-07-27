//go:build windows

package main

import (
	"fmt"
	"strings"

	"github.com/ebfe/scard"
)

// pcscTeshisi, PKCS#11 DLL'i hiç bulunamadığında/başlatılamadığında bile Windows'a gömülü
// PC/SC servisi (winscard.dll, ayrı bir işletim sistemi katmanı — PKCS#11 sürücüsüne ihtiyaç
// duymaz) üzerinden okuyucu adlarını ve takılı kartın ATR'sini okumayı dener. Bu sayede
// "sürücü yok" bildiriminde şu ayrımı da yapabiliyoruz: okuyucu hiç bağlı değil mi, okuyucu
// bağlı ama kart takılı değil mi, yoksa kart takılı ve PC/SC seviyesinde okunabiliyor ama
// bizim aday listemizde olmayan bir PKCS#11 sürücüsü mü gerekiyor.
func pcscTeshisi() string {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return fmt.Sprintf("PC/SC bağlamı kurulamadı: %v", err)
	}
	defer ctx.Release()

	okuyucular, err := ctx.ListReaders()
	if err != nil {
		return fmt.Sprintf("PC/SC okuyucu listesi alınamadı: %v", err)
	}
	if len(okuyucular) == 0 {
		return "Sistemde hiçbir akıllı kart okuyucu görünmüyor (PC/SC seviyesinde)"
	}

	var satirlar []string
	for _, ad := range okuyucular {
		kart, err := ctx.Connect(ad, scard.ShareShared, scard.ProtocolAny)
		if err != nil {
			satirlar = append(satirlar, fmt.Sprintf("%s: kart bağlanamadı (%v) — okuyucu bağlı, kart takılı olmayabilir", ad, err))
			continue
		}
		durum, err := kart.Status()
		kart.Disconnect(scard.LeaveCard)
		if err != nil {
			satirlar = append(satirlar, fmt.Sprintf("%s: bağlandı ama durum okunamadı (%v)", ad, err))
			continue
		}
		satirlar = append(satirlar, fmt.Sprintf("%s: ATR=% X", ad, durum.Atr))
	}
	return strings.Join(satirlar, " | ")
}
