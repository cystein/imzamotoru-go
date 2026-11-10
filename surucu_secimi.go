package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

// ============================================================================
// ÇOKLU PKCS#11 SÜRÜCÜSÜ SEÇİMİ (v1.4.1, EL_KITABI §9.14)
// ============================================================================
//
// Eskiden initDriver() C_Initialize'ı geçen İLK DLL'i seçip onunla kalıyordu ve her işlem
// slots[0]'ı kullanıyordu. 2026-11-05 vakası: makinede hem AKİS (akisp11.dll) hem SafeNet
// (eTPKCS11.dll) kurulu, kart bir E-GÜVEN eToken'ı. Listede önce gelen AKİS başlatıldı, eToken'ı
// slot olarak gördü ama C_OpenSession üretici tanımlı 0x80000007 döndürdü — imza atılamadı.
//
// Artık başlatılabilen TÜM sürücüler yüklü tutuluyor ve her işlemde kartı GERÇEKTEN açabilen
// sürücü+slot seçiliyor (sırası: driver.txt'teki özel yol, sonra driverAdaylari sırası). Kart
// sonradan takılsa ya da başka bir sürücünün kartı takılsa bile yeniden başlatma gerekmiyor.

// yukluSurucu, C_Initialize'ı başarıyla geçmiş bir PKCS#11 kütüphanesidir.
type yukluSurucu struct {
	Yol   string
	P     *pkcs11.Ctx
	Bilgi string // C_GetInfo özeti (üretici, açıklama, sürüm) — tanılama raporu için
}

// surucuSeti, aynı süreçte yüklü tüm sürücüler. Yalnız cardWorker iş parçacığından kullanılır
// (PKCS#11 çağrıları OS thread'e kilitli), bu yüzden kendi içinde kilit gerekmiyor.
type surucuSeti struct {
	surucular []yukluSurucu
	denenmis  map[string]bool // yeniSuruculeriYukle'nin daha önce denediği yollar (küçük harf)
}

// yollar, yüklü sürücülerin tam yolları (sürücü önerisi için).
func (s *surucuSeti) yollar() []string {
	var y []string
	for _, d := range s.surucular {
		y = append(y, d.Yol)
	}
	return y
}

// kartOturumu, açık bir PKCS#11 oturumudur; Kapat() ile kapatılmalıdır.
type kartOturumu struct {
	p       *pkcs11.Ctx
	slot    uint
	session pkcs11.SessionHandle
	surucu  string
}

func (k *kartOturumu) Kapat() { k.p.CloseSession(k.session) }

// surucuBilgisi, C_GetInfo'dan okunabilir tek satırlık bir özet üretir.
func surucuBilgisi(p *pkcs11.Ctx) string {
	info, err := p.GetInfo()
	if err != nil {
		return fmt.Sprintf("C_GetInfo hatası: %v", err)
	}
	return fmt.Sprintf("%s / %s / kütüphane %d.%d",
		strings.TrimSpace(info.ManufacturerID), strings.TrimSpace(info.LibraryDescription),
		info.LibraryVersion.Major, info.LibraryVersion.Minor)
}

func yeniYukluSurucu(yol string, p *pkcs11.Ctx) yukluSurucu {
	s := yukluSurucu{Yol: yol, P: p, Bilgi: surucuBilgisi(p)}
	log.Printf("[WORKER] ✅ Sürücü yüklendi: %s (%s)", yol, s.Bilgi)
	return s
}

// Tanılama raporu başka bir goroutine'den (tepsi menüsü) okunduğu için sürücü özeti ayrıca
// kilitli bir değişkende tutuluyor — rapor PKCS#11'e hiç dokunmuyor.
var (
	surucuOzetiMu       sync.Mutex
	yukluSurucuOzeti    string   // "yol (bilgi)" satırları
	yukluSurucuYollari  []string // tanılama raporundaki sürücü önerisi için
	sonKullanilanSurucu string   // en son oturum açılabilen sürücü + kart
)

func surucuOzetiniKaydet(s *surucuSeti) {
	var satirlar []string
	for _, d := range s.surucular {
		satirlar = append(satirlar, fmt.Sprintf("%s (%s)", d.Yol, d.Bilgi))
	}
	surucuOzetiMu.Lock()
	yukluSurucuOzeti = strings.Join(satirlar, " | ")
	yukluSurucuYollari = s.yollar()
	surucuOzetiMu.Unlock()
}

func sonKullanilanSurucuyuKaydet(k *kartOturumu) {
	etiket := ""
	if info, err := k.p.GetTokenInfo(k.slot); err == nil {
		etiket = fmt.Sprintf(" — kart: %s (%s %s)", strings.TrimSpace(info.Label),
			strings.TrimSpace(info.ManufacturerID), strings.TrimSpace(info.Model))
	}
	surucuOzetiMu.Lock()
	sonKullanilanSurucu = fmt.Sprintf("%s, slot %d%s", k.surucu, k.slot, etiket)
	surucuOzetiMu.Unlock()
}

// surucuRaporSatirlari, tanılama raporuna eklenecek iki satırı döndürür.
func surucuRaporSatirlari() (yuklu, sonKullanilan string) {
	surucuOzetiMu.Lock()
	defer surucuOzetiMu.Unlock()
	yuklu, sonKullanilan = yukluSurucuOzeti, sonKullanilanSurucu
	if yuklu == "" {
		yuklu = "yok"
	}
	if sonKullanilan == "" {
		sonKullanilan = "henüz kart oturumu açılmadı"
	}
	return
}

// ErrKartYok: hiçbir yüklü sürücü kartlı bir slot görmüyor.
var ErrKartYok = errors.New("kart takılı değil")

// oturumHatasiMesaji, oturum açılamayan slotların hatalarını eczacıya/destek ekibine gösterilecek
// tek bir mesaja çevirir. 0x8000xxxx (CKR_VENDOR_DEFINED) kodları sürücünün kendine özgüdür ve
// pratikte "bu kart bu sürücüyle açılmıyor" anlamına geliyor.
func oturumHatasiMesaji(hatalar []string) error {
	ipucu := ""
	for _, h := range hatalar {
		if strings.Contains(h, "0x8") {
			ipucu = " Kartınızın kendi üreticisinin sürücüsü kurulu olmayabilir ya da güncel değil (E-GÜVEN/SafeNet eToken için SafeNet Authentication Client, AKİS kart için AKİS sürücüsü)."
			break
		}
	}
	return &kartHatasi{mesaj: fmt.Sprintf("Kart oturumu açılamadı: %s.%s", strings.Join(hatalar, "; "), ipucu), neden: ErrKartAcilamadi}
}

// kartOturumlari, kartı açılabilen her (sürücü, slot) için fn'i çağırır. fn true dönerse oturum
// açık bırakılır ve çağırana verilir; false dönerse oturum kapatılır ve aramaya devam edilir.
// Hiçbir slot kabul edilmezse: hiç kartlı slot yoksa ErrKartYok; en az bir oturum açıldı ama fn
// hiçbirini kabul etmediyse (nil, nil); hiçbir oturum açılamadıysa ayrıntılı hata döner.
func (s *surucuSeti) kartOturumlari(fn func(*kartOturumu) bool) (*kartOturumu, error) {
	kartliSlotVar, oturumAcildi := false, false
	var hatalar []string
	for _, d := range s.surucular {
		slots, err := d.P.GetSlotList(true)
		if err != nil {
			hatalar = append(hatalar, fmt.Sprintf("%s: slot listesi alınamadı (%v)", d.Yol, err))
			continue
		}
		for _, slot := range slots {
			kartliSlotVar = true
			session, err := d.P.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
			if err != nil {
				log.Printf("[WORKER] ⚠️ %s slot %d: oturum açılamadı: %v — sıradaki deneniyor", d.Yol, slot, err)
				hatalar = append(hatalar, fmt.Sprintf("%s slot %d: %v", d.Yol, slot, err))
				continue
			}
			oturumAcildi = true
			k := &kartOturumu{p: d.P, slot: slot, session: session, surucu: d.Yol}
			if fn(k) {
				sonKullanilanSurucuyuKaydet(k)
				return k, nil
			}
			k.Kapat()
		}
	}
	if !kartliSlotVar {
		return nil, ErrKartYok
	}
	if !oturumAcildi && len(hatalar) > 0 {
		return nil, oturumHatasiMesaji(hatalar)
	}
	return nil, nil
}

// sertifikaOturumuAc, verilen CKA_ID'li sertifikayı taşıyan kartta oturum açar. Sertifika
// nesneleri genel (public) olduğu için Login'den önce aranabiliyor.
func (s *surucuSeti) sertifikaOturumuAc(certID []byte) (*kartOturumu, error) {
	k, err := s.kartOturumlari(func(k *kartOturumu) bool {
		k.p.FindObjectsInit(k.session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
			pkcs11.NewAttribute(pkcs11.CKA_ID, certID),
		})
		objs, _, _ := k.p.FindObjects(k.session, 1)
		k.p.FindObjectsFinal(k.session)
		return len(objs) > 0
	})
	if err != nil {
		return nil, err
	}
	if k == nil {
		return nil, fmt.Errorf("Seçilen sertifika takılı kartlarda bulunamadı. Kartı çıkarıp taktıysanız sayfayı yenileyip sertifikayı yeniden seçin.")
	}
	return k, nil
}

// sertifikaParmakIzi, aynı kartı iki ayrı sürücü görürse listede çift göstermemek için.
func sertifikaParmakIzi(der []byte) [32]byte { return sha256.Sum256(der) }

// yukluYollarKopyasi, tanılama raporu (tepsi goroutine'i) için yüklü sürücü yollarının kopyası.
func yukluYollarKopyasi() []string {
	surucuOzetiMu.Lock()
	defer surucuOzetiMu.Unlock()
	return append([]string(nil), yukluSurucuYollari...)
}

// bilgi, yüklü bir sürücünün C_GetInfo özetini döndürür.
func (s *surucuSeti) bilgi(yol string) string {
	for _, d := range s.surucular {
		if d.Yol == yol {
			return d.Bilgi
		}
	}
	return ""
}
