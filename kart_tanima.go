package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/miekg/pkcs11"
)

// ============================================================================
// KART TANIMA VE SÜRÜCÜ ÖNERİSİ (v1.5.0, EL_KITABI §9.15)
// ============================================================================
//
// Eczacının en çok zorlandığı adım, elindeki karta uygun sürücüyü bulup kurmak. PC/SC katmanı
// (Windows'un kendisi) sürücü kurulu olmasa bile okuyucu adını ve kartın ATR'sini veriyor. ATR,
// kartın işletim sistemini belli eden kimlik baytlarıdır. 2026-11-10'daki kayıt incelemesinde
// sürücü sorunu yaşayan 45 kartlı makinenin 43'ü AKİS, 1'i SafeNet eToken, 1'i genel bir JCOP
// kartıydı. Buradan kartın ailesi, oradan da gereken sürücü kesin bilinebiliyor.
//
// Motor yalnız bir öneri KODU üretir. Eczacıya gösterilen ayrıntılı rehber (indirme bağlantısı,
// adımlar) web sayfasında durur, böylece bağlantı değişince motor sürümü çıkarmak gerekmez.

// KartAilesi, ATR'den tanınan kart işletim sistemi ailesi.
type KartAilesi string

const (
	KartAKIS       KartAilesi = "AKIS"       // TÜBİTAK BİLGEM AKİS — Kamu SM, ArkSigner, E-Tuğra, TÜRKTRUST kartlarının çoğu
	KartSafeNet    KartAilesi = "SAFENET"    // Thales/Gemalto SafeNet eToken — E-GÜVEN
	KartJCOP       KartAilesi = "JCOP"       // NXP JCOP genel Java kart — sürücü ATR'den belli olmuyor
	KartBilinmiyor KartAilesi = "BILINMIYOR" // tanınmayan ATR
)

// OkuyucuDurumu, PC/SC'nin gördüğü bir okuyucu ve (varsa) içindeki kart.
type OkuyucuDurumu struct {
	Ad      string     `json:"okuyucu"`
	ATR     string     `json:"atr,omitempty"`
	KartVar bool       `json:"kart_var"`
	Aile    KartAilesi `json:"kart_ailesi,omitempty"`
}

// PcscSonuc, pcscTara()'nın yapılandırılmış sonucu.
type PcscSonuc struct {
	Kategori   PcscKategori
	Detay      string
	Okuyucular []OkuyucuDurumu
}

// kartAilesiBul, ATR'yi ve okuyucu adını kart ailesine çevirir.
//   - AKİS: ATR'nin tarihsel baytlarında "UEKAE" (eski kurum adı) ya da 0x80'den sonra "eTC" var.
//     Kayıtlarda görülen beş AKİS nesli de bu iki kalıptan birine uyuyor; pcsc-tools ATR
//     listesindeki AKİS kayıtları da öyle.
//   - SafeNet eToken: ATR "3B D5 18 00 81 31" ile başlayıp "73 C8 21 10" taşıyor ya da okuyucu,
//     tokenın kendi sanal okuyucusu ("AKS ifdh" = Aladdin Knowledge Systems, "Aladdin Token JC",
//     "SafeNet Token JC", "eToken").
//   - JCOP: tarihsel baytlarda "JCOP".
func kartAilesiBul(atr []byte, okuyucu string) KartAilesi {
	if bytes.Contains(atr, []byte("UEKAE")) || bytes.Contains(atr, []byte{0x80, 'e', 'T', 'C'}) {
		return KartAKIS
	}
	if bytes.HasPrefix(atr, []byte{0x3B, 0xD5, 0x18, 0x00, 0x81, 0x31}) && bytes.Contains(atr, []byte{0x73, 0xC8, 0x21, 0x10}) {
		return KartSafeNet
	}
	ok := strings.ToLower(okuyucu)
	for _, ipucu := range []string{"aks ifdh", "aladdin", "safenet", "etoken"} {
		if strings.Contains(ok, ipucu) {
			return KartSafeNet
		}
	}
	if bytes.Contains(atr, []byte("JCOP")) {
		return KartJCOP
	}
	return KartBilinmiyor
}

// atrCoz, "3B 9F ..." biçimindeki ATR metnini bayta çevirir (testler ve sunucu kayıtları için).
func atrCoz(s string) []byte {
	b, _ := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	return b
}

// Öneri kodları — web sayfası (ornekleme.html, SURUCU_REHBERI) bu kodlara göre rehber gösterir.
// Kod adlarını değiştirmek sayfayla uyumu bozar; yalnız yenisi eklenir.
const (
	OneriServisKapali   = "SCARD_SERVIS_KAPALI"
	OneriOkuyucuYok     = "OKUYUCU_YOK"
	OneriKartYok        = "KART_TAKILI_DEGIL"
	OneriAkisYok        = "AKIS_SURUCU_YOK"
	OneriAkis32Bit      = "AKIS_32BIT"
	OneriSafeNetYok     = "SAFENET_SURUCU_YOK"
	OneriBilinmeyenKart = "BILINMEYEN_KART"
)

// SurucuOnerisi, sayfaya ve tepsiye giden yapılandırılmış öneri.
type SurucuOnerisi struct {
	Kod     string     `json:"kod"`
	Mesaj   string     `json:"mesaj"`
	Aile    KartAilesi `json:"kart_ailesi,omitempty"`
	Okuyucu string     `json:"okuyucu,omitempty"`
	ATR     string     `json:"atr,omitempty"`
}

const oneriAdimlari = " Sürücüyü kurduktan sonra kartı USB'den çıkarıp yeniden takın ve KolitakipIMZA'yı yeniden başlatın. Ayrıntılı rehber ve indirme bağlantısı imza sayfasında."

var oneriMesajlari = map[string]string{
	OneriServisKapali:   "Windows Akıllı Kart Hizmeti çalışmıyor ya da bilgisayara hiç kart okuyucu takılı değil. Kart okuyucunuzu (ya da USB e-imzanızı) takın; sorun sürerse bilgisayarı yeniden başlatın.",
	OneriOkuyucuYok:     "Bilgisayarda kart okuyucu görünmüyor. Kart okuyucunuzu (ya da USB e-imzanızı) bilgisayara takın, birkaç saniye bekleyip tekrar deneyin.",
	OneriKartYok:        "Kart okuyucu takılı ama içinde kart görünmüyor. Kartınızı okuyucuya takın; hangi sürücüye ihtiyacınız olduğunu size söyleyelim.",
	OneriAkisYok:        "Kartınız bir AKİS kart ve bilgisayarınızda AKİS kart sürücüsü kurulu değil." + oneriAdimlari,
	OneriAkis32Bit:      "Kartınız bir AKİS kart. Bilgisayarınızda AKİS sürücüsünün yalnızca 32 bit sürümü kurulu, 64 bit sürümü gerekiyor." + oneriAdimlari,
	OneriSafeNetYok:     "Kartınız bir SafeNet eToken (genellikle E-GÜVEN) ve bilgisayarınızda SafeNet sürücüsü kurulu değil." + oneriAdimlari,
	OneriBilinmeyenKart: "Kartınız takılı ama türünü tanıyamadık ve uygun sürücü kurulu değil. Sertifikanızı aldığınız firmanın sürücüsünü kurun." + oneriAdimlari,
}

// surucuOnerisiBelirle, PC/SC taramasına ve yüklü sürücülere bakıp eczacının ne yapması
// gerektiğini söyleyen bir öneri üretir. Bilinen bir eksik yoksa nil döner (çağıran eski
// mesajı kullanır). yukluSurucular: başlatılmış DLL'lerin tam yolları.
//
// surucuDosyasiDurumu platforma özeldir (driver_windows.go / driver_linux.go).
func surucuOnerisiBelirle(s PcscSonuc, yukluSurucular []string) *SurucuOnerisi {
	yeni := func(kod string, o *OkuyucuDurumu) *SurucuOnerisi {
		r := &SurucuOnerisi{Kod: kod, Mesaj: oneriMesajlari[kod]}
		if o != nil {
			r.Aile, r.Okuyucu, r.ATR = o.Aile, o.Ad, o.ATR
		}
		return r
	}
	switch s.Kategori {
	case PcscKaynakYoneticisiKapali:
		return yeni(OneriServisKapali, nil)
	case PcscOkuyucuYok:
		return yeni(OneriOkuyucuYok, nil)
	case PcscBilinmiyor:
		return nil
	}

	yuklu := map[string]bool{}
	for _, y := range yukluSurucular {
		yuklu[strings.ToLower(filepath.Base(strings.ReplaceAll(y, `\`, "/")))] = true
	}

	// Tanınan aileden bir kart varsa onu esas al (sanal okuyucular ve boş yuvalar atlanır).
	var kart *OkuyucuDurumu
	for i := range s.Okuyucular {
		o := &s.Okuyucular[i]
		if !o.KartVar {
			continue
		}
		if kart == nil || (kart.Aile == KartBilinmiyor && o.Aile != KartBilinmiyor) {
			kart = o
		}
	}
	if kart == nil {
		return yeni(OneriKartYok, nil)
	}

	switch kart.Aile {
	case KartAKIS:
		if yuklu["akisp11.dll"] {
			return nil // sürücü yüklü; sorun başka yerde
		}
		var64, var32 := surucuDosyasiDurumu("akisp11.dll")
		if var32 && !var64 {
			return yeni(OneriAkis32Bit, kart)
		}
		return yeni(OneriAkisYok, kart)
	case KartSafeNet:
		if yuklu["etpkcs11.dll"] {
			return nil
		}
		return yeni(OneriSafeNetYok, kart)
	default:
		return yeni(OneriBilinmeyenKart, kart)
	}
}

// ErrKartAcilamadi: kartlı slot var ama hiçbir yüklü sürücü oturum açamadı.
var ErrKartAcilamadi = errors.New("kart oturumu açılamadı")

// kartHatasi, kullanıcıya gösterilecek mesajı korurken altta yatan nedeni (ErrKartYok /
// ErrKartAcilamadi) errors.Is ile ayırt edilebilir tutar — cardWorker buna bakıp öneri üretir.
// v1.5.2: detay, eczacıya gösterilmeyen teknik ayrıntıdır (pkcs11 kodu, DLL yolu, HTTP durumu).
// Sayfa onu katlanır "Teknik ayrıntı" kutusunda gösterir; mesaj sade Türkçe kalır.
type kartHatasi struct {
	mesaj string
	detay string
	neden error
}

func (e *kartHatasi) Error() string { return e.mesaj }
func (e *kartHatasi) Unwrap() error { return e.neden }

// sadeHata, eczacıya sade bir mesaj, destek ekibine teknik ayrıntı taşıyan hata üretir (v1.5.2).
// Teknik ayrıntı ayrıca yerel loga yazılır.
func sadeHata(mesaj string, detay string, args ...any) error {
	d := fmt.Sprintf(detay, args...)
	log.Printf("[HATA] %s | teknik: %s", mesaj, d)
	return &kartHatasi{mesaj: mesaj, detay: d}
}

// hataDetayi, hatanın teknik ayrıntısını döndürür (yoksa boş).
func hataDetayi(err error) string {
	var k *kartHatasi
	if errors.As(err, &k) {
		return k.detay
	}
	return ""
}

// Sık kullanılan sade mesajlar.
const (
	mesajSayfayiYenile       = "Belge imzaya hazırlanırken bir sorun oluştu. Sayfayı yenileyip tekrar deneyin; sorun sürerse bizimle iletişime geçin."
	mesajKartTakiliDegil     = "Kartınız takılı görünmüyor. Kartı okuyucuya takıp tekrar deneyin."
	mesajKartImzalamadi      = "Kartınız imzayı tamamlayamadı. Kartı çıkarıp yeniden takın ve tekrar deneyin; sorun sürerse kart sürücünüzü yeniden kurmanız gerekebilir."
	mesajAnahtarYok          = "Seçtiğiniz sertifikanın imza anahtarı kartta bulunamadı. Doğru kartı taktığınızdan ve listeden doğru sertifikayı seçtiğinizden emin olun."
	mesajSertifikaOkunamadi  = "Kartınızdaki sertifika okunamadı. Kartı çıkarıp yeniden takın ve tekrar deneyin."
	mesajPinKilitli          = "Kartınızın PIN kodu, çok sayıda hatalı deneme nedeniyle kilitlenmiş. Kilidi açmak için PUK kodunuzla sertifika sağlayıcınızın programını kullanmanız gerekiyor."
	mesajSunucuyaUlasilamadi = "Sunucuya ulaşılamadı. İnternet bağlantınızı kontrol edip tekrar deneyin."
)

// pinHatasi, Login hatasını sade mesaja çevirir: yalnız gerçekten "PIN yanlış" kodlarında
// "PIN hatalı" denir; diğer Login hataları (kart teması, cihaz hatası) ayrı anlatılır.
func pinHatasi(err error, pinDurumu string) error {
	if pErr, ok := err.(pkcs11.Error); ok && (pErr == pkcs11.CKR_PIN_INCORRECT || pErr == pkcs11.CKR_PIN_LEN_RANGE) {
		mesaj := "PIN kodu hatalı. Lütfen kontrol edip tekrar deneyin. Art arda yanlış girilirse kart kilitlenir."
		if strings.Contains(pinDurumu, "SON DENEME") {
			mesaj = "PIN kodu hatalı. Dikkat: son deneme hakkınız kaldı, bir yanlış giriş daha kartı kilitler."
		} else if strings.Contains(pinDurumu, "Az deneme") {
			mesaj = "PIN kodu hatalı. Dikkat: az deneme hakkınız kaldı."
		}
		return sadeHata(mesaj, "Login: %v (kart durumu: %s)", err, pinDurumu)
	}
	return sadeHata("PIN kodu hatalı ya da kart okunamadı. PIN kodunuzu kontrol edip tekrar deneyin; PIN doğruysa kartı çıkarıp yeniden takın.",
		"Login: %v (kart durumu: %s)", err, pinDurumu)
}

// kartErisimHatasiMi: hata, sürücü önerisi üretmeye değer bir "kart görünmüyor/açılamıyor" mu?
func kartErisimHatasiMi(err error) bool {
	return errors.Is(err, ErrKartYok) || errors.Is(err, ErrKartAcilamadi)
}
