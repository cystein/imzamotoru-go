//go:build windows

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"

	update "github.com/inconshreveable/go-update"
)

// RELEASE_PUBLIC_KEY_PEM: bu ekip dışında kimsenin elinde olmayan özel anahtarla eşleşen açık
// anahtar — exe'nin kendisine gömülü olduğu için, sunucu tamamen ele geçirilse bile saldırgan
// geçerli bir imza üretemez (özel anahtar sunucuda hiç yok, sadece bu geliştirme makinesinde,
// ~/.kolitakip-release-key/release-private.pem). Yeni sürüm yayınlarken tools/sign_release ile
// üretilen imza, latest.json'daki "signature" alanına konur ve burada doğrulanır.
const RELEASE_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEO+yu7rNnee0zw4npt9j76eTStnjP
BjkweJEr2cq/8NZHewIuyCtuY4Il+AJmAS3tdX7nL0e3a892Z/AdZvGPiQ==
-----END PUBLIC KEY-----`

// latestVersionURL, Node.js sunucusundaki (mevcut public/ klasörü zaten express.static ile
// servis ediyor) statik sürüm bilgisi dosyasıdır — yeni sürüm çıkınca tek yapılacak bu
// dosyayı ve içindeki exe'yi güncellemek, ayrı bir sunucu route'u gerekmiyor.
const latestVersionURL = NODE_API_URL + "/imza-motoru/latest.json"

// updateHTTPClient, exe indirme adımı için httpClient'tan (30sn) daha uzun zaman aşımına
// sahip ayrı bir istemci — indirme birkaç dakika sürebilir, bu diğer kısa ömürlü sunucu
// isteklerinin (imza yükleme/indirme) zaman aşımını etkilemesin diye ayrıldı.
var updateHTTPClient = &http.Client{Timeout: 5 * time.Minute}

type latestVersionInfo struct {
	Version   string `json:"version"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
}

// checkForUpdates, açılışta bir kez ve sonrasında 6 saatte bir sürüm kontrolü yapar.
func checkForUpdates() {
	for {
		guncellemeyiDenetle()
		time.Sleep(6 * time.Hour)
	}
}

func guncellemeyiDenetle() {
	resp, err := httpClient.Get(latestVersionURL)
	if err != nil {
		log.Printf("[UPDATE] Sürüm kontrolü yapılamadı: %v", err)
		return
	}
	defer resp.Body.Close()

	var info latestVersionInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		log.Printf("[UPDATE] Sürüm bilgisi okunamadı: %v", err)
		return
	}

	if info.Version == "" || info.Version == APP_VERSION {
		return // güncel
	}

	// İmzasız/sha256'sız bir "güncelleme" asla kabul edilmez — eskiden sha256 boşsa bile
	// uygulanıyordu, bu bir gerileme olurdu, artık sert biçimde reddediyoruz.
	if info.SHA256 == "" || info.Signature == "" {
		log.Printf("[UPDATE] ⛔ latest.json'da sha256 veya imza eksik, güncelleme reddedildi (sahte/bozuk sunucu yanıtı olabilir)")
		bildir(SeviyeKritik, "SAHTE_GUNCELLEME", fmt.Sprintf("latest.json'da sha256/imza eksik (hedef sürüm: %s), güncelleme reddedildi", info.Version))
		return
	}

	log.Printf("[UPDATE] Yeni sürüm bulundu: %s -> %s, indiriliyor...", APP_VERSION, info.Version)

	// info.URL, düşük bant genişlikli bağlantılar için gzip ile sıkıştırılmış exe'yi işaret
	// eder (~%60 daha küçük indirme) — açık exe'ye değil .gz'ye bakar, burada açılır.
	binResp, err := updateHTTPClient.Get(info.URL)
	if err != nil {
		log.Printf("[UPDATE] Yeni sürüm indirilemedi: %v", err)
		return
	}
	defer binResp.Body.Close()

	gzReader, err := gzip.NewReader(binResp.Body)
	if err != nil {
		log.Printf("[UPDATE] Gzip açılamadı (bozuk indirme olabilir, bir sonraki denemede tekrar denenecek): %v", err)
		return
	}
	defer gzReader.Close()

	// Mevcut exe ~17MB — 100MB zaten çok cömert bir tavan. Bir sıkıştırma bombası (gzip
	// içinde devasa bir içerik) belleği tüketip programı çökertmeye çalışırsa, burada keseriz;
	// kesilen veri zaten sha256/imza kontrolünden geçemeyeceği için güncelleme uygulanmaz.
	const maxGuncellemeBoyutu = 100 << 20
	data, err := io.ReadAll(io.LimitReader(gzReader, maxGuncellemeBoyutu))
	if err != nil {
		log.Printf("[UPDATE] Yeni sürüm içeriği okunamadı (bozuk indirme olabilir, bir sonraki denemede tekrar denenecek): %v", err)
		return
	}

	shaBytes, err := hex.DecodeString(info.SHA256)
	if err != nil {
		log.Printf("[UPDATE] ⛔ sha256 formatı geçersiz, güncelleme reddedildi: %v", err)
		bildir(SeviyeKritik, "SAHTE_GUNCELLEME", fmt.Sprintf("sha256 formatı geçersiz (hedef sürüm: %s), güncelleme reddedildi: %v", info.Version, err))
		return
	}
	sigBytes, err := base64.StdEncoding.DecodeString(info.Signature)
	if err != nil {
		log.Printf("[UPDATE] ⛔ imza formatı geçersiz, güncelleme reddedildi: %v", err)
		bildir(SeviyeKritik, "SAHTE_GUNCELLEME", fmt.Sprintf("imza formatı geçersiz (hedef sürüm: %s), güncelleme reddedildi: %v", info.Version, err))
		return
	}

	// Doğrulamayı elle yapmıyoruz — go-update'in kendi Checksum+PublicKey+Signature mekanizmasına
	// devrediyoruz (Apply() içinde: önce sha256 karşılaştırılır, sonra ECDSA imza doğrulanır,
	// ikisi de geçmezse dosyaya HİÇ dokunulmadan hata döner).
	opts := update.Options{Checksum: shaBytes, Signature: sigBytes}
	if err := opts.SetPublicKeyPEM([]byte(RELEASE_PUBLIC_KEY_PEM)); err != nil {
		log.Printf("[UPDATE] ⛔ Gömülü açık anahtar okunamadı (bu bir kod hatası, sunucudan bağımsız): %v", err)
		return
	}

	if err := update.Apply(bytes.NewReader(data), opts); err != nil {
		log.Printf("[UPDATE] ⛔ Güncelleme reddedildi (sha256 veya imza uyuşmadı, ya da dosya sistemi hatası): %v", err)
		bildir(SeviyeKritik, "SAHTE_GUNCELLEME", fmt.Sprintf("sha256/imza doğrulaması başarısız (hedef sürüm: %s), güncelleme reddedildi: %v — bu bir güvenlik olayı olabilir", info.Version, err))
		return
	}

	log.Printf("[UPDATE] ✅ Güncelleme imzası doğrulandı, başarıyla uygulandı (v%s), uygulama yeniden başlatılıyor...", info.Version)
	yenidenBaslat()
}

func yenidenBaslat() {
	exePath, err := os.Executable()
	if err != nil {
		log.Printf("[UPDATE] Yeniden başlatılamadı: %v", err)
		return
	}
	if err := exec.Command(exePath).Start(); err != nil {
		log.Printf("[UPDATE] Yeni süreç başlatılamadı: %v", err)
		return
	}
	os.Exit(0)
}
