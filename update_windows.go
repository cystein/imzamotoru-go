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
	"strings"
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
	// MinSupportedVersion — UZAKTAN KILL SWITCH. Normal yayınlarda BOŞ bırakılır (davranışta
	// hiçbir değişiklik olmaz). Sahada GEÇERSİZ İMZA ÜRETEN bir sürüm bulunursa (bu projede
	// daha önce iki kez oldu: RSA DigestInfo ve ECDSA r‖s kodlama hataları), bu alana en düşük
	// GÜVENLİ sürüm yazılır — bundan daha eski bir APP_VERSION ile çalışan istemciler, henüz
	// kendileri güncellenmemiş olsa bile (self-update 6 saate kadar gecikebilir) imza atmayı
	// hemen reddeder. Elle, tools/sign_release'in opsiyonel 6. argümanıyla set edilir; ayrı bir
	// acil durum aracı — normal ./release.sh akışı bu alana asla otomatik bir şey yazmaz.
	MinSupportedVersion string `json:"min_supported_version,omitempty"`
}

// surumKarsilastir basit bir "X.Y.Z" semver-lite karşılaştırıcısı — bu projede sürüm numaraları
// hep bu üç parçalı biçimde. a<b ise -1, a==b ise 0, a>b ise 1 döner. Ayrıştırılamayan bir parça
// 0 sayılır (asla panic etmez — kill switch'in kendisi bir hataya çarpıp devre dışı kalmasın).
func surumKarsilastir(a, b string) int {
	ap := strings.Split(a, ".")
	bp := strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		var av, bv int
		if i < len(ap) {
			fmt.Sscanf(ap[i], "%d", &av)
		}
		if i < len(bp) {
			fmt.Sscanf(bp[i], "%d", &bv)
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
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

	// UZAKTAN KILL SWITCH — yeni bir sürüm çıkmış olsun ya da olmasın, HER kontrolde bakılır
	// (bir kereye mahsus değil): sunucudaki latest.json bu istemcinin sürümünü artık desteklemez
	// diyorsa, imzalama hemen durdurulur. bkz. latestVersionInfo.MinSupportedVersion.
	if info.MinSupportedVersion != "" && surumKarsilastir(APP_VERSION, info.MinSupportedVersion) < 0 {
		// Eczacıya sade mesaj; sürüm numaraları yalnız bize giden bildirimde ve logda.
		mesaj := "KolitakipIMZA programınızın sürümü eski olduğu için imza atılamıyor. Ekranın sağ altındaki KolitakipIMZA simgesine sağ tıklayıp \"Şimdi Güncellemeyi Kontrol Et\"i seçin (bu seçenek yoksa programı imza sayfasındaki kurulum bağlantısından yeniden kurun); güncelleme bitince tekrar deneyin."
		if imzalamaEngelMesaji() != mesaj {
			teknik := fmt.Sprintf("Bu istemci sürümü (v%s) artık güvenli kabul edilmiyor (asgari desteklenen: v%s) — imzalama durduruldu.", APP_VERSION, info.MinSupportedVersion)
			log.Println("⛔ [UPDATE] KILL SWITCH devrede:", teknik)
			bildir(SeviyeKritik, "SURUM_DESTEKLENMIYOR", teknik)
		}
		imzalamaEngeli.Store(mesaj)
	} else {
		imzalamaEngeli.Store("") // izin verilen aralığa dönüldü (ör. sunucu latest.json'ı düzeltti)
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

	// GERİ ALMA GÜVENLİK AĞI: bir önceki (çalışan) exe'yi sakla. sha256/imza kontrolü SAHTE/bozuk
	// bir dosyaya karşı korur ama derlemesi geçen, imzası geçerli, sha256'sı doğru, ama ÇALIŞMA
	// ZAMANINDA hata veren bir sürüm yayınlanırsa bu olmadan geri dönüş yolu yoktu — her eczane
	// otomatik o sürüme geçerdi. `os.Executable()` başarısız olursa (çok nadir) OldSavePath boş
	// kalır, eski davranışa (yedeksiz güncelleme) sessizce düşülür — güncellemeyi engellemez.
	if exePath, exeErr := os.Executable(); exeErr == nil {
		opts.OldSavePath = exePath + ".onceki-surum"
	}

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
