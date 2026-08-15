// sign_release, bir sürüm exe'sini özel anahtarla imzalayıp latest.json üretir.
// Kullanım: go run ./tools/sign_release <ozel-anahtar.pem> <exe-yolu> <versiyon> <indirme-url> <cikti-latest.json> [asgari-desteklenen-surum]
//
// Son argüman OPSİYONEL ve NORMAL yayınlarda hiç verilmez — sadece bir UZAKTAN KILL SWITCH
// gerektiğinde (sahada geçersiz imza üreten bir sürüm bulunduğunda) elle, ayrı bir çağrıyla
// kullanılır: o an yayınladığınız sürümden değil, DAHA ESKİ hangi sürümlerin artık imza
// atmayı reddetmesini istediğinizden bahseder. Örnek: "1.2.5" verilirse, 1.2.5'ten eski TÜM
// çalışan istemciler bir sonraki güncelleme kontrolünde (en geç 6 saat içinde) imzalamayı
// durdurur. Bkz. update_windows.go MinSupportedVersion.
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
)

type latestInfo struct {
	Version             string `json:"version"`
	URL                 string `json:"url"`
	SHA256              string `json:"sha256"`
	Signature           string `json:"signature"`
	MinSupportedVersion string `json:"min_supported_version,omitempty"`
}

func main() {
	if len(os.Args) != 6 && len(os.Args) != 7 {
		fmt.Fprintln(os.Stderr, "kullanım: sign_release <ozel-anahtar.pem> <exe-yolu> <versiyon> <indirme-url> <cikti-latest.json> [asgari-desteklenen-surum]")
		os.Exit(1)
	}
	keyPath, exePath, version, url, outPath := os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5]
	minSurum := ""
	if len(os.Args) == 7 {
		minSurum = os.Args[6]
		fmt.Printf("⚠️  KILL SWITCH: v%s öncesi TÜM istemciler bir sonraki güncelleme kontrolünde imzalamayı durduracak.\n", minSurum)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "özel anahtar okunamadı:", err)
		os.Exit(1)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		fmt.Fprintln(os.Stderr, "özel anahtar PEM ayrıştırılamadı")
		os.Exit(1)
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "özel anahtar çözümlenemedi:", err)
		os.Exit(1)
	}

	exeData, err := os.ReadFile(exePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "exe okunamadı:", err)
		os.Exit(1)
	}
	hash := sha256.Sum256(exeData)

	sig, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "imzalama başarısız:", err)
		os.Exit(1)
	}

	info := latestInfo{
		Version:             version,
		URL:                 url,
		SHA256:              hex.EncodeToString(hash[:]),
		Signature:           base64.StdEncoding.EncodeToString(sig),
		MinSupportedVersion: minSurum,
	}
	out, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "json üretilemedi:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outPath, append(out, '\n'), 0644); err != nil {
		fmt.Fprintln(os.Stderr, "dosya yazılamadı:", err)
		os.Exit(1)
	}
	fmt.Println("OK — imzalandı ve yazıldı:", outPath)
}
