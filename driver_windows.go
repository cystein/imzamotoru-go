//go:build windows

package main

/*
#include <windows.h>
#include <stdlib.h>

typedef int (*C_Initialize_t)(void*);

static int force_init(const char* lib_path) {
    // LoadLibraryA yerine bilerek LoadLibraryExA + arama bayrakları: yüklenen DLL'in
    // bağımlılıkları ararken uygulamanın kendi klasörü/CWD DEĞİL, sadece System32/SysWOW64 ve
    // DLL'in kendi bulunduğu klasör taranır. Aksi halde uygulamanın kurulu olduğu klasöre (artık
    // %LOCALAPPDATA%, Program Files'a göre daha yazılabilir) aynı isimde kötü niyetli bir DLL
    // bırakan başka bir yerel süreç, sürücü yüklenirken sessizce çalıştırılabilirdi.
    HMODULE handle = LoadLibraryExA(lib_path, NULL,
        LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR);
    if (!handle) return -1;
    C_Initialize_t c_init = (C_Initialize_t)GetProcAddress(handle, "C_Initialize");
    if (!c_init) return -2;
    return c_init(NULL);
}
*/
import "C"

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/miekg/pkcs11"
)

// driverAdaylari: bilinen akıllı kart PKCS#11 sürücü DLL adları, denenme sırasıyla.
// Yeni bir sağlayıcı doğrulandıkça bu listeye eklenir.
var driverAdaylari = []string{
	"akisp11.dll",  // TÜBİTAK Kamu SM AKİS
	"aetpkss1.dll", // A.E.T. Europe SafeSign/AETSign ailesi (TÜRKTRUST'ın bazı kart nesilleri) — ikincil kaynaklardan doğrulandı, garanti değil
	"gclib.dll",    // GemSafe (Gemalto/Thales) kart orta katmanı
	"siecap11.dll", // Siemens CardOS PKCS#11 orta katmanı
	"eTPKCS11.dll", // SafeNet/Aladdin eToken PKCS#11 orta katmanı
}

// driverAdayKlasorleri, DLL'lerin aranacağı sistem klasörlerini döndürür.
func driverAdayKlasorleri() []string {
	sistemKok := os.Getenv("SystemRoot")
	if sistemKok == "" {
		sistemKok = `C:\Windows`
	}
	return []string{
		filepath.Join(sistemKok, "System32"),
		filepath.Join(sistemKok, "SysWOW64"),
	}
}

// surucuYapilandirmaDosyalari, kullanıcı/destek ekibinin bilinen aday listesine güvenmeden
// manuel bir DLL yolu belirtebileceği konumlardır — listede olmayan yeni bir kart sağlayıcısı
// çıktığında kod/derleme değiştirmeden destek eklemeyi sağlar. Sırayla denenir.
func surucuYapilandirmaDosyalari() []string {
	var yollar []string
	if exePath, err := os.Executable(); err == nil {
		yollar = append(yollar, filepath.Join(filepath.Dir(exePath), "driver.txt"))
	}
	if programData := os.Getenv("ProgramData"); programData != "" {
		yollar = append(yollar, filepath.Join(programData, "KolitakipIMZA", "driver.txt"))
	}
	return yollar
}

// ozelSurucuYoluOku, config dosyalarından (varsa) kullanıcı tanımlı bir DLL yolu okur.
// Dosya içeriği tek satırlık DLL tam yolundan ibarettir.
func ozelSurucuYoluOku() (string, bool) {
	for _, yol := range surucuYapilandirmaDosyalari() {
		data, err := os.ReadFile(yol)
		if err != nil {
			continue
		}
		ozelYol := strings.TrimSpace(string(data))
		if ozelYol == "" {
			continue
		}
		if _, err := os.Stat(ozelYol); err != nil {
			log.Printf("[WORKER] ⚠️ %s içinde belirtilen sürücü yolu bulunamadı: %s", yol, ozelYol)
			continue
		}
		return ozelYol, true
	}
	return "", false
}

// bulunanSurucuAdaylari, System32/SysWOW64'te fiilen var olan bilinen sürücü DLL'lerinin
// tam yollarını, driverAdaylari sırasına göre döndürür (birden fazla olabilir — örn. hem
// AKİS hem TÜRKTRUST orta katmanı kurulu bir makinede).
func bulunanSurucuAdaylari() []string {
	var bulunanlar []string
	for _, klasor := range driverAdayKlasorleri() {
		for _, ad := range driverAdaylari {
			yol := filepath.Join(klasor, ad)
			if _, err := os.Stat(yol); err == nil {
				bulunanlar = append(bulunanlar, yol)
			}
		}
	}
	return bulunanlar
}

// surucuyuBaslat, Linux tarafındaki initDriver ile aynı tekniği Windows API'siyle tek bir DLL
// üzerinde dener: önce ham bir handle ile C_Initialize(NULL) çağrılır (AKİS gibi bazı sürücüler,
// miekg/pkcs11'in gönderdiği dolu CK_C_INITIALIZE_ARGS struct'ını değil, NULL bekler), sonra
// resmi pkcs11 wrapper'ı aynı yüklü DLL'e bağlanır.
func surucuyuBaslat(dllYolu string) (*pkcs11.Ctx, error) {
	log.Printf("[WORKER] Akıllı kart sürücüsü deneniyor: %s", dllYolu)

	cPath := C.CString(dllYolu)
	defer C.free(unsafe.Pointer(cPath))

	if res := C.force_init(cPath); res != 0 {
		return nil, fmt.Errorf("force_init kod %d (%s)", res, dllYolu)
	}
	return pkcs11.New(dllYolu), nil
}

// initDriver, önce (varsa) config dosyasındaki özel sürücü yolunu, sonra bilinen adaylardan
// makinede fiilen bulunanları sırayla dener; ilk başarılı olan kullanılır. Bir aday
// başlatılamazsa (dosya bozuk, mimari uyuşmazlığı vb.) sıradaki adaya geçilir — tek bir
// bozuk/uyumsuz sürücü yüzünden uygulama tamamen çökmez.
func initDriver() (*pkcs11.Ctx, error) {
	if ozelYol, ok := ozelSurucuYoluOku(); ok {
		if p, err := surucuyuBaslat(ozelYol); err == nil {
			return p, nil
		} else {
			log.Printf("[WORKER] ⚠️ Yapılandırmadaki özel sürücü başlatılamadı, bilinen adaylara devam ediliyor: %v", err)
		}
	}

	adaylar := bulunanSurucuAdaylari()
	if len(adaylar) == 0 {
		return nil, fmt.Errorf("bilinen akıllı kart sürücüsü (%v) System32/SysWOW64 içinde bulunamadı — sürücü kurulu mu?", driverAdaylari)
	}

	var sonHata error
	for _, dllYolu := range adaylar {
		p, err := surucuyuBaslat(dllYolu)
		if err == nil {
			return p, nil
		}
		log.Printf("[WORKER] ⚠️ %s başlatılamadı, sıradaki adaya geçiliyor: %v", dllYolu, err)
		sonHata = err
	}
	return nil, fmt.Errorf("bulunan hiçbir sürücü başlatılamadı, son hata: %v", sonHata)
}
