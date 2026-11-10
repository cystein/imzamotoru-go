//go:build windows

package main

/*
#include <windows.h>
#include <stdlib.h>

typedef int (*C_Initialize_t)(void*);

// son_win_hata: LoadLibraryEx/GetProcAddress başarısız olduğunda GetLastError()'ı çağırana taşır.
// Özellikle ERROR_BAD_EXE_FORMAT (193) — 32-bit bir DLL'in 64-bit sürece (ya da tam tersi)
// yüklenmeye çalışılması — "dosya yok/bozuk" ile "mimari uyuşmazlığı"nı ayırt etmemizi sağlar;
// gerçek bir üretim vakasında (2026-07, AKİS'in sadece 32-bit sürümü kuruluydu) bu ayrımı sadece
// manuel analizle (force_init kod -1'in ne anlama geldiğini tahmin ederek) çıkarabilmiştik.
static int force_init(const char* lib_path, DWORD* son_win_hata) {
    // LoadLibraryA yerine bilerek LoadLibraryExA + arama bayrakları: yüklenen DLL'in
    // bağımlılıkları ararken uygulamanın kendi klasörü/CWD DEĞİL, sadece System32/SysWOW64 ve
    // DLL'in kendi bulunduğu klasör taranır. Aksi halde uygulamanın kurulu olduğu klasöre (artık
    // %LOCALAPPDATA%, Program Files'a göre daha yazılabilir) aynı isimde kötü niyetli bir DLL
    // bırakan başka bir yerel süreç, sürücü yüklenirken sessizce çalıştırılabilirdi.
    HMODULE handle = LoadLibraryExA(lib_path, NULL,
        LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR);
    if (!handle) {
        *son_win_hata = GetLastError();
        return -1;
    }
    C_Initialize_t c_init = (C_Initialize_t)GetProcAddress(handle, "C_Initialize");
    if (!c_init) {
        *son_win_hata = GetLastError();
        return -2;
    }
    *son_win_hata = 0;
    return c_init(NULL);
}
*/
import "C"

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
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

	var sonWinHata C.DWORD
	if res := C.force_init(cPath, &sonWinHata); res != 0 {
		return nil, fmt.Errorf("force_init kod %d%s (%s)", int(res), winHataAciklamasi(int(res), uint32(sonWinHata)), dllYolu)
	}
	return pkcs11.New(dllYolu), nil
}

// winHataAciklamasi, force_init'in LoadLibraryEx aşamasında (res == -1) aldığı GetLastError()
// değerini insan tarafından okunabilir bir teşhise çevirir. En yaygın/önemli örnek
// ERROR_BAD_EXE_FORMAT (193): DLL'in mimarisi (32/64-bit) bu sürecin mimarisiyle uyuşmuyor —
// bunu bilince bildir() raporundan doğrudan kesin teşhis çıkar, "acaba mimari mi?" diye manuel
// tahmin yürütmeye gerek kalmaz.
func winHataAciklamasi(res int, winHata uint32) string {
	if res != -1 || winHata == 0 {
		return ""
	}
	if winHata == 193 { // ERROR_BAD_EXE_FORMAT
		return fmt.Sprintf(" [Windows hata %d ERROR_BAD_EXE_FORMAT — ⚠️ Mimari uyuşmazlığı: DLL bu sürecin mimarisiyle (%s) uyumsuz, muhtemelen yanlış bitlikte (32/64-bit) bir sürücü kurulu]", winHata, runtime.GOARCH)
	}
	return fmt.Sprintf(" [Windows hata %d]", winHata)
}

// initDriver, önce (varsa) config dosyasındaki özel sürücü yolunu, sonra bilinen adaylardan
// makinede fiilen bulunanları dener ve başlatılabilen HEPSİNİ yüklü tutar (v1.4.1, §9.14).
// Hangisinin kullanılacağına her işlemde, kartı gerçekten açabilmesine göre karar verilir
// (surucu_secimi.go). Bir aday başlatılamazsa (dosya bozuk, mimari uyuşmazlığı vb.) atlanır —
// tek bir bozuk/uyumsuz sürücü yüzünden uygulama tamamen çökmez.
func initDriver() (*surucuSeti, error) {
	var yollar []string
	if ozelYol, ok := ozelSurucuYoluOku(); ok {
		yollar = append(yollar, ozelYol)
	}
	adaylar := bulunanSurucuAdaylari()
	if len(yollar) == 0 && len(adaylar) == 0 {
		// %w ile ErrSurucuHicKurulmamis'e sarmalanıyor (main.go) — surucuHatasiKullaniciMesaji()
		// bu sentinel'i errors.Is() ile yakalayıp eczacıya "sürücü kurulu değil, kurun" diyor;
		// aşağıdaki "bulundu ama başlatılamadı" durumundan (mimari uyuşmazlığı vb.) ayırt ediliyor.
		return nil, fmt.Errorf("%w — aranan dosyalar: %v (System32/SysWOW64 içinde bulunamadı)", ErrSurucuHicKurulmamis, driverAdaylari)
	}
	for _, aday := range adaylar {
		if len(yollar) > 0 && strings.EqualFold(aday, yollar[0]) {
			continue // driver.txt'teki yol zaten başta
		}
		yollar = append(yollar, aday)
	}

	set := &surucuSeti{}
	var sonHata error
	for _, dllYolu := range yollar {
		p, err := surucuyuBaslat(dllYolu)
		if err != nil {
			log.Printf("[WORKER] ⚠️ %s başlatılamadı, sıradaki adaya geçiliyor: %v", dllYolu, err)
			sonHata = err
			continue
		}
		set.surucular = append(set.surucular, yeniYukluSurucu(dllYolu, p))
	}
	if len(set.surucular) == 0 {
		return nil, fmt.Errorf("bulunan hiçbir sürücü başlatılamadı, son hata: %v", sonHata)
	}
	return set, nil
}

// surucuDosyasiDurumu, bir sürücü DLL'inin 64 bitlik (System32) ve 32 bitlik (SysWOW64)
// konumlarda bulunup bulunmadığını söyler — "yalnız 32 bit kurulu" teşhisi için (v1.5.0).
func surucuDosyasiDurumu(ad string) (var64, var32 bool) {
	klasorler := driverAdayKlasorleri() // [System32, SysWOW64]
	if _, err := os.Stat(filepath.Join(klasorler[0], ad)); err == nil {
		var64 = true
	}
	if _, err := os.Stat(filepath.Join(klasorler[1], ad)); err == nil {
		var32 = true
	}
	return
}

// yeniSuruculeriYukle, motor çalışırken sonradan kurulan bir sürücüyü (ör. eczacı rehberdeki
// AKİS sürücüsünü kurdu) yeniden başlatma beklemeden sete ekler (v1.5.0). Daha önce denenip
// başlatılamayan yollar tekrar denenmez. Yalnız cardWorker iş parçacığından çağrılır.
func (s *surucuSeti) yeniSuruculeriYukle() {
	if s.denenmis == nil {
		s.denenmis = map[string]bool{}
		for _, d := range s.surucular {
			s.denenmis[strings.ToLower(d.Yol)] = true
		}
	}
	eklendi := false
	for _, yol := range bulunanSurucuAdaylari() {
		anahtar := strings.ToLower(yol)
		if s.denenmis[anahtar] {
			continue
		}
		s.denenmis[anahtar] = true
		p, err := surucuyuBaslat(yol)
		if err != nil {
			log.Printf("[WORKER] ⚠️ Sonradan bulunan sürücü başlatılamadı: %v", err)
			continue
		}
		s.surucular = append(s.surucular, yeniYukluSurucu(yol, p))
		eklendi = true
	}
	if eklendi {
		surucuOzetiniKaydet(s)
	}
}
