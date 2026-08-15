//go:build windows

package main

import (
	_ "embed"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/getlantern/systray"
)

//go:embed assets/icon.ico
var trayIcon []byte

// platformStartup, Windows'ta konsol yerine sistem tepsisinde çalışır (bkz. build_windows.sh'deki
// -H=windowsgui bayrağı). systray.Run çağrı yapan goroutine'i (Windows mesaj döngüsü için) bloke
// eder; asıl WS/HTTP sunucusu ve self-update kontrolü onTrayReady içinde ayrı goroutine'lerde başlar.
func platformStartup() {
	systray.Run(onTrayReady, onTrayExit)
}

// logKlasoru, app.log ve tanılama raporunun yaşadığı %ProgramData%\KolitakipIMZA klasörünü
// döndürür (yoksa oluşturur). Bu iki fonksiyon (logDosyasiniAyarla, tanilamaRaporuKaydet)
// aynı klasörü paylaştığı için ortak bir yere çıkarıldı.
func logKlasoru() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	klasor := filepath.Join(programData, "KolitakipIMZA")
	os.MkdirAll(klasor, 0755)
	return klasor
}

// logDosyasiniAyarla, log çıktısını (varsayılan olarak -H=windowsgui derlemesinde HİÇBİR YERE
// gitmeyen, konsolsuz bir process olduğu için kaybolan) stderr yerine kalıcı bir dosyaya
// yönlendirir. Program pencere/konsol açmadığı için bu dosya, saha desteğinde "eczacının
// bilgisayarında ne oldu" sorusuna cevap bulabileceğimiz TEK yer.
//
// LOG ROTASYONU: dosya belli bir boyutu (5MB) geçmişse bir öncekinin üzerine yazarak ".old"a
// taşınır, yeni boş bir dosyayla devam edilir. Sürücüsü hiç düzelmeyen bir kurulum aylarca
// 5 dakikada bir aynı hatayı loglayabiliyor (bkz. EL_KITABI.md §9.1'in bulduğu, sunucu
// tarafındaki aynı sorunun eczacının kendi diskindeki hâli) — sınırsız büyümeyi engelliyoruz.
func logDosyasiniAyarla() {
	klasor := logKlasoru()
	yol := filepath.Join(klasor, "app.log")

	const maxBoyut = 5 << 20 // 5MB
	if bilgi, err := os.Stat(yol); err == nil && bilgi.Size() > maxBoyut {
		os.Rename(yol, yol+".old") // hata olursa (ör. dosya kilitli) sessizce mevcut dosyaya append edilmeye devam edilir
	}

	dosya, err := os.OpenFile(yol, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	log.SetOutput(dosya)
	log.SetFlags(log.LstdFlags)
}

// tanilamaRaporuKaydet, destek sürecini hızlandırmak için tek tıkla bir tanılama raporu
// üretir: PC/SC teşhisi, sürücü durumu, işletim sistemi/mimari, sürüm bilgisi. Panoya kopyalama
// YERİNE dosyaya yazıp Not Defteri ile açıyoruz — panoya kopyalamak yeni bir bağımlılık (bu
// projede henüz hiç kullanılmayan bir clipboard kütüphanesi) gerektirirdi, dosya+Not Defteri
// hem bağımlılıksız hem de eczacının ekran görüntüsü/dosya olarak paylaşmasına daha uygun.
func tanilamaRaporuKaydet() {
	kategori, pcscDetay := pcscTeshisi()
	kategoriMetni := map[PcscKategori]string{
		PcscBilinmiyor:              "bilinmiyor",
		PcscKaynakYoneticisiKapali:  "Windows Akıllı Kart Hizmeti çalışmıyor",
		PcscOkuyucuYok:              "okuyucu bulunamadı",
		PcscOkuyucuVarSurucuGerekli: "okuyucu var, sürücü gerekiyor",
	}[kategori]

	rapor := fmt.Sprintf(
		"KolitakipIMZA Tanılama Raporu\n"+
			"Oluşturulma: %s\n"+
			"Sürüm: %s\n"+
			"İşletim Sistemi/Mimari: %s/%s\n"+
			"Sürücü durum mesajı: %s\n"+
			"PC/SC kategorisi: %s\n"+
			"PC/SC teşhis detayı: %s\n"+
			"İmzalama engeli: %s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		APP_VERSION,
		runtime.GOOS, runtime.GOARCH,
		sonSurucuTeshisMesaji,
		kategoriMetni,
		pcscDetay,
		func() string {
			if m := imzalamaEngelMesaji(); m != "" {
				return m
			}
			return "yok"
		}(),
	)

	yol := filepath.Join(logKlasoru(), "tanilama-raporu.txt")
	if err := os.WriteFile(yol, []byte(rapor), 0644); err != nil {
		log.Printf("[TANILAMA] Rapor dosyaya yazılamadı: %v", err)
		return
	}
	log.Printf("[TANILAMA] Rapor kaydedildi: %s", yol)
	exec.Command("notepad.exe", yol).Start()
}

func onTrayReady() {
	logDosyasiniAyarla()
	systray.SetIcon(trayIcon)
	systray.SetTitle(APP_NAME)

	// Port'u BİR KEZ, kalıcı olarak ayırıyoruz ve aynı listener'ı hem tekillik kontrolü hem
	// de gerçek servis için kullanıyoruz (önceki sürümde ayrı bir "probe" ile kontrol edip
	// hemen kapatıp yeniden dinliyorduk — iki adım arasında teorik bir yarış durumu (iki kopya
	// art arda başlarsa ikisi de "boşta" görüp devam edebilir) vardı, artık yok). Port zaten
	// kullanımdaysa (başka bir KolitakipIMZA kopyası çalışıyorsa) donanıma HİÇ dokunmadan
	// (cardWorker() bilerek burada başlamıyor) kullanıcıyı tepside bilgilendirip kapanıyoruz.
	ln, err := net.Listen("tcp", "127.0.0.1:"+PORT)
	if err != nil {
		systray.SetTooltip(APP_NAME + " zaten çalışıyor (başka bir kopya açık)")
		mZaten := systray.AddMenuItem("⚠️ Zaten çalışıyor, bu kopya kapanacak", "")
		mZaten.Disable()
		go func() {
			time.Sleep(3 * time.Second)
			systray.Quit()
		}()
		return
	}

	systray.SetTooltip(fmt.Sprintf("%s çalışıyor (v%s)", APP_NAME, APP_VERSION))

	// mDurum paket seviyesinde tanımlı (notify_windows.go) — burada sadece atanıyor, böylece
	// bildir() farklı bir goroutine'den (cardWorker, update kontrolü) tepsi başlığını/tooltip'i
	// sonradan güncelleyebiliyor.
	mDurum = systray.AddMenuItem(fmt.Sprintf("Durum: Çalışıyor (v%s)", APP_VERSION), "")
	mDurum.Disable()
	systray.AddSeparator()
	mGuncelleKontrol := systray.AddMenuItem("🔄 Şimdi Güncellemeyi Kontrol Et", "Sunucudaki en güncel sürümü hemen kontrol et")
	mTanilama := systray.AddMenuItem("📋 Tanılama Raporu Kaydet", "Destek için bir tanılama raporu dosyası oluştur ve aç")
	systray.AddSeparator()
	mCikis := systray.AddMenuItem("Çıkış", "Uygulamadan çık")

	gorutinGuvenliBaslat("cardWorker", cardWorker)
	gorutinGuvenliBaslat("startServer", func() { startServer(ln) })
	gorutinGuvenliBaslat("checkForUpdates", checkForUpdates)

	go func() {
		for range mGuncelleKontrol.ClickedCh {
			log.Println("[TRAY] Kullanıcı 'Şimdi Güncellemeyi Kontrol Et' seçti.")
			go guncellemeyiDenetle()
		}
	}()

	go func() {
		for range mTanilama.ClickedCh {
			log.Println("[TRAY] Kullanıcı 'Tanılama Raporu Kaydet' seçti.")
			go tanilamaRaporuKaydet()
		}
	}()

	go func() {
		<-mCikis.ClickedCh
		log.Println("Kullanıcı tepsi menüsünden çıkışı seçti.")
		systray.Quit()
	}()
}

func onTrayExit() {
	// systray.Quit() çağrıldığında tetiklenir; process systray.Run() dönünce sonlanır.
}
