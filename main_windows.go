//go:build windows

package main

import (
	_ "embed"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
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

// logDosyasiniAyarla, log çıktısını (varsayılan olarak -H=windowsgui derlemesinde HİÇBİR YERE
// gitmeyen, konsolsuz bir process olduğu için kaybolan) stderr yerine kalıcı bir dosyaya
// yönlendirir. Program pencere/konsol açmadığı için bu dosya, saha desteğinde "eczacının
// bilgisayarında ne oldu" sorusuna cevap bulabileceğimiz TEK yer.
func logDosyasiniAyarla() {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	klasor := filepath.Join(programData, "KolitakipIMZA")
	if err := os.MkdirAll(klasor, 0755); err != nil {
		return // log dosyasına yazamıyoruz ama bu, uygulamanın çalışmasını engellememeli
	}
	dosya, err := os.OpenFile(filepath.Join(klasor, "app.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	log.SetOutput(dosya)
	log.SetFlags(log.LstdFlags)
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
	mCikis := systray.AddMenuItem("Çıkış", "Uygulamadan çık")

	go cardWorker()
	go startServer(ln)
	go checkForUpdates()

	go func() {
		<-mCikis.ClickedCh
		log.Println("Kullanıcı tepsi menüsünden çıkışı seçti.")
		systray.Quit()
	}()
}

func onTrayExit() {
	// systray.Quit() çağrıldığında tetiklenir; process systray.Run() dönünce sonlanır.
}
