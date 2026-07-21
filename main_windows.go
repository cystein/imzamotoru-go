//go:build windows

package main

import (
	_ "embed"
	"fmt"
	"log"
	"net"
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

func onTrayReady() {
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

	mDurum := systray.AddMenuItem(fmt.Sprintf("Durum: Çalışıyor (v%s)", APP_VERSION), "")
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
