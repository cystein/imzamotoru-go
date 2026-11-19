package main

// Bağlantı testi modülünün açılışı ve --simule giriş noktası.

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

// İzinli origin'ler modül bazında: eczane sitesi (Kolitakip) yalnız bağlantı testini ve ping'i
// kullanabilir; imza işlemleri (kart okuma, PIN ile imza) yalnız imza sitesinden. Böylece Kolitakip
// sitesindeki olası bir XSS, eczacının kartına imza attırmaya kalkamaz.
var imzaKaynaklari = map[string]bool{
	"https://eimza.sgkkolitakip.web.tr":  true,
	"https://itiraz.sgkkolitakip.web.tr": true, // eski adres
	"http://localhost:3000":              true, // yerel geliştirme/test
}

var baglantiTestiKaynaklari = map[string]bool{
	"https://sgkkolitakip.web.tr":     true,
	"https://www.sgkkolitakip.web.tr": true,
	"http://localhost:3000":           true,
}

func kaynakIzinli(origin string) bool {
	return imzaKaynaklari[origin] || baglantiTestiKaynaklari[origin]
}

// wsBaglanti, tek yazıcı kuralını (gorilla/websocket) kilitle sağlar: bağlantı testi akışı aynı
// bağlantıya başka goroutine'lerden de yazar.
type wsBaglanti struct {
	c      *websocket.Conn
	mu     sync.Mutex
	origin string
}

func (w *wsBaglanti) Yaz(v any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.c.WriteJSON(v)
}

// btBaslatGercek: normal çalışmada modülü kurar (gözlemci platforma özel; yoksa "desteklenmiyor").
func btBaslatGercek() {
	btYon = &btYonetici{
		aboneler: map[btIstemci]string{}, saatHizi: 1, gozlemci: gercekGozlemciFabrikasi(),
		gonderici: yeniBtGonderici(false, 1), hedefler: map[string]string{"canli": btCanliHedef},
	}
	btYon.gonderici.kuyrukDevam()
	btYon.gonderici.yarimTestiKurtar()
}

// simuleCalistir: "--simule <senaryo>" giriş noktası. Gerçek kartla/ağla hiç konuşmaz.
func simuleCalistir(args []string) {
	fs := flag.NewFlagSet("simule", flag.ExitOnError)
	hiz := fs.Float64("hiz", 1, "zaman hızlandırma çarpanı (ör. 10)")
	raporURL := fs.String("rapor-url", "", "raporun POST edileceği yerel adres (yalnız simülatörde)")
	port := fs.String("port", PORT, "WebSocket portu")
	originler := fs.String("origin", "", "ek izinli origin'ler, virgülle (ör. http://localhost:8080)")
	if len(args) == 0 || args[0] == "liste" || strings.HasPrefix(args[0], "-") {
		fmt.Printf("Kullanım: %s --simule <senaryo> [--hiz 10] [--rapor-url URL] [--origin http://localhost:8080] [--port %s]\n\nSenaryolar:\n%s",
			os.Args[0], PORT, simSenaryoListesi())
		return
	}
	ad := args[0]
	s, ok := simSenaryolar[ad]
	if !ok {
		fmt.Printf("Bilinmeyen senaryo: %s\n\nSenaryolar:\n%s", ad, simSenaryoListesi())
		os.Exit(2)
	}
	fs.Parse(args[1:])
	for _, o := range strings.Split(*originler, ",") {
		if o = strings.TrimSpace(o); o != "" {
			baglantiTestiKaynaklari[o] = true
		}
	}
	gon := yeniBtGonderici(true, *hiz)
	btYon = &btYonetici{
		aboneler: map[btIstemci]string{}, saatHizi: *hiz, simulasyon: ad, gonderici: gon,
		hedefler: map[string]string{"canli": *raporURL, "test": *raporURL},
	}
	btYon.gozlemci = func(t *btTest) btGozlemci {
		gon.mu.Lock()
		gon.simHata = s.simHata
		gon.mu.Unlock()
		return &simGozlemci{s: s, saat: func() *btSaat { return t.saat }, bitirFn: func() {
			select {
			case t.bitirC <- "test_bitir":
			default:
			}
		}}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+*port)
	if err != nil {
		log.Fatalf("port açılamadı (gerçek KolitakipIMZA çalışıyor olabilir): %v", err)
	}
	log.Printf("[SİMÜLATÖR] senaryo=%s hız=%.1fx rapor-url=%q ws://127.0.0.1:%s/ws", ad, *hiz, *raporURL, *port)
	log.Printf("[SİMÜLATÖR] anahtar_no=0, test anahtarı=%q (herkese açık)", btTestAnahtari)
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) { wsIsleyici(w, r, true) })
	log.Fatal(http.Serve(ln, nil))
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return kaynakIzinli(r.Header.Get("Origin")) },
}

// wsIsleyici: tek WebSocket ucu; mesaj "modul" alanına göre yönlendirilir. "modul" yoksa ya da
// "imza" ise eski imza akışı (action alanıyla) aynen çalışır.
func wsIsleyici(w http.ResponseWriter, r *http.Request, sim bool) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// CheckOrigin izin vermediğinde Upgrade() HTTP hatasını zaten yazıp nil döndürüyor.
		return
	}
	defer conn.Close()
	ws := &wsBaglanti{c: conn, origin: r.Header.Get("Origin")}
	defer func() {
		if btYon != nil {
			btYon.ayril(ws)
		}
	}()
	for {
		_, ham, err := conn.ReadMessage()
		if err != nil {
			break
		}
		var baslik struct {
			Modul  string `json:"modul"`
			Action string `json:"action"`
		}
		json.Unmarshal(ham, &baslik)

		// "ping" donanıma dokunmuyor, anında cevap verir — sayfa sürüm/aktiflik göstergesi için kullanır.
		if baslik.Action == "ping" && (baslik.Modul == "" || baslik.Modul == "imza") {
			ws.Yaz(ResponseMessage{Status: "success", Data: map[string]string{"version": APP_VERSION}})
			continue
		}

		if baslik.Modul == btModul {
			if !baglantiTestiKaynaklari[ws.origin] {
				ws.Yaz(btHata(nil, "GECERSIZ_MESAJ", "bu sayfa bağlantı testi modülünü kullanamaz"))
				continue
			}
			if btYon == nil {
				ws.Yaz(btHata(nil, "PLATFORM_DESTEKLENMIYOR", "modül başlatılmadı"))
				continue
			}
			btYon.mesajIsle(ws, ham)
			continue
		}
		if baslik.Modul != "" && baslik.Modul != "imza" {
			ws.Yaz(map[string]any{"modul": baslik.Modul, "tip": "hata", "kod": "BILINMEYEN_MODUL"})
			continue
		}

		// İMZA MODÜLÜ (eski akış).
		if !imzaKaynaklari[ws.origin] {
			ws.Yaz(ResponseMessage{Status: "error", Error: "Bu sayfa imza işlemi başlatamaz."})
			continue
		}
		if sim {
			ws.Yaz(ResponseMessage{Status: "error", Error: "Simülatör modunda imza yok."})
			continue
		}
		var msg RequestMessage
		if err := json.Unmarshal(ham, &msg); err != nil {
			break
		}
		log.Printf("[WEB-SOCKET] Gelen İstek -> Action: '%s', CertID: '%s', Döküm: '%s'", msg.Action, msg.CertID, msg.DokumNo)
		replyChan := make(chan ResponseMessage, 1)
		jobQueue <- CardJob{
			Action: msg.Action, Pin: msg.Pin, Hash: msg.Hash, CertID: msg.CertID,
			DokumNo: msg.DokumNo, Token: msg.Token, Reply: replyChan,
		}
		ws.Yaz(<-replyChan)
	}
}
