package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pdfsign/sign"
	"github.com/gorilla/websocket"
	"github.com/miekg/pkcs11"
)

const (
	PORT         = "53911"
	NODE_API_URL = "https://itiraz.sgkkolitakip.web.tr" // Node.js Sunucu Adresin
)

// Sunucuya giden indirme/yükleme istekleri için zaman aşımlı istemci.
// (Varsayılan http.Get/http.Post süresiz bekleyebilir; Node çökerse/ağ takılırsa
// PKCS11 oturumu da beraberinde süresiz asılı kalırdı.)
var httpClient = &http.Client{Timeout: 30 * time.Second}

// imzalamaEngeli — uzaktan "kill switch". guncellemeyiDenetle() (update_windows.go), sunucudaki
// latest.json'da "min_supported_version" alanı bu çalışan APP_VERSION'dan yüksekse bunu set
// eder; cardWorker() imza işlemlerini (sign_hash/sign_pades) bu doluysa reddeder. Amaç: sahada
// GEÇERSİZ İMZA ÜRETEN bir sürüm bulunursa (bu projede daha önce iki kez oldu — RSA DigestInfo
// ve ECDSA r‖s kodlama hataları), düzeltmenin self-update ile yayılmasını (6 saat) beklemeden
// etkilenen istemcileri hemen durdurabilmek. atomic.Value kullanılıyor çünkü bu değeri yazan
// (checkForUpdates goroutine'i) ve okuyan (cardWorker goroutine'i) farklı goroutine'ler.
var imzalamaEngeli atomic.Value // string; hiç Store edilmemiş ya da "" = engel yok

func imzalamaEngelMesaji() string {
	v := imzalamaEngeli.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

// gorutinGuvenliBaslat, verilen fonksiyonu ayrı bir goroutine'de çalıştırır ve içinde
// BEKLENMEYEN bir panic olursa (Go'da recover edilmeyen bir panic normalde tüm süreci
// beraberinde götürür) süreci çökertmek yerine durumu loglayıp sunucuya son bir "PANIC"
// bildirimi göndermeyi dener. Amaç çökmeyi önlemek değil GÖRÜNÜR KILMAK — bugüne kadar hiçbir
// panic bize hiç bildirilmedi, eczacı tarafında sessizce "program kapandı" olarak kayboluyordu.
// Panic'i üreten goroutine sona erer (o alt sistem durur — ör. cardWorker çökerse imzalama artık
// çalışmaz) ama SÜREÇ ayakta kalır: diğer goroutine'ler (checkForUpdates, startServer) çalışmaya
// devam eder, böylece bir düzeltme yayınlanırsa self-update hâlâ devreye girebilir.
func gorutinGuvenliBaslat(isim string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				mesaj := fmt.Sprintf("goroutine '%s' beklenmeyen bir hatayla çöktü: %v\n%s", isim, r, debug.Stack())
				log.Println("💥 [PANIC]", mesaj)
				bildir(SeviyeKritik, "PANIC", mesaj)
				time.Sleep(2 * time.Second) // bildir()'in arka plandaki POST goroutine'i gönderebilsin diye kısa bir pay
			}
		}()
		fn()
	}()
}

type RequestMessage struct {
	Action  string `json:"action"`
	Pin     string `json:"pin"`
	Hash    string `json:"hash,omitempty"`
	CertID  string `json:"cert_id"`
	DokumNo string `json:"dokum_no,omitempty"`
	Token   string `json:"upload_token,omitempty"`
}

type ResponseMessage struct {
	Status string `json:"status"`
	Data   any    `json:"data,omitempty"`
	Error  string `json:"error,omitempty"`
}

type CardJob struct {
	Action  string
	Pin     string
	Hash    string
	CertID  string
	DokumNo string
	Token   string
	Reply   chan ResponseMessage
}

var jobQueue = make(chan CardJob, 100)

// Sadece izinli kaynaklardan gelen WebSocket bağlantılarını kabul et.
// (Eskiden her origin'e izin veriliyordu — bilgisayarda açık başka bir sekme
// sessizce list_certs çağırıp kullanıcının adını/TCKN'sini onaysız okuyabilirdi.)
var izinliKaynaklar = map[string]bool{
	"https://itiraz.sgkkolitakip.web.tr": true,
	"http://localhost:3000":              true, // yerel geliştirme/test
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return izinliKaynaklar[r.Header.Get("Origin")]
	},
}

func main() {
	// cardWorker() (donanım erişimi) kasıtlı olarak burada BAŞLAMIYOR — platformStartup()
	// port'u tekil olarak ele geçirdiğini doğruladıktan SONRA başlatıyor. Böylece ikinci bir
	// kopya (ör. exe'ye art arda çift tıklama) donanıma/akıllı karta hiç dokunmadan kapanır.
	platformStartup()
}

// startServer, WebSocket/HTTP sunucusunu verilen (zaten açılmış) listener üzerinden ayağa
// kaldırır. platformStartup() tarafından çağrılır — Linux'ta doğrudan, Windows'ta sistem
// tepsisi hazır olduktan sonra arka planda.
func startServer(ln net.Listener) {
	log.Printf("[BAŞLATMA] %s hazır, port: %s\n", APP_NAME, PORT)

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			// CheckOrigin izin vermediğinde (veya bağlantı bir sebeple yükseltilemediğinde)
			// Upgrade() zaten uygun bir HTTP hata yanıtı yazıp nil bir *Conn döndürüyor —
			// eskiden bu hata görmezden gelinip nil conn üzerinde Close/ReadJSON çağrılıyordu,
			// bu da her izinsiz kaynaktan gelen istekte panic'e (nil pointer dereference) yol açıyordu.
			return
		}
		defer conn.Close()
		for {
			var msg RequestMessage
			if err := conn.ReadJSON(&msg); err != nil {
				break
			}

			// "ping" donanıma dokunmuyor, kart okuyucu meşgulse bile kuyrukta beklemeden
			// anında cevap verir — web arayüzü bunu sürüm/aktiflik göstergesi için kullanır.
			// Anlamlı işlem loglarına (kim ne zaman imzaladı vb.) karışmasın diye bilerek
			// aşağıdaki log satırından önce, ayrı işleniyor.
			if msg.Action == "ping" {
				conn.WriteJSON(ResponseMessage{Status: "success", Data: map[string]string{"version": APP_VERSION}})
				continue
			}

			log.Printf("[WEB-SOCKET] Gelen İstek -> Action: '%s', CertID: '%s', Döküm: '%s'", msg.Action, msg.CertID, msg.DokumNo)

			replyChan := make(chan ResponseMessage, 1)
			jobQueue <- CardJob{
				Action:  msg.Action,
				Pin:     msg.Pin,
				Hash:    msg.Hash,
				CertID:  msg.CertID,
				DokumNo: msg.DokumNo,
				Token:   msg.Token,
				Reply:   replyChan,
			}

			res := <-replyChan
			conn.WriteJSON(res)
		}
	})
	log.Fatal(http.Serve(ln, nil))
}

// ============================================================================
// DONANIM İŞÇİSİ (ESKİ YAPINA HİÇ DOKUNULMADI)
// ============================================================================
func cardWorker() {
	runtime.LockOSThread()
	log.Println("🛡️ [WORKER] Donanım İş Parçacığı (OS Thread) kilitlendi.")

	// ÖNEMLİ: initDriver() başarısız olursa process ARTIK ÖLMÜYOR. Eskiden log.Fatalf() ile
	// tüm süreç os.Exit(1) oluyordu — bu, sürücüsü eksik/bozuk bir makinede kendi kendini
	// kilitleyen bir sistem yaratıyordu: program çalışmadığı için self-update (checkForUpdates,
	// bkz. update_windows.go) da hiç devreye giremiyor, düzeltme kullanıcıya asla ulaşamıyordu.
	// Artık: hata bildirilir (log + systray + uzak sunucu), süreç ayakta kalır, 5 dakikada bir
	// yeniden dener (kullanıcı sürücüyü sonradan kurabilir ya da exe güncellenebilir).
	p := surucuyuDeneYeninenBildir()

	yenidenDenemeAraligi := time.NewTicker(5 * time.Minute)
	defer yenidenDenemeAraligi.Stop()

	for {
		select {
		case job := <-jobQueue:
			if p == nil {
				msg := sonSurucuTeshisMesaji
				if msg == "" {
					msg = "Akıllı kart sürücüsü bulunamadı/başlatılamadı."
				}
				job.Reply <- ResponseMessage{Status: "error", Error: msg + " (Uygulama arka planda periyodik olarak yeniden deniyor.)"}
				continue
			}
			switch job.Action {
			case "list_certs":
				data, err := listCertificates(p)
				if err != nil {
					job.Reply <- ResponseMessage{Status: "error", Error: err.Error()}
				} else {
					job.Reply <- ResponseMessage{Status: "success", Data: data}
				}
			case "sign_hash":
				if engelMesaji := imzalamaEngelMesaji(); engelMesaji != "" {
					job.Reply <- ResponseMessage{Status: "error", Error: engelMesaji}
					continue
				}
				if job.CertID == "" {
					job.Reply <- ResponseMessage{Status: "error", Error: "Sertifika ID boş olamaz!"}
					continue
				}
				sig, err := signHash(p, job.Pin, job.Hash, job.CertID)
				if err != nil {
					job.Reply <- ResponseMessage{Status: "error", Error: err.Error()}
				} else {
					job.Reply <- ResponseMessage{Status: "success", Data: sig}
				}
			case "sign_pades":
				if engelMesaji := imzalamaEngelMesaji(); engelMesaji != "" {
					job.Reply <- ResponseMessage{Status: "error", Error: engelMesaji}
					continue
				}
				if job.CertID == "" || job.DokumNo == "" {
					job.Reply <- ResponseMessage{Status: "error", Error: "Sertifika ID veya Döküm No boş olamaz!"}
					continue
				}
				if job.Token == "" {
					job.Reply <- ResponseMessage{Status: "error", Error: "Yükleme jetonu (upload_token) eksik! Lütfen sayfayı yenileyip tekrar deneyin."}
					continue
				}
				err := signPAdESAndSync(p, job.Pin, job.CertID, job.DokumNo, job.Token)
				if err != nil {
					job.Reply <- ResponseMessage{Status: "error", Error: err.Error()}
				} else {
					job.Reply <- ResponseMessage{Status: "success", Data: "PAdES İmza PDF'e gömüldü ve sunucuya iletildi!"}
				}
			}
		case <-yenidenDenemeAraligi.C:
			if p == nil {
				p = surucuyuDeneYeninenBildir()
			}
		}
	}
}

// ErrSurucuHicKurulmamis: initDriver() sistemde bilinen HİÇBİR sürücü dosyası (System32/SysWOW64
// içinde akisp11.dll vb. hiçbiri yok) bulamadığında bu sentinel'i sarmalayarak döner. Bu, "sürücü
// hiç kurulu değil" durumunu "sürücü kurulu ama başlatılamadı (örn. mimari uyuşmazlığı)"
// durumundan ayırt etmemizi sağlar — ikisi eczacı için tamamen farklı eylemler gerektirir.
var ErrSurucuHicKurulmamis = errors.New("bilinen bir akıllı kart sürücüsü sistemde bulunamadı")

// sonSurucuTeshisMesaji, cardWorker()'ın sürücü olmadan gelen bir işe (list_certs/sign_pades)
// verdiği yanıtta eczacıya gösterdiği, en güncel ve SPESİFİK sürücü durumu açıklamasıdır.
// surucuyuDeneYeninenBildir() her denemede günceller — böylece web arayüzündeki hata mesajı
// artık sabit/genel bir cümle değil, "sürücü hiç kurulu değil" ile "kurulu ama mimarisi
// uyumsuz" gibi kök nedene özgü, eczacının ne yapması gerektiğini söyleyen bir metin olur.
var sonSurucuTeshisMesaji string

// surucuHatasiKullaniciMesaji, initDriver()'ın döndürdüğü teknik hatayı VE PC/SC seviyesindeki
// teşhisi (kategori) eczacının anlayıp aksiyon alabileceği bir Türkçe cümleye çevirir.
// Üç PC/SC kategorisi üç FARKLI kök nedeni işaret eder — üçüne de aynı "sürücü kurun" mesajını
// göstermek yanlış yönlendirme olurdu (bkz. EL_KITABI.md §9.1, 2026-08-15 log analizi: olayların
// %63'ü aslında sürücü sorunu bile değildi).
func surucuHatasiKullaniciMesaji(err error, kategori PcscKategori) string {
	switch kategori {
	case PcscKaynakYoneticisiKapali:
		return "Windows'un Akıllı Kart Hizmeti şu an çalışmıyor — bu bir sürücü sorunu DEĞİL. " +
			"Kart okuyucunuzun bilgisayara takılı olduğundan emin olun, ardından bilgisayarınızı " +
			"yeniden başlatın. Sorun sürerse BT desteğinize 'Smart Card servisi kapalı' olduğunu iletin."
	case PcscOkuyucuYok:
		return "Bilgisayarınızda bir akıllı kart okuyucu bulunamadı. Kart okuyucunuzun USB'ye " +
			"takılı olduğundan emin olun."
	}

	// PcscOkuyucuVarSurucuGerekli ya da PcscBilinmiyor (Linux/teşhis başarısız) — burada gerçekten
	// bir sürücü eksikliği söz konusu, initDriver()'ın kendi hatasına göre spesifikleştiriyoruz.
	if errors.Is(err, ErrSurucuHicKurulmamis) {
		return "Bilgisayarınızda akıllı kart okuyucu sürücüsü kurulu değil. Lütfen kartınızın (AKİS, TÜRKTRUST vb.) resmi sürücüsünü kurup uygulamayı yeniden başlatın."
	}
	if strings.Contains(err.Error(), "ERROR_BAD_EXE_FORMAT") {
		return "Bilgisayarınızda bulunan kart sürücüsü mimarinizle uyumsuz (32-bit/64-bit karışıklığı). Lütfen sürücüyü kaldırıp kart üreticinizin sitesinden doğru (64-bit) sürümü yeniden kurun."
	}
	return "Kart okuyucu sürücünüz bulundu ama başlatılamadı. Kart okuyucunuzu çıkarıp tekrar takmayı veya bilgisayarı yeniden başlatmayı deneyin; sorun sürerse destek ile iletişime geçin."
}

// sonBildirilenTeshis, en son SUNUCUYA bildirilen (log değil, bildir() ile POST edilen) tam
// teşhis metnidir — aynı metin tekrar üretilirse (5 dakikalık ticker aynı bozuk durumu tekrar
// tekrar buluyorsa) sunucuya yeniden POST ATILMAZ, sadece yerel logda kalır. 2026-08-15 log
// analizinde tek bir makine 24 saatte 295 kez aynı olayı bildirmişti — bu dedup, 1167 satırlık
// gürültüyü gerçek olay sayısına indirir. Durum düzelince ("" atanınca) bir sonraki bozulma
// yeniden bildirilir.
var sonBildirilenTeshis string

// surucuyuDeneYeninenBildir, initDriver()'ı bir kez dener; başarısızsa merkezi bildir()
// üzerinden (Kritik/SURUCU_YOK, ilk oluşumda) haber verir ve nil döner — çağıran taraf
// (cardWorker) bunu öldürücü bir hata olarak değil, "şimdilik yok, sonra tekrar denenecek"
// olarak ele alır.
func surucuyuDeneYeninenBildir() *pkcs11.Ctx {
	p, err := initDriver()
	if err != nil {
		// PKCS#11 DLL'i bulunamasa/başlatılamasa bile PC/SC (winscard.dll) seviyesinde okuyucu
		// ve kart görünüyor mu diye ayrıca bakıyoruz — bu teşhis, "okuyucu hiç yok" ile "Windows
		// servisi kapalı" ile "kart var ama bizim aday listemizde olmayan bir sürücü lazım"
		// ayrımını bizim tarafımızdan (uzaktan, eczaneye gitmeden) yapabilmemizi sağlıyor.
		kategori, pcscDetay := pcscTeshisi()
		log.Printf("⚠️ [WORKER] SÜRÜCÜ BAŞLATILAMADI: %v | PC/SC: %s", err, pcscDetay)
		sonSurucuTeshisMesaji = surucuHatasiKullaniciMesaji(err, kategori)

		// Kaynak Yöneticisi kapalıysa başlatmayı dene — çoğu zaman yönetici izni ister, garantisi
		// yok ama denemenin bedeli yok. Başarılı olursa sürücüyü HEMEN bir kez daha dene, 5 dakika
		// beklemeye gerek kalmasın.
		if kategori == PcscKaynakYoneticisiKapali {
			basarili, servisDetay := scardSvrBaslatmayiDene()
			log.Printf("[WORKER] SCardSvr başlatma denemesi: başarılı=%v | %s", basarili, servisDetay)
			if basarili {
				if p2, err2 := initDriver(); err2 == nil {
					log.Println("✅ [WORKER] SCardSvr başlatıldıktan sonra sürücü ikinci denemede bağlandı.")
					sonSurucuTeshisMesaji = ""
					sonBildirilenTeshis = ""
					bildir(SeviyeBilgi, "SURUCU_OK", "SCardSvr başlatıldıktan sonra sürücü bağlandı.")
					return p2
				}
			}
		}

		tamMesaj := fmt.Sprintf("Akıllı kart sürücüsü bulunamadı/başlatılamadı: %v | PC/SC teşhisi: %s", err, pcscDetay)
		if tamMesaj == sonBildirilenTeshis {
			return nil // aynı teşhis daha önce sunucuya bildirildi, tekrar POST atma
		}
		sonBildirilenTeshis = tamMesaj
		bildir(SeviyeKritik, "SURUCU_YOK", tamMesaj)
		return nil
	}
	sonSurucuTeshisMesaji = ""
	sonBildirilenTeshis = "" // düzeldi — bir dahaki bozulma yeniden bildirilsin
	log.Println("✅ [WORKER] Sürücü Thread'e başarıyla bağlandı, emirler bekleniyor...")
	bildir(SeviyeBilgi, "SURUCU_OK", "Akıllı kart sürücüsü başarıyla başlatıldı.")
	return p
}

// NOT: PKCS11 standardı karttan sadece nitel bayraklar verir (Normal / Az Kaldı / Son Deneme /
// Kilitli) — kartın gerçek azami deneme sayısını (3 mü, 5 mi, 10 mu?) HİÇBİR ZAMAN sayısal olarak
// vermez. Önceki sürümdeki "(3 Hak)" / "2 Hak Kaldı" gibi metinler uydurma/varsayılan sayılardı;
// gerçek kartın azami hakkı farklıysa yanıltıcı olabiliyordu. Bu yüzden artık sadece donanımın
// garanti ettiği nitel durumları gösteriyoruz.
// getPinStatus SADECE bilgilendirme amaçlıdır — arayüzde gösterilecek bir ön-izlenim döndürür,
// kesin bir hüküm değil. BURADAN merkezi bildir() ÇAĞRILMAZ: GetTokenInfo().Flags, OpenSession
// gerektirmeyen, session dışı bir sorgu olduğundan, marjinal okuyucu/kart teması ya da art arda
// gelen session aç/kapa trafiği yüzünden ara sıra yanlış (bozuk) değer dönebiliyor — Go seviyesinde
// err == nil dönse bile. 2026-07-28'de tam bu senaryo yaşandı: bir eczanede burada "PIN kilitli"
// okundu (Kritik rapor gitti, imza butonu kilitlendi), ama 1 dakika sonra AYNI kart gerçek
// Login()'i sorunsuz geçti — yani ilk okuma yanlış pozitifti. Kartın GERÇEKTEN kilitli olduğunun
// TEK güvenilir kanıtı Login()'in döndürdüğü CKR_PIN_LOCKED hata koludur (bkz. signHash/
// signPAdESAndSync) — bildir() ve gerçek engelleme kararı SADECE oradan verilir.
func getPinStatus(p *pkcs11.Ctx, slot uint) (string, bool) {
	info, err := p.GetTokenInfo(slot)
	if err != nil {
		return "Bilinmiyor", false
	}
	log.Printf("[DEBUG] TokenInfo.Flags ham değeri: 0x%08X (kart: %s)", info.Flags, info.Label)
	if info.Flags&pkcs11.CKF_USER_PIN_LOCKED != 0 {
		return "⛔ KİLİTLİ GÖRÜNÜYOR (PUK Kodu Gerekebilir)", true
	}
	if info.Flags&pkcs11.CKF_USER_PIN_FINAL_TRY != 0 {
		return "🔴 SON DENEME HAKKI! Bir yanlış giriş daha kartı tamamen kilitler.", false
	}
	if info.Flags&pkcs11.CKF_USER_PIN_COUNT_LOW != 0 {
		return "⚠️ DİKKAT: Az deneme hakkınız kaldı.", false
	}
	return "Normal", false
}

func listCertificates(p *pkcs11.Ctx) ([]map[string]any, error) {
	log.Println("[INFO] Donanım taranıyor...")
	slots, err := p.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		return nil, fmt.Errorf("KART OKUYUCU BOŞ VEYA KART TAKILI DEĞİL!")
	}

	slot := slots[0]
	pinMesaj, kilitliMi := getPinStatus(p, slot)
	log.Printf("[INFO] Kart Durumu -> PIN: %s | Kilitli: %v", pinMesaj, kilitliMi)

	session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, fmt.Errorf("Oturum açılamadı: %v", err)
	}
	defer p.CloseSession(session)

	p.FindObjectsInit(session, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE)})
	objs, _, _ := p.FindObjects(session, 10)
	p.FindObjectsFinal(session)

	var list []map[string]any
	for _, obj := range objs {
		attrs, _ := p.GetAttributeValue(session, obj, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
		})
		if len(attrs) < 2 || attrs[1].Value == nil {
			continue
		}
		cert, err := x509.ParseCertificate(attrs[1].Value)
		certBase64 := base64.StdEncoding.EncodeToString(attrs[1].Value)
		if err != nil {
			continue
		}

		algo := cert.PublicKeyAlgorithm.String()
		log.Printf("[INFO] Bulunan Sertifika -> Sahibi: '%s' | Algoritma: '%s'", cert.Subject.CommonName, algo)

		list = append(list, map[string]any{
			"id":         hex.EncodeToString(attrs[0].Value),
			"sahibi":     cert.Subject.CommonName,
			"tckn":       cert.Subject.SerialNumber,
			"cert_data":  certBase64,
			"bitis":      cert.NotAfter.Format("2006-01-02"),
			"pin_durumu": pinMesaj,
			"kilitli":    kilitliMi,
			"algoritma":  algo,
		})
	}
	log.Printf("[INFO] %d adet sertifika arayüze gönderildi.", len(list))
	return list, nil
}

func signHash(p *pkcs11.Ctx, pin, hashBase64, certID string) (string, error) {
	log.Printf("[SIGN-1] İmza emri alındı. Hedef ID: '%s'", certID)

	slots, err := p.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		return "", fmt.Errorf("KART TAKILI DEĞİL!")
	}
	slot := slots[0]

	// NOT: Burada artık getPinStatus()'un kilitliMi sonucuna bakarak Login()'den ÖNCE
	// işlemi reddetmiyoruz — o bayrak yanlış pozitif verebiliyor (bkz. getPinStatus yorumu).
	// pinMesaj yalnızca aşağıdaki hata mesajında bilgi amaçlı gösteriliyor.
	pinMesaj, _ := getPinStatus(p, slot)

	session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return "", fmt.Errorf("Oturum açılamadı: %v", err)
	}
	defer p.CloseSession(session)

	if err := p.Login(session, pkcs11.CKU_USER, pin); err != nil {
		// Kartın GERÇEKTEN kilitli olduğunun tek güvenilir kanıtı budur — Login()'in kendisinin
		// döndürdüğü CKR_PIN_LOCKED. Sadece bu durumda Kritik rapor gönderiyoruz.
		if pErr, ok := err.(pkcs11.Error); ok && pErr == pkcs11.CKR_PIN_LOCKED {
			bildir(SeviyeKritik, "PIN_KILITLI", fmt.Sprintf("Kart PIN'i GERÇEKTEN kilitli (Login CKR_PIN_LOCKED) — sertifika ID: %s", certID))
			return "", fmt.Errorf("❌ KART PIN KODU KİLİTLİ! PUK KODU İLE AÇMANIZ GEREKMEKTEDİR.")
		}
		log.Println("❌ [UYARI] PIN DOĞRULAMA BAŞARISIZ OLDU!")
		return "", fmt.Errorf("❌ PIN HATALI! Lütfen kontrol edin. Kart Durumu: %s | Hata: %v", pinMesaj, err)
	}
	defer p.Logout(session)

	idBytes, err := hex.DecodeString(certID)
	if err != nil {
		return "", fmt.Errorf("Geçersiz CertID formatı!")
	}

	p.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, idBytes),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
	})
	keys, _, _ := p.FindObjects(session, 1)
	p.FindObjectsFinal(session)

	var mech *pkcs11.Mechanism
	if len(keys) > 0 {
		mech = pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
	} else {
		p.FindObjectsInit(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, idBytes),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		})
		keys, _, _ = p.FindObjects(session, 1)
		p.FindObjectsFinal(session)

		if len(keys) == 0 {
			return "", fmt.Errorf("Bu ID için kartta ne ECDSA ne de RSA özel anahtarı bulunamadı!")
		}
		mech = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
	}

	h, err := base64.StdEncoding.DecodeString(hashBase64)
	if err != nil {
		return "", fmt.Errorf("Hash Base64 decode edilemedi!")
	}

	dataToSign := h
	if mech.Mechanism == pkcs11.CKM_ECDSA {
		hash := sha256.Sum256(h)
		dataToSign = hash[:]
	}

	err = p.SignInit(session, []*pkcs11.Mechanism{mech}, keys[0])
	if err != nil {
		return "", fmt.Errorf("SignInit hatası: %v", err)
	}

	start := time.Now()
	sig, err := p.Sign(session, dataToSign)
	if err != nil {
		return "", fmt.Errorf("İMZA ATILAMADI (Donanım İşlemi Reddeti): %v", err)
	}

	log.Printf("[SIGN-3] İmza başarıyla üretildi (işlem süresi: %v)", time.Since(start))
	return base64.StdEncoding.EncodeToString(sig), nil
}

// ============================================================================
// AKILLI KART (AKİS) İLE PAdES KÜTÜPHANESİ ARASINDAKİ KURUMSAL KÖPRÜ
// ============================================================================
type AkisSigner struct {
	p       *pkcs11.Ctx
	session pkcs11.SessionHandle
	privKey pkcs11.ObjectHandle
	pubKey  crypto.PublicKey
	mech    *pkcs11.Mechanism
}

func (a *AkisSigner) Public() crypto.PublicKey {
	return a.pubKey
}

// RFC 8017 (PKCS#1 v1.5) DigestInfo ASN.1 önekleri. RSA imzalamada bu önek, hash baytlarının
// önüne eklenip PKCS#1 dolgusu ondan sonra uygulanır — imzanın "hangi algoritmayla üretilmiş bir
// özeti imzaladığını" kriptografik olarak imzanın içine bağlar. PKCS#11'in CKM_RSA_PKCS
// mekanizması bunu KENDİSİ eklemiyor; yalnızca kendisine verilen baytlara PKCS#1 v1.5 dolgusu
// uygulayıp ham RSA işlemi yapıyor — önek eklemek çağıranın (bizim) sorumluluğumuz. Bu adım
// atlanınca üretilen imza kriptografik olarak yine GEÇERLİ ve sahtelenemez kalıyor (özel anahtarla
// üretildiği matematiksel olarak doğrulanabiliyor), ama RFC 5652/CMS'in beklediği standart
// DigestInfo yapısına uymuyor — Adobe Reader gibi katı doğrulayıcılar bu yüzden "imzanın
// geçerliliği bilinmiyor" uyarısı veriyordu. CKM_ECDSA için bu önek GEREKMEZ (ECDSA imzası zaten
// doğrudan hash üzerinden, DigestInfo sarmalamadan atılır) — bu yüzden yalnızca RSA dalında uygulanıyor.
var digestInfoOnekleri = map[crypto.Hash][]byte{
	crypto.SHA1:   {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

func (a *AkisSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	log.Println("[AKIS-SIGNER] PAdES kütüphanesi çipe imza emri verdi, donanım hesaplıyor...")
	err := a.p.SignInit(a.session, []*pkcs11.Mechanism{a.mech}, a.privKey)
	if err != nil {
		return nil, fmt.Errorf("SignInit hatası: %v", err)
	}

	dataToSign := digest
	if a.mech.Mechanism == pkcs11.CKM_RSA_PKCS {
		onek, ok := digestInfoOnekleri[opts.HashFunc()]
		if !ok {
			return nil, fmt.Errorf("desteklenmeyen özet algoritması, DigestInfo öneki bulunamadı: %v", opts.HashFunc())
		}
		dataToSign = append(append([]byte{}, onek...), digest...)
	}

	sig, err := a.p.Sign(a.session, dataToSign)
	if err != nil {
		return nil, fmt.Errorf("Donanım imza üretimi başarısız: %v", err)
	}

	if a.mech.Mechanism == pkcs11.CKM_ECDSA {
		// PKCS#11'in CKM_ECDSA mekanizması ham (r || s) bayt dizisini eğrinin boyutuna göre sabit
		// genişlikte döndürüyor (ör. P-384 için 48+48=96 bayt) — ama CMS/X.509'un beklediği
		// ECDSA-Sig-Value (RFC 3279) DER SEQUENCE{ INTEGER r, INTEGER s } formatıdır. Bu adım
		// atlanınca imza yine kriptografik olarak GEÇERLİ kalıyor (kartın özel anahtarıyla
		// üretildiği matematiksel olarak doğrulanabiliyor, sadece gerçek gerçek doğrulama
		// yaparken elle DER'e çevirmek gerekiyor) ama standart doğrulayıcılar imzayı
		// ayrıştıramadığı için reddediyor — RSA'daki DigestInfo eksikliğiyle aynı aile bir sorun.
		sig, err = ecdsaHamImzayiDerYap(sig)
		if err != nil {
			return nil, fmt.Errorf("ECDSA imzası DER formatına çevrilemedi: %v", err)
		}
	}

	log.Println("[AKIS-SIGNER] ✅ Çip kriptografik mühtü başarıyla üretti!")
	return sig, nil
}

// ecdsaHamImzayiDerYap, PKCS#11'in CKM_ECDSA'dan döndürdüğü ham (r || s) baytlarını (r ve s eşit
// uzunlukta, eğrinin bayt boyutuna göre sabit genişlikte) standart ECDSA-Sig-Value DER kodlamasına
// çevirir: SEQUENCE { INTEGER r, INTEGER s }.
func ecdsaHamImzayiDerYap(ham []byte) ([]byte, error) {
	if len(ham) == 0 || len(ham)%2 != 0 {
		return nil, fmt.Errorf("beklenmeyen ECDSA ham imza uzunluğu: %d bayt (çift sayı olmalı)", len(ham))
	}
	yari := len(ham) / 2
	r := new(big.Int).SetBytes(ham[:yari])
	s := new(big.Int).SetBytes(ham[yari:])
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

// ============================================================================
// PAdES GÖMME VE SUNUCUYA SENKRONİZASYON MODÜLÜ (ASLA ÇÖKMEYEN ZIRHLI SÜRÜM)
// ============================================================================
// sunucuHataMesaji, Node'un JSON gövdesindeki "message" alanını okuyup kullanıcıya
// anlamlı bir Türkçe hata olarak döndürür (ham "HTTP Durum: 401" yerine).
func sunucuHataMesaji(resp *http.Response, baglamMesaji string) error {
	// Sunucudan (veya araya giren biri tarafından) anormal büyük bir gövde gelirse belleği
	// tüketmeyelim — bir hata mesajı için 1MB zaten cömert bir tavan.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var sunucuHata struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &sunucuHata) == nil && sunucuHata.Message != "" {
		return fmt.Errorf("%s: %s", baglamMesaji, sunucuHata.Message)
	}
	return fmt.Errorf("%s (Sunucu beklenmeyen bir yanıt döndü, HTTP %d)", baglamMesaji, resp.StatusCode)
}

// ============================================================================
// İMZALAYAN KİŞİNİN KİMLİK MÜHÜRÜ (dairesel "E-İMZA" rozeti + kart sertifikasından
// okunan ad-soyad ve maskelenmiş TCKN). Node'ın ürettiği PDF'deki "İMZALAYAN ECZANE"
// kutusunun (x: 325.28-545.28, y: 50-145) üzerine, imzanın KENDİSİYLE AYNI incremental
// update içinde bindirilir — orijinal PDF byte'larına dokunmaz, Node'daki bütünlük (hash)
// kontrolünü bozmaz. Türkçe karakterlerin (Ş, Ğ, İ vb.) PDF standart fontlarıyla (WinAnsi)
// doğru basılamama riskine karşı, isim/TCKN metni pdfsign'ın kendi metin motoruna
// bırakılmadan, önceden Pillow ile üretilmiş bir glyph atlasından piksel piksel bindirilir.
// ============================================================================

const imzaKimlikMuhurBase64 = `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`

const imzaKimlikAtlasBase64 = `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
JEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSVE9Dvdx4FCdX12AfHp5n6eFNCMu0Hm9/gxrsw6gpPcsUO1cZFhkWGRYZFhkWGRbJ
sMiwyLCoT00b1IbnWTrk4bNnkWGRYZFhkQyLDIsMiwyLDIsMi2RYZFhkWGRYZFhkWGRYpOfU61UUFg3Y/vp8nqWH2LNIhkWGRYZFhkWGRYZFMiwyLDIs6i/T
Brjt1/Rgm7lhGUB5lm7od91hSIZFhkWGRTIsMiwyLDIsMiwyLJJhkWGRYZFhkWGRYZFhkQyLDIt6YJDXZ7mmT/bh4XmWHt6EsAzy3f0b9Ek7IochybDIsMiw
yLDIsMiwSIZFhkWGRZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSdJkDfVy41Gc
LBrknZdn6VCTwjLF74sMiwyLDIsMiwyLDItkWGRYZFjUp6YNcNuv8fAZlknJs3RDD5/DkAyLDIsMi2RYZFhkWGRYZFhkWCTDIsMiwyLDIsMiwyLDIhkWGRb1
wCCvz9KLG7YPz7P08KaGZZDv7t+gF/l2GJIMiwyLDIsMiwyLDItkWGRYZFjUfwZ5fZYhD589iwyLDIsMi2RYZFhkWGRYZFhkWCTDIsMiwyLDIsMiwyLDIhkW
GRYZFhkWGRYZFsmwyLDIsMiwyLDIsEiSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmS
JKmfDNXtA0VxsjKwJbAusA6wJjATmFH+WwQ8Vv57GBgv/90BXAlclmfpg0ajhmGJ4mQxYE/glcCOwPoVVHsTcAZwGnBanqX3G5UBDksUJxsC7wdeDyzXwU3N
Bf4I/DzP0lMNy2CFZBPgM8BrgSld3vxFwOfyLD3ZsPR3SIaBQ4APAtN63JyTgLfnWTpuWPovKNsAxwBr91Gz7gPelGfpKU0Jy9QBCMpbgROAqM+atiSw3/DI
6F0T42OZYel9UA4DDu3jdk4BXj48Mnr3xPjYRYald0H5NvChAdmPew2PjF41MT52lXOW7gfl68BHB2xfTgAvzLP0CsPSvaAcAPxqQPfntcAWeZbOcRjqfFC2
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
KuaZFj57N63N6v+vDwEzW/xspLhXoxbuPXT7nGUt4OcLOcHdLubhvBHW+zngay/ykRnAATEPPzYGfXKCG/NwK7Ap8AWef0L3L0YalNIR5Qnx85kKpAalz3qW
BXqDKWUvs+58Q9U6MQ+PVKxvM+DS+b7nPIrXYz8z0rcb1WO3+2dMm/rg8OQpJ1A859kEeH/Mw9U16rt3ePKUyUAKPAi8PebhuBnTpj5n0w+QJM3WbVM9SyZp
dmKSZi/zqEqSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmS
JEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSpGYY6pUdSdJsXWBfYGtgZWAJ4EngHuBi4KSYh6k2WYPD
kqTZMHAs8J6F7M884BRg/5iH6TZdw8KSpNkk4CJggxEUuxbYKubhaZuvs8Z0efs/GWFQAF4L/NSma1DPkqTZxsAVNarYNObhCpuwGT3Le2uW39fma05YtqpZ
fmubrzlhWaFm+ck2X3PCMtTl8uqjsDzQ5fLqo7BcVLP8xTZfc8JyQs3yweZrSFjKeySnVix+WszD5TZfc3oWgP2Aa0ZY5tqynJoUlvKB4FbAzykeFC7MKcCW
Phfqz8vXtknSbD2Ku7KvB17O/6Yo3FueDJ/oFAVJkiRJkiRJkiRJkiRJkiRJkiRJkiRJkiRJkiRJkiRJkiRJkiRJkiRJkiRJkiRJkiRJkiRJkiRJkiRJkiRJ
kiRJkiRJkiRJkiRJkiRJkiRJkiRJkiRJkiRJkiRJkiRJkiRJUt8a6taGkzS7pdPbjHlY2yavblwXt72Wh7+/jPEQyLDIsMiwyLDIsMiwSIZFhkWGRZIkSZIk
SZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSZIkSdUNDdKX
SdJsG2CLFj/++5iH3Ai0btyAfZ+vARu3+NmTbf6G9ixJmr0cuKvF73RdzMNrbf6RGTNA32WPEYT/dJvesGBYDMvChqBVgQ1b/PjVMQ932PTN7Vn2tFcxLO0e
guYZlgaHJUmzNYApLX787zEP99jsze1ZRjIEnWaTG5ZWh6AzbPKGhiVJs7WB9Vr8+GUxD/fb5M3tWbwKMixtvwqaC5xpczc0LEmarQu8ssWPXxLzMM3mbm7P
4hBkWFr29hY/9xzwa5u6oWFJ0mx9YK0WP35RzMN/bOrm9iwjecLsjTjD0pI5wG9s5oaGJUmzFFi9xY9fGPPwiM3c3J7FZ0GGpe1XQbOBs2zihoYlSbPXAau0
+PHzYx4es4mb27N4I86wtNSrDAFva/Hjs4Czbd7m9iybAiu1+NnzYh6esHmbGxZvxBmWloagMSMYgmYCv7Npm9uzbA5MbvGzf4x5eNqmbW5YvBFnWFoegnZv
8eMzgD/YrM3tWbYGlm3xs3+IeZhhszY3LN6IMywtDUHjgN1a/PjTwB9t0ub2LG8AkhY/+/uYh2ds0uaGxRtxhqWlIWg8sGuLH38SONfmbG7Psi3w0hY/e3bM
wyybs7lh8UacYWlpCFoE2KXFjz8OXGBTNrdneTOwRIuf/W3Mw7M2ZXPD4o04w9LSELQosHOLH38E+LPN2NyeZXtg8REMQXNsxuaGxRtxhqWlIWgisFOLH38Y
+KtN2Nye5S3ApBY/++uYh+dswuaGxRtxhqWlIWhS2bO04kHgEpuvuT3LTsDEFj97ZszDXJuvuWHxRpxhaWkIWhzYrsWP3w/8zaZrbs/yVmDREQxB82y65obF
G3GGpaUhaAmKp8ytuAe40mZrbs+yK7BIi589wyGo2WFxCOoTXf1d5yTNlgIeAsa38PE7Yx5Ws8ma27Ps1mJQwHsrjQ+LN+IchloaghJgGjCuhY//O+bhFTZX
c3uW3VsMir2KYfEqyGGotSFoWYpnPGNb+PgtMQ/r2FTN7Vne1mJQHIIMy4iGIMPS1GEoSbPlgftaDOqNMQ/r2kzN7VnePoLtemLb8LB4I85hqKUhaEWKaQat
bPcfMQ/r20TN7Vn2GEFA7VUMi0OQw9DCh6BVgDtb/Hge87CBzdPcnsVexbAYFsPS3iFoNSBt8eNXxTzcZdM0t2fxhXfD0vawzAPOsFkaGpYkzdYEXtPix6+I
ebjXZmluz+LtfUmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJEmSJElqrv8HLucNeSLJQ/EAAAAASUVORK5CYII=`

const atlasCellH = 160

type glyphBilgisi struct {
	Y     int // atlastaki dikey konum
	CropW int // kırpılacak genişlik (mürekkep genişliği + pay), en-boy oranını korumak için
}

var glyphAtlasMeta = map[string]glyphBilgisi{
	" ": {Y: 0, CropW: 29},
	"A": {Y: 160, CropW: 86},
	"B": {Y: 320, CropW: 82},
	"C": {Y: 480, CropW: 84},
	"Ç": {Y: 640, CropW: 84},
	"D": {Y: 800, CropW: 84},
	"E": {Y: 960, CropW: 75},
	"F": {Y: 1120, CropW: 73},
	"G": {Y: 1280, CropW: 87},
	"Ğ": {Y: 1440, CropW: 87},
	"H": {Y: 1600, CropW: 90},
	"I": {Y: 1760, CropW: 46},
	"İ": {Y: 1920, CropW: 46},
	"J": {Y: 2080, CropW: 74},
	"K": {Y: 2240, CropW: 84},
	"L": {Y: 2400, CropW: 72},
	"M": {Y: 2560, CropW: 107},
	"N": {Y: 2720, CropW: 89},
	"O": {Y: 2880, CropW: 88},
	"Ö": {Y: 3040, CropW: 88},
	"P": {Y: 3200, CropW: 83},
	"Q": {Y: 3360, CropW: 88},
	"R": {Y: 3520, CropW: 82},
	"S": {Y: 3680, CropW: 80},
	"Ş": {Y: 3840, CropW: 80},
	"T": {Y: 4000, CropW: 80},
	"U": {Y: 4160, CropW: 84},
	"Ü": {Y: 4320, CropW: 84},
	"V": {Y: 4480, CropW: 84},
	"W": {Y: 4640, CropW: 107},
	"X": {Y: 4800, CropW: 82},
	"Y": {Y: 4960, CropW: 81},
	"Z": {Y: 5120, CropW: 79},
	"0": {Y: 5280, CropW: 76},
	"1": {Y: 5440, CropW: 76},
	"2": {Y: 5600, CropW: 76},
	"3": {Y: 5760, CropW: 76},
	"4": {Y: 5920, CropW: 76},
	"5": {Y: 6080, CropW: 76},
	"6": {Y: 6240, CropW: 76},
	"7": {Y: 6400, CropW: 76},
	"8": {Y: 6560, CropW: 76},
	"9": {Y: 6720, CropW: 76},
	":": {Y: 6880, CropW: 45},
	"*": {Y: 7040, CropW: 63},
	".": {Y: 7200, CropW: 46},
	"-": {Y: 7360, CropW: 56},
	"/": {Y: 7520, CropW: 56},
}

func base64PNGYukle(b64 string) (image.Image, error) {
	temiz := strings.ReplaceAll(b64, "\n", "")
	data, err := base64.StdEncoding.DecodeString(temiz)
	if err != nil {
		return nil, err
	}
	return png.Decode(bytes.NewReader(data))
}

// kirpilmisGoruntu, bir image.Image'in dikdörtgen bir alt bölgesini yeni bir (0,0) kökenli
// image.Image olarak sunar — concrete tipe (NRGBA/RGBA) bağımlı kalmadan güvenli kırpma sağlar.
type kirpilmisGoruntu struct {
	kaynak     image.Image
	dikdortgen image.Rectangle
}

func (k *kirpilmisGoruntu) ColorModel() color.Model { return k.kaynak.ColorModel() }
func (k *kirpilmisGoruntu) Bounds() image.Rectangle {
	return image.Rect(0, 0, k.dikdortgen.Dx(), k.dikdortgen.Dy())
}
func (k *kirpilmisGoruntu) At(x, y int) color.Color {
	return k.kaynak.At(k.dikdortgen.Min.X+x, k.dikdortgen.Min.Y+y)
}

// resizeKutuOrtalamaIle, kaynak görseli (sadece küçültme için) basit kutu-ortalama filtresiyle
// hedef boyuta indirger. Go standart kütüphanesinde görsel yeniden boyutlandırma olmadığı için
// (yeni bağımlılık eklememek adına) kendimiz yazdık — premultiplied RGBA değerlerini ortalıyoruz.
func resizeKutuOrtalamaIle(src image.Image, yeniGenislik, yeniYukseklik int) *image.RGBA {
	bounds := src.Bounds()
	kaynakG, kaynakY := bounds.Dx(), bounds.Dy()
	dst := image.NewRGBA(image.Rect(0, 0, yeniGenislik, yeniYukseklik))
	if yeniGenislik <= 0 || yeniYukseklik <= 0 || kaynakG <= 0 || kaynakY <= 0 {
		return dst
	}
	for dy := 0; dy < yeniYukseklik; dy++ {
		sy0 := dy * kaynakY / yeniYukseklik
		sy1 := (dy + 1) * kaynakY / yeniYukseklik
		if sy1 <= sy0 {
			sy1 = sy0 + 1
		}
		for dx := 0; dx < yeniGenislik; dx++ {
			sx0 := dx * kaynakG / yeniGenislik
			sx1 := (dx + 1) * kaynakG / yeniGenislik
			if sx1 <= sx0 {
				sx1 = sx0 + 1
			}
			var toplamR, toplamG, toplamB, toplamA, sayac uint32
			for sy := sy0; sy < sy1 && sy < kaynakY; sy++ {
				for sx := sx0; sx < sx1 && sx < kaynakG; sx++ {
					r, g, b, a := src.At(bounds.Min.X+sx, bounds.Min.Y+sy).RGBA()
					toplamR += r
					toplamG += g
					toplamB += b
					toplamA += a
					sayac++
				}
			}
			if sayac == 0 {
				sayac = 1
			}
			dst.SetRGBA(dx, dy, color.RGBA{
				R: uint8((toplamR / sayac) >> 8),
				G: uint8((toplamG / sayac) >> 8),
				B: uint8((toplamB / sayac) >> 8),
				A: uint8((toplamA / sayac) >> 8),
			})
		}
	}
	return dst
}

// metinCiz, glyph atlasını kullanarak metni tuvale piksel piksel bindirir ve bir sonraki
// karakterin başlayacağı x konumunu döndürür.
func metinCiz(canvas *image.RGBA, atlas image.Image, metin string, x, yUst, hedefYukseklik int) int {
	cursor := x
	bosluk := hedefYukseklik / 2
	aralik := hedefYukseklik / 14
	for _, r := range metin {
		ch := string(r)
		meta, ok := glyphAtlasMeta[ch]
		if !ok {
			cursor += bosluk
			continue
		}
		if ch == " " {
			cursor += bosluk
			continue
		}
		hedefGenislik := meta.CropW * hedefYukseklik / atlasCellH
		if hedefGenislik < 1 {
			hedefGenislik = 1
		}
		kirpik := &kirpilmisGoruntu{
			kaynak:     atlas,
			dikdortgen: image.Rect(0, meta.Y, meta.CropW, meta.Y+atlasCellH),
		}
		glyphKucuk := resizeKutuOrtalamaIle(kirpik, hedefGenislik, hedefYukseklik)
		hedefDikdortgen := image.Rect(cursor, yUst, cursor+hedefGenislik, yUst+hedefYukseklik)
		draw.Draw(canvas, hedefDikdortgen, glyphKucuk, image.Point{}, draw.Over)
		cursor += hedefGenislik + aralik
	}
	return cursor
}

// tcknMaskele, TCKN'nin sadece ilk 3 hanesini gösterip gerisini yıldızla gizler.
func tcknMaskele(tckn string) string {
	tckn = strings.TrimSpace(tckn)
	if len(tckn) <= 3 {
		return tckn
	}
	return tckn[:3] + strings.Repeat("*", len(tckn)-3)
}

// imzaKimlikGorseliOlustur, dairesel "E-İMZA" mührünü + imzalayanın adını ve maskelenmiş
// TCKN'sini TEK bir PNG üzerinde birleştirir. Bu görsel Node'daki "İMZALAYAN ECZANE" kutusunun
// (220x95pt) tamamını kaplayacak şekilde konumlandırılır; mühür sağ üstte, kimlik bilgisi
// kutunun zaten dolu olan üst kısmının ALTINDA, sol tarafta yer alır.
func imzaKimlikGorseliOlustur(adSoyad, tcknMaskeli string) ([]byte, error) {
	const tuvalG, tuvalY = 880, 380 // 220x95pt kutunun 4x piksel karşılığı

	muhur, err := base64PNGYukle(imzaKimlikMuhurBase64)
	if err != nil {
		return nil, fmt.Errorf("mühür görseli çözülemedi: %v", err)
	}
	atlas, err := base64PNGYukle(imzaKimlikAtlasBase64)
	if err != nil {
		return nil, fmt.Errorf("glyph atlası çözülemedi: %v", err)
	}

	canvas := image.NewRGBA(image.Rect(0, 0, tuvalG, tuvalY))

	// Mühür: sağ üst köşe
	muhurBoyut := 190
	muhurKucuk := resizeKutuOrtalamaIle(muhur, muhurBoyut, muhurBoyut)
	muhurX, muhurY := tuvalG-muhurBoyut-70, 35
	draw.Draw(canvas,
		image.Rect(muhurX, muhurY, muhurX+muhurBoyut, muhurY+muhurBoyut),
		muhurKucuk, image.Point{}, draw.Over)

	// Kimlik bilgisi: sol alt (Node'un çizdiği "Tarih:" satırının altına denk gelir)
	metinCiz(canvas, atlas, strings.ToUpper(adSoyad), 48, 268, 36)
	metinCiz(canvas, atlas, "TCKN: "+tcknMaskeli, 48, 314, 30)

	var buf bytes.Buffer
	if err := png.Encode(&buf, canvas); err != nil {
		return nil, fmt.Errorf("kimlik görseli PNG olarak kodlanamadı: %v", err)
	}
	return buf.Bytes(), nil
}

func signPAdESAndSync(p *pkcs11.Ctx, pin, certID, dokumNo, token string) error {
	log.Printf("[PAdES-1] Döküm: %s için PAdES süreci başladı...", dokumNo)

	// 1. Sunucudan imzasız ham PDF'i indir (JWT jetonuyla korumalı rota)
	// NOT: path /api/itiraz/* — eskiden /api/ornekleme/* idi, uygulama artık hem örnekleme hem
	// kesinti itirazını kapsadığı için sunucu tarafında yeniden adlandırıldı (v1.3.0). Sunucu,
	// eski path'i geçiş süresince paralel olarak da kabul etmeye devam ediyor (bkz. EL_KITABI.md
	// §4, §9.3) — ama yeni kurulan/güncellenen istemciler doğrudan yeni path'i kullanmalı.
	pdfUrl := fmt.Sprintf("%s/api/itiraz/download/%s?token=%s", NODE_API_URL, url.PathEscape(dokumNo), url.QueryEscape(token))
	log.Printf("[PAdES-2] Ham PDF sunucudan çekiliyor: %s/api/itiraz/download/%s", NODE_API_URL, dokumNo)

	resp, err := httpClient.Get(pdfUrl)
	if err != nil {
		return fmt.Errorf("Sunucuya bağlanılamadı! Node.js çalışıyor mu ve internet bağlantınız düzgün mü? Detay: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return sunucuHataMesaji(resp, "İmzasız PDF sunucudan alınamadı")
	}

	// Resmi bir dilekçe için 50MB zaten çok cömert bir tavan — anormal büyük bir yanıt belleği
	// tüketmesin diye sınırlıyoruz.
	pdfData, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20))
	if err != nil || len(pdfData) == 0 {
		return fmt.Errorf("PDF dosya içeriği okunamadı veya dosya boş!")
	}

	// 2. PKCS11 oturumu aç ve sertifikayı bul
	slots, err := p.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		return fmt.Errorf("Kart okuyucuda takılı değil veya temas etmiyor!")
	}
	slot := slots[0]

	session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return fmt.Errorf("Kart oturumu açılamadı: %v", err)
	}
	defer p.CloseSession(session)

	if err := p.Login(session, pkcs11.CKU_USER, pin); err != nil {
		// Kartın GERÇEKTEN kilitli olduğunun tek güvenilir kanıtı budur — Login()'in kendisinin
		// döndürdüğü CKR_PIN_LOCKED. GetTokenInfo().Flags'teki bayrağa (bkz. getPinStatus) artık
		// güvenmiyoruz; gerçek imza yolu (bu fonksiyon) buraya kadar o bayrağa hiç bakmadan geldi.
		if pErr, ok := err.(pkcs11.Error); ok && pErr == pkcs11.CKR_PIN_LOCKED {
			bildir(SeviyeKritik, "PIN_KILITLI", fmt.Sprintf("Kart PIN'i GERÇEKTEN kilitli (Login CKR_PIN_LOCKED) — sertifika ID: %s, döküm: %s", certID, dokumNo))
			return fmt.Errorf("❌ KART PIN KODU KİLİTLİ! PUK KODU İLE AÇMANIZ GEREKMEKTEDİR.")
		}
		return fmt.Errorf("❌ PIN Hatalı veya Kart Okunamadı! Lütfen PIN kodunuzu kontrol edip tekrar deneyin. (Detay: %v)", err)
	}
	defer p.Logout(session)

	idBytes, err := hex.DecodeString(certID)
	if err != nil {
		return fmt.Errorf("Sertifika ID formatı geçersiz!")
	}

	// Özel Anahtarı Bul
	p.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, idBytes),
	})
	keys, _, _ := p.FindObjects(session, 1)
	p.FindObjectsFinal(session)
	if len(keys) == 0 {
		return fmt.Errorf("Bu sertifika ID'si için kartta ÖZEL ANAHTAR bulunamadı!")
	}

	// Açık Sertifikayı Bul
	p.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_ID, idBytes),
	})
	certObjs, _, _ := p.FindObjects(session, 1)
	p.FindObjectsFinal(session)
	if len(certObjs) == 0 {
		return fmt.Errorf("Kart içinde sertifika nesnesi okunamadı!")
	}

	valAttr, err := p.GetAttributeValue(session, certObjs[0], []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)})
	if err != nil || len(valAttr) == 0 || valAttr[0].Value == nil {
		return fmt.Errorf("Sertifika veri içeriği (Value) karttan okunamadı!")
	}

	cert, err := x509.ParseCertificate(valAttr[0].Value)
	if err != nil {
		return fmt.Errorf("Sertifika formatı ayrıştırılamadı (X509): %v", err)
	}

	// SERTİFİKA SÜRESİ KONTROLÜ — ikinci güvence: aynı kontrol zaten tarayıcı tarafında (PIN
	// istenmeden önce, ornekleme.html) yapılıyor ve sunucu tarafında da gölge modda tespit
	// ediliyor (bkz. sgk-imza-platformu EL_KITABI.md §4.6) — burası savunma-derinliği, tarayıcı
	// kontrolü bir şekilde atlanırsa (bayat önbellek, ileride farklı bir kod yolu) diye. PKCS#11
	// imza işlemi kartın özel anahtarıyla ham bir kriptografik işlemdir, sertifikanın geçerlilik
	// tarihine hiç bakmaz — bu kontrolü BİZ koymazsak hiç kimse koymuyor demektir.
	simdi := time.Now()
	if simdi.Before(cert.NotBefore) || simdi.After(cert.NotAfter) {
		return fmt.Errorf("❌ Bu sertifikanın geçerlilik süresi (%s – %s) imzalama anını kapsamıyor. Süresi dolmuş/henüz başlamamış bir sertifikayla imza atılamaz.",
			cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
	}

	var mech *pkcs11.Mechanism
	if cert.PublicKeyAlgorithm == x509.ECDSA {
		log.Println("[PAdES] Algoritma ECDSA olarak tespit edildi.")
		mech = pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
	} else {
		log.Println("[PAdES] Algoritma RSA olarak tespit edildi.")
		mech = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
	}

	// 3. AkisSigner Köprüsünü Kur
	akisSigner := &AkisSigner{
		p:       p,
		session: session,
		privKey: keys[0],
		pubKey:  cert.PublicKey,
		mech:    mech,
	}

	// 4. PAdES İmza Yapılandırması ve PDF Okuyucu
	log.Println("[PAdES-3] PDF mühürleme ve kriptografik damga hazırlanıyor...")
	inputReader := bytes.NewReader(pdfData)
	size := int64(len(pdfData))

	pdfReader, err := pdf.NewReader(inputReader, size)
	if err != nil {
		return fmt.Errorf("PDF yapısı bozuk veya okuyucu başlatılamadı: %v", err)
	}

	var outputBuffer bytes.Buffer

	// TAM DOĞRU YAPILANDIRMA (Görünür İmzalı)
	// İmza kimlik mührü (dairesel "E-İMZA" rozeti + kart sertifikasından okunan ad-soyad ve
	// maskelenmiş TCKN), Node'un ürettiği PDF'deki "İMZALAYAN ECZANE" kutusunun tamamına
	// (x: 325.28-545.28, y: 50-145) denk gelecek şekilde konumlandırıldı. Görsel oluşturulamazsa
	// (beklenmez ama zırhlı kalalım) imza görünmez uygulanmaya devam eder.
	appearance := sign.Appearance{Visible: false}
	adSoyad := cert.Subject.CommonName
	tcknMaskeli := tcknMaskele(cert.Subject.SerialNumber)
	if kimlikPNG, kimlikErr := imzaKimlikGorseliOlustur(adSoyad, tcknMaskeli); kimlikErr == nil {
		appearance = sign.Appearance{
			Visible:     true,
			Page:        1,
			LowerLeftX:  325.28,
			LowerLeftY:  50,
			UpperRightX: 545.28,
			UpperRightY: 145,
			Image:       kimlikPNG,
		}
	} else {
		log.Printf("⚠️ İmza kimlik görseli oluşturulamadı, imza görünmez uygulanacak: %v", kimlikErr)
	}

	signerData := sign.SignData{
		Certificate: cert,

		Signature: sign.SignDataSignature{
			CertType: sign.ApprovalSignature,
			Info: sign.SignDataSignatureInfo{
				Name:        cert.Subject.CommonName,
				Location:    "İstanbul Sosyal Güvenlik İl Müdürlüğü - Süreyyapaşa SSGM",
				Reason:      "5070 Sayılı Kanun Gereğince Resmi Örneklemeye İtiraz Dilekçesi e-İmza Onayı",
				ContactInfo: "sureyyapasakomisyon@sgk.gov.tr",
				Date:        time.Now(),
			},
		},
		Signer:         akisSigner,
		RevocationData: revocation.InfoArchival{},
		Appearance:     appearance,
	}

	// 5. İmzayı PDF'e Göm
	if err := sign.Sign(inputReader, &outputBuffer, pdfReader, size, signerData); err != nil {
		return fmt.Errorf("PAdES imza gömme işlemi başarısız: %v", err)
	}

	// 6. İmzalı PAdES dosyasını Node.js Sunucusuna geri post et (Sync)
	log.Println("[PAdES-4] Mühürlü PDF sunucuya geri yükleniyor (Sync)...")
	signedBase64 := base64.StdEncoding.EncodeToString(outputBuffer.Bytes())
	sertifikaBase64 := base64.StdEncoding.EncodeToString(valAttr[0].Value)
	// NOT: "imza_base64" alanı kasıtlı olarak GÖNDERİLMİYOR — eskiden "signed_pdf" ile birebir
	// aynı veriyi (imzalı PDF'in tamamı, base64) ikinci kez taşıyordu, gövdeyi gereksiz yere
	// ~%45 büyütüyordu. Bu, 2026-08-19'da proxy'de ModSecurity'nin 128KB'lık gövde limitine
	// (SecRequestBodyNoFilesLimit) çarpıp TÜM imzalama isteklerini günlerce kesmesine katkıda
	// bulundu (bkz. EL_KITABI.md §9.12). Sunucu artık "imza_base64" DB sütununu "signed_pdf"
	// alanından dolduruyor (eski istemcilerle geriye dönük uyumlu — bkz. app.js).
	payload := map[string]string{
		"dokum_no":      dokumNo,
		"signed_pdf":    signedBase64,
		"imzaci_tc":     cert.Subject.SerialNumber,
		"imzaci_ad":     cert.Subject.CommonName,
		"sertifika_bin": sertifikaBase64,
		"upload_token":  token,
		// Hangi imza motoru sürümünün imzaladığı — geriye dönük hata ayıklama/istatistik için
		// (ör. "bu 5 evrak da 1.2.1 ile imzalanmış, o sürümde bilinen X hatası vardı" diyebilmek).
		"imza_motoru_surumu": APP_VERSION,
	}
	jsonPayload, _ := json.Marshal(payload)

	postResp, err := httpClient.Post(fmt.Sprintf("%s/api/itiraz/save_signed", NODE_API_URL), "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("İmzalı dosya sunucuya gönderilemedi (Ağ Hatası): %v", err)
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != 200 {
		return sunucuHataMesaji(postResp, "Sunucu imzalı dosyayı reddetti")
	}

	log.Println("[PAdES-5] Evrak başarıyla mühürlendi ve arşive kaldırıldı.")
	return nil
}
