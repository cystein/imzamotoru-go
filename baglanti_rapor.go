package main

// Bağlantı testi: rapor imzalama, gönderim kuyruğu, nonce kaydı, yarım test kurtarma, yerel arşiv
// (PROTOKOL.md §8, §11).

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Derlemede -ldflags "-X main.btAnahtarHex=... -X main.btAnahtarNo=..." ile enjekte edilir
// (GitHub Actions secret'ı). Kaynakta YOK. Enjekte edilmemiş derleme herkesçe bilinen test anahtarı ve
// anahtar_no=0 ile imzalar; canlı sunucu anahtar_no=0'ı her zaman reddeder.
var (
	btAnahtarHex = ""
	btAnahtarNo  = "0"
	btCanliHedef = "https://sgkkolitakip.web.tr/statik_ip_ag.php"
)

// btTestAnahtari: simülatör ve anahtarsız derleme için HERKESE AÇIK anahtar (PROTOKOL §8.2).
const btTestAnahtari = "kolitakip-baglanti-testi-simulator-anahtari"

const btAzamiGovdeB64 = 512 * 1024 // base64 sonrası gövde sınırı (Kolitakip/proxy sınırı 1 MB)

func btAnahtar() (int, []byte) {
	no, _ := strconv.Atoi(btAnahtarNo)
	if no > 0 && btAnahtarHex != "" {
		if k, err := hex.DecodeString(btAnahtarHex); err == nil && len(k) >= 16 {
			return no, k
		}
	}
	return 0, []byte(btTestAnahtari)
}

// btImza: hex(HMAC-SHA256(anahtar, nonce || 0x0A || rapor_baytları)).
func btImza(anahtar []byte, nonce string, rapor []byte) string {
	m := hmac.New(sha256.New, anahtar)
	m.Write([]byte(nonce))
	m.Write([]byte{0x0A})
	m.Write(rapor)
	return hex.EncodeToString(m.Sum(nil))
}

func btVeriDizini(sim bool) string {
	var kok string
	if runtime.GOOS == "windows" {
		kok = os.Getenv("LOCALAPPDATA")
	}
	if kok == "" {
		kok, _ = os.UserCacheDir()
	}
	if kok == "" {
		kok = os.TempDir()
	}
	d := filepath.Join(kok, "KolitakipIMZA", "baglanti_testi")
	if sim {
		d = filepath.Join(d, "simulasyon")
	}
	os.MkdirAll(filepath.Join(d, "kuyruk"), 0700)
	os.MkdirAll(filepath.Join(d, "raporlar"), 0700)
	return d
}

// ---------------------------------------------------------------------------
// Rapor boyutu: base64 sonrası 512 KB'ı aşarsa yoklama dizileri kabalaştırılır.
// ---------------------------------------------------------------------------

type btKabaDizi struct {
	Bas     int64          `json:"bas"`
	Bit     int64          `json:"bit"`
	Sonuc   string         `json:"sonuc"` // tek sonuç ya da "karisik"
	Adet    int            `json:"adet"`
	Dagilim map[string]int `json:"dagilim,omitempty"`
}

// kabalastir, minMs'den kısa dizileri komşularıyla birleştirir ("karisik" + dağılım).
func kabalastir(liste []btYoklamaDizisi, minMs int64) []btKabaDizi {
	var out []btKabaDizi
	for _, d := range liste {
		kisa := d.Bit-d.Bas < minMs
		if n := len(out); n > 0 && (kisa || out[n-1].Sonuc == "karisik" && out[n-1].Bit-out[n-1].Bas < minMs || out[n-1].Sonuc == d.Sonuc) {
			o := &out[n-1]
			if o.Sonuc != d.Sonuc && o.Sonuc != "karisik" {
				o.Dagilim = map[string]int{o.Sonuc: o.Adet}
				o.Sonuc = "karisik"
			}
			if o.Sonuc == "karisik" {
				o.Dagilim[d.Sonuc] += d.Adet
			}
			o.Bit = d.Bit
			o.Adet += d.Adet
			continue
		}
		out = append(out, btKabaDizi{Bas: d.Bas, Bit: d.Bit, Sonuc: d.Sonuc, Adet: d.Adet})
	}
	return out
}

// raporBaytlari, raporu JSON'a çevirir; sınır aşılırsa yoklamaları giderek kabalaştırır.
func raporBaytlari(r btRapor, arp []btYoklamaDizisi, tcp map[int][]btYoklamaDizisi) []byte {
	b, _ := json.Marshal(r)
	for minMs := int64(2000); (arp != nil || tcp != nil) && base64.StdEncoding.EncodedLen(len(b)) > btAzamiGovdeB64 && minMs <= 3600000; minMs *= 2 {
		kTCP := map[string]any{}
		for port, l := range tcp {
			kTCP[fmt.Sprint(port)] = kabalastir(l, minMs)
		}
		r.Yoklamalar = map[string]any{"arp": kabalastir(arp, minMs), "tcp": kTCP, "kabalastirma_ms": minMs}
		b, _ = json.Marshal(r)
	}
	if base64.StdEncoding.EncodedLen(len(b)) > btAzamiGovdeB64 { // son çare: yoklamaları çıkar, olaylar kalır
		r.Yoklamalar = map[string]any{"cikarildi": "boyut_siniri"}
		b, _ = json.Marshal(r)
	}
	return b
}

// ---------------------------------------------------------------------------
// Gönderici
// ---------------------------------------------------------------------------

type btKuyrukKaydi struct {
	TestID   string    `json:"test_id"`
	URL      string    `json:"url"`
	Istek    []byte    `json:"istek"` // POST gövdesi (hazır, imzalı)
	SonTarih time.Time `json:"son_tarih"`
	Deneme   int       `json:"deneme"`
	Sha256   string    `json:"govde_sha256"`
}

type btGonderici struct {
	dizin    string
	sim      bool
	istemci  *http.Client
	mu       sync.Mutex
	nonceler []string
	// simülatör: ilk N POST'u ağ hatasıyla düşür (senaryo rapor_kuyrukta)
	simHata int
	hiz     float64
}

func yeniBtGonderici(sim bool, hiz float64) *btGonderici {
	g := &btGonderici{dizin: btVeriDizini(sim), sim: sim, hiz: hiz,
		istemci: &http.Client{Timeout: 30 * time.Second}}
	if b, err := os.ReadFile(filepath.Join(g.dizin, "nonceler.json")); err == nil {
		json.Unmarshal(b, &g.nonceler)
	}
	return g
}

func (g *btGonderici) nonceKullanildi(n string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, x := range g.nonceler {
		if x == n {
			return true
		}
	}
	return false
}

func (g *btGonderici) nonceKaydet(n string) {
	g.mu.Lock()
	g.nonceler = append(g.nonceler, n)
	if len(g.nonceler) > 100 {
		g.nonceler = g.nonceler[len(g.nonceler)-100:]
	}
	b, _ := json.Marshal(g.nonceler)
	g.mu.Unlock()
	os.WriteFile(filepath.Join(g.dizin, "nonceler.json"), b, 0600)
}

// arsivle, son 20 raporu yerelde tutar (imzalanan JSON aynen).
func (g *btGonderici) arsivle(testID string, rapor []byte) {
	d := filepath.Join(g.dizin, "raporlar")
	os.WriteFile(filepath.Join(d, time.Now().UTC().Format("20060102T150405")+"_"+testID+".json"), rapor, 0600)
	girdiler, _ := os.ReadDir(d)
	var adlar []string
	for _, e := range girdiler {
		adlar = append(adlar, e.Name())
	}
	sort.Strings(adlar)
	for len(adlar) > 20 {
		os.Remove(filepath.Join(d, adlar[0]))
		adlar = adlar[1:]
	}
}

// kuyrugaEkle, raporu imzalar, arşivler ve gönderimi başlatır.
func (g *btGonderici) kuyrugaEkle(testID, nonce, url string, rapor []byte, yenidenMs int64, saat *btSaat, durum func(map[string]any)) {
	g.arsivle(testID, rapor)
	no, anahtar := btAnahtar()
	if g.sim {
		no, anahtar = 0, []byte(btTestAnahtari)
	}
	istek, _ := json.Marshal(map[string]any{
		"protokol": btProtokol, "test_id": testID, "anahtar_no": no,
		"govde_b64": base64.StdEncoding.EncodeToString(rapor), "imza": btImza(anahtar, nonce, rapor),
	})
	ozet := sha256.Sum256(rapor)
	k := btKuyrukKaydi{TestID: testID, URL: url, Istek: istek, Sha256: hex.EncodeToString(ozet[:]),
		SonTarih: time.Now().Add(saat.gercek(yenidenMs))}
	durum(map[string]any{"durum": "hazirlaniyor", "govde_sha256": k.Sha256, "boyut": len(istek)})
	if url == "" {
		log.Printf("[BAĞLANTI] %s: rapor hedefi yok, gönderilmedi (yerelde arşivlendi)", testID)
		durum(map[string]any{"durum": "vazgecildi", "neden": "rapor_hedefi_yok", "govde_sha256": k.Sha256})
		return
	}
	g.kuyrukYaz(k)
	go g.gonder(k, saat, durum)
}

func (g *btGonderici) kuyrukYolu(id string) string {
	return filepath.Join(g.dizin, "kuyruk", id+".json")
}

func (g *btGonderici) kuyrukYaz(k btKuyrukKaydi) {
	b, _ := json.Marshal(k)
	os.WriteFile(g.kuyrukYolu(k.TestID), b, 0600)
}

// kuyrukDevam, açılışta yarım kalmış gönderimleri sürdürür.
func (g *btGonderici) kuyrukDevam() {
	girdiler, _ := os.ReadDir(filepath.Join(g.dizin, "kuyruk"))
	for _, e := range girdiler {
		b, err := os.ReadFile(filepath.Join(g.dizin, "kuyruk", e.Name()))
		var k btKuyrukKaydi
		if err != nil || json.Unmarshal(b, &k) != nil {
			continue
		}
		log.Printf("[BAĞLANTI] kuyrukta bekleyen rapor bulundu: %s (deneme %d)", k.TestID, k.Deneme)
		go g.gonder(k, yeniBtSaat(g.hiz), func(map[string]any) {})
	}
}

func (g *btGonderici) gonder(k btKuyrukKaydi, saat *btSaat, durum func(map[string]any)) {
	bekleme := int64(2000)
	for {
		k.Deneme++
		durum(map[string]any{"durum": "gonderiliyor", "deneme": k.Deneme, "govde_sha256": k.Sha256})
		kod, govde, err := g.post(k)
		switch {
		case err == nil && kod == 200:
			os.Remove(g.kuyrukYolu(k.TestID))
			log.Printf("[BAĞLANTI] %s rapor gönderildi (deneme %d)", k.TestID, k.Deneme)
			durum(map[string]any{"durum": "gonderildi", "deneme": k.Deneme, "http": kod, "govde_sha256": k.Sha256})
			return
		case err == nil && kod != 429 && kod < 500:
			os.Remove(g.kuyrukYolu(k.TestID))
			log.Printf("[BAĞLANTI] %s rapor reddedildi: HTTP %d: %.200s", k.TestID, kod, govde)
			if kod == 403 && !g.sim {
				// Olası ModSecurity engeli — yalnız kod + sürüm + test_id (KVKK; Kolitakip ile anlaşma).
				bildir(SeviyeUyari, "RAPOR_403", "test_id="+k.TestID)
			}
			durum(map[string]any{"durum": "reddedildi", "deneme": k.Deneme, "http": kod, "govde_sha256": k.Sha256})
			return
		}
		if err != nil {
			log.Printf("[BAĞLANTI] %s rapor gönderilemedi (deneme %d): %v", k.TestID, k.Deneme, err)
		} else {
			log.Printf("[BAĞLANTI] %s geçici sunucu hatası HTTP %d (deneme %d)", k.TestID, kod, k.Deneme)
		}
		if time.Now().After(k.SonTarih) {
			os.Remove(g.kuyrukYolu(k.TestID))
			durum(map[string]any{"durum": "vazgecildi", "deneme": k.Deneme, "govde_sha256": k.Sha256})
			return
		}
		g.kuyrukYaz(k)
		durum(map[string]any{"durum": "kuyrukta", "deneme": k.Deneme, "sonraki_ms": bekleme, "govde_sha256": k.Sha256})
		time.Sleep(saat.gercek(bekleme))
		if bekleme *= 2; bekleme > 60000 {
			bekleme = 60000
		}
	}
}

func (g *btGonderici) post(k btKuyrukKaydi) (int, string, error) {
	g.mu.Lock()
	if g.simHata > 0 {
		g.simHata--
		g.mu.Unlock()
		return 0, "", fmt.Errorf("simülasyon: ağ yok")
	}
	g.mu.Unlock()
	req, err := http.NewRequest("POST", k.URL, bytes.NewReader(k.Istek))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("KolitakipIMZA/%s (baglanti_testi; protokol %d)", APP_VERSION, btProtokol))
	resp, err := g.istemci.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, strings.TrimSpace(string(b)), nil
}

// ---------------------------------------------------------------------------
// Yarım test kurtarma: program test sürerken kapanırsa (öldürülme, çökme, kapatma) bir sonraki
// açılışta son anlık görüntü "yarim" rapor olarak gönderilir — kaçış yolu kalmasın.
// ---------------------------------------------------------------------------

type btAnlikGoruntu struct {
	Rapor     btRapor   `json:"rapor"`
	URL       string    `json:"url"`
	YenidenMs int64     `json:"yeniden_ms"`
	Zaman     time.Time `json:"zaman"`
}

func (g *btGonderici) anlikGoruntuYolu() string { return filepath.Join(g.dizin, "aktif_test.json") }

func (g *btGonderici) anlikGoruntuYaz(a btAnlikGoruntu) {
	a.Zaman = time.Now()
	b, _ := json.Marshal(a)
	gecici := g.anlikGoruntuYolu() + ".yeni"
	if os.WriteFile(gecici, b, 0600) == nil {
		os.Rename(gecici, g.anlikGoruntuYolu())
	}
}

func (g *btGonderici) anlikGoruntuSil() { os.Remove(g.anlikGoruntuYolu()) }

// yarimTestiKurtar, açılışta önceki çalışmadan kalan aktif test varsa yarım rapor olarak gönderir.
func (g *btGonderici) yarimTestiKurtar() {
	b, err := os.ReadFile(g.anlikGoruntuYolu())
	if err != nil {
		return
	}
	g.anlikGoruntuSil()
	var a btAnlikGoruntu
	if json.Unmarshal(b, &a) != nil || a.Rapor.TestID == "" {
		return
	}
	r := a.Rapor
	r.RaporTuru = "yarim"
	son := int64(0)
	if n := len(r.Olaylar); n > 0 {
		son = r.Olaylar[n-1].MonoMs
	}
	r.Olaylar = append(r.Olaylar, btOlay{Sira: len(r.Olaylar) + 1, MonoMs: son,
		Duvar: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), Kod: "program_yeniden_baslatildi",
		Veri: map[string]any{"son_bilinen_mono_ms": son, "son_goruntu_duvar": a.Zaman.UTC().Format(time.RFC3339)}})
	log.Printf("[BAĞLANTI] yarım kalmış test bulundu: %s — yarım rapor gönderiliyor", r.TestID)
	govde := raporBaytlari(r, nil, nil)
	g.kuyrugaEkle(r.TestID, r.Nonce, a.URL, govde, a.YenidenMs, yeniBtSaat(g.hiz), func(map[string]any) {})
}
