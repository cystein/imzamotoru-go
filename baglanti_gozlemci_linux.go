//go:build linux

package main

// Linux ağ gözlemcisi (PROTOKOL.md §4–§5, §11.4). Yönetici hakkı GEREKTİRMEZ:
//   - yol/ağ geçidi: /proc/net/route (ana tablo; politika yönlendirmesi kullanan VPN'ler ayrıca
//     arayüz türünden yakalanır),
//   - arayüzler: /sys/class/net (operstate, carrier, tür, sürücü, hız),
//   - TCP yoklaması ve TTL=2 ölçümü (UDP + IP_RECVERR, tracepath yöntemi) yetkisiz,
//   - ARP: gerçek ARP isteği AF_PACKET ister → yalnız programa CAP_NET_RAW verilmişse
//     (`sudo setcap cap_net_raw+ep ./imzaci`). O zaman her yoklama önbellekten bağımsız, TAZE bir
//     ARP isteğidir. Yetki yoksa ARP "yok_destek" raporlanır (onbellek_once: /proc/net/arp) ve ağ
//     geçidi TCP ile izlenir; karar sunucuda.
//   - uyku: Linux'ta Go'nun monotonik saati askıdaki süreyi saymaz; motor duvar saatiyle
//     karşılaştırıp "saat_atlamasi" üretir (baglanti_testi.go saatDenetle).

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func gercekGozlemciFabrikasi() func(t *btTest) btGozlemci {
	return func(t *btTest) btGozlemci { return &linuxGozlemci{} }
}

// ---------------------------------------------------------------------------
// Arayüzler
// ---------------------------------------------------------------------------

type lArayuz struct {
	No        int
	Ad        string
	Durum     string // operstate
	Yonetim   bool   // IFF_UP
	Calisiyor bool   // IFF_RUNNING
	Carrier   int    // 1 bağlı, 0 değil, -1 bilinmiyor
	Tip       int    // /sys/class/net/X/type (ARPHRD_*)
	Surucu    string
	Kablosuz  bool
	TunTap    bool
	HizMbps   int
	MAC       net.HardwareAddr
	IPv4      []string
}

func sysOku(ad, dosya string) string {
	b, err := os.ReadFile(filepath.Join("/sys/class/net", ad, dosya))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (a lArayuz) up() bool {
	return a.Durum == "up" || (a.Durum == "unknown" && a.Yonetim && a.Calisiyor)
}

func (a lArayuz) vpnMi() bool {
	ad := strings.ToLower(a.Ad)
	for _, on := range []string{"tun", "tap", "wg", "ppp", "tailscale", "zt", "nordlynx", "proton", "cscotun", "vpn", "ipsec", "gpd"} {
		if strings.HasPrefix(ad, on) {
			return true
		}
	}
	return a.TunTap || a.Tip == 65534 || a.Tip == 512
}

func (a lArayuz) sanalMi() bool {
	ad := strings.ToLower(a.Ad)
	for _, on := range []string{"docker", "br-", "veth", "virbr", "vmnet", "vboxnet", "lxc", "lxd", "cni", "flannel", "podman"} {
		if strings.HasPrefix(ad, on) {
			return true
		}
	}
	return a.Surucu == "bridge" || a.Surucu == "veth"
}

func (a lArayuz) tur() string {
	switch {
	case a.vpnMi():
		return "tunel"
	case a.sanalMi():
		return "sanal"
	case a.Kablosuz:
		return "wifi"
	case strings.HasPrefix(strings.ToLower(a.Ad), "wwan") || a.Surucu == "qmi_wwan" || a.Surucu == "cdc_mbim" || a.Surucu == "option":
		return "mobil"
	case a.Tip == 1:
		return "ethernet"
	}
	return "diger"
}

func arayuzleriOkuLinux() (map[int]lArayuz, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	m := map[int]lArayuz{}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		a := lArayuz{No: i.Index, Ad: i.Name, Durum: sysOku(i.Name, "operstate"), Yonetim: i.Flags&net.FlagUp != 0,
			Calisiyor: i.Flags&net.FlagRunning != 0, Carrier: -1, MAC: i.HardwareAddr}
		if c, err := strconv.Atoi(sysOku(i.Name, "carrier")); err == nil {
			a.Carrier = c
		}
		a.Tip, _ = strconv.Atoi(sysOku(i.Name, "type"))
		a.HizMbps, _ = strconv.Atoi(sysOku(i.Name, "speed"))
		if hedef, err := os.Readlink(filepath.Join("/sys/class/net", i.Name, "device", "driver")); err == nil {
			a.Surucu = filepath.Base(hedef)
		}
		if _, err := os.Stat(filepath.Join("/sys/class/net", i.Name, "wireless")); err == nil {
			a.Kablosuz = true
		} else if _, err := os.Stat(filepath.Join("/sys/class/net", i.Name, "phy80211")); err == nil {
			a.Kablosuz = true
		}
		if _, err := os.Stat(filepath.Join("/sys/class/net", i.Name, "tun_flags")); err == nil {
			a.TunTap = true
		}
		if adrs, err := i.Addrs(); err == nil {
			for _, ad := range adrs {
				if n, ok := ad.(*net.IPNet); ok && n.IP.To4() != nil {
					on, _ := n.Mask.Size()
					a.IPv4 = append(a.IPv4, fmt.Sprintf("%s/%d", n.IP.To4(), on))
				}
			}
		}
		m[a.No] = a
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Yollar (/proc/net/route, IPv4 ana tablo)
// ---------------------------------------------------------------------------

type lYol struct {
	Arayuz   string
	Hedef    uint32
	Maske    uint32
	AgGecidi net.IP
	Metrik   int
}

func hexIP(s string) uint32 { // /proc/net/route: küçük uçlu hex
	v, _ := strconv.ParseUint(s, 16, 32)
	return uint32(v)
}

func uint32IP(v uint32) net.IP {
	b := make(net.IP, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func yollariOku() []lYol {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil
	}
	defer f.Close()
	var y []lYol
	s := bufio.NewScanner(f)
	s.Scan() // başlık
	for s.Scan() {
		a := strings.Fields(s.Text())
		if len(a) < 8 {
			continue
		}
		bayrak, _ := strconv.ParseUint(a[3], 16, 32)
		if bayrak&0x1 == 0 { // RTF_UP
			continue
		}
		met, _ := strconv.Atoi(a[6])
		y = append(y, lYol{Arayuz: a[0], Hedef: hexIP(a[1]), AgGecidi: uint32IP(hexIP(a[2])), Maske: hexIP(a[7]), Metrik: met})
	}
	return y
}

// enIyiYolLinux: hedefe en uzun önek eşleşmesi, eşitlikte en küçük metrik.
func enIyiYolLinux(hedef net.IP) (lYol, bool) {
	h := binary.LittleEndian.Uint32(hedef.To4())
	var en lYol
	enOnek, bulundu := -1, false
	for _, y := range yollariOku() {
		if h&y.Maske != y.Hedef&y.Maske {
			continue
		}
		onek := 0
		for m := y.Maske; m != 0; m &= m - 1 {
			onek++
		}
		if onek > enOnek || (onek == enOnek && y.Metrik < en.Metrik) {
			en, enOnek, bulundu = y, onek, true
		}
	}
	return en, bulundu
}

// ---------------------------------------------------------------------------
// ARP: önbellek (/proc/net/arp) ve gerçek istek (AF_PACKET, CAP_NET_RAW)
// ---------------------------------------------------------------------------

func arpOnbellek(ip net.IP, arayuz string) (string, string) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return "yok", ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Scan()
	for s.Scan() {
		a := strings.Fields(s.Text())
		if len(a) < 6 || a[0] != ip.String() || (arayuz != "" && a[5] != arayuz) {
			continue
		}
		bayrak, _ := strconv.ParseUint(strings.TrimPrefix(a[2], "0x"), 16, 32)
		mac, _ := net.ParseMAC(a[3])
		if bayrak&0x2 != 0 { // ATF_COM
			return "complete", ouiYaz(mac)
		}
		return "incomplete", ""
	}
	return "yok", ""
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// arpIstegi: ağ geçidine tek bir taze ARP isteği gönderir, cevabı (gönderen MAC) bekler.
func arpIstegi(a lArayuz, kaynak, hedef net.IP, zaman time.Duration) (net.HardwareAddr, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ARP), Ifindex: a.No}); err != nil {
		return nil, err
	}
	paket := make([]byte, 28)
	binary.BigEndian.PutUint16(paket[0:], 1)      // Ethernet
	binary.BigEndian.PutUint16(paket[2:], 0x0800) // IPv4
	paket[4], paket[5] = 6, 4
	binary.BigEndian.PutUint16(paket[6:], 1) // istek
	copy(paket[8:14], a.MAC)
	copy(paket[14:18], kaynak.To4())
	copy(paket[24:28], hedef.To4())
	yayin := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ARP), Ifindex: a.No, Halen: 6}
	for i := 0; i < 6; i++ {
		yayin.Addr[i] = 0xff
	}
	if err := unix.Sendto(fd, paket, 0, yayin); err != nil {
		return nil, err
	}
	son := time.Now().Add(zaman)
	buf := make([]byte, 128)
	for {
		kalan := time.Until(son)
		if kalan <= 0 {
			return nil, errZamanAsimi
		}
		tv := unix.NsecToTimeval(kalan.Nanoseconds())
		unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, err
		}
		if n >= 28 && binary.BigEndian.Uint16(buf[6:]) == 2 && net.IP(buf[14:18]).Equal(hedef.To4()) {
			return net.HardwareAddr(append([]byte{}, buf[8:14]...)), nil
		}
	}
}

var errZamanAsimi = errors.New("zaman aşımı")

// arpYetkisiVar: AF_PACKET soketi açılabiliyor mu (CAP_NET_RAW).
func arpYetkisiVar() bool {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}

// ---------------------------------------------------------------------------
// TTL=2 (yetkisiz): UDP + IP_RECVERR → ICMP "time exceeded" gönderen adres (tracepath yöntemi)
// ---------------------------------------------------------------------------

func ttl2Linux(hedef net.IP, zaman time.Duration) (net.IP, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1)
	unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, 2)
	sa := &unix.SockaddrInet4{Port: 33434}
	copy(sa.Addr[:], hedef.To4())
	if err := unix.Sendto(fd, []byte("kolitkp"), 0, sa); err != nil {
		return nil, err
	}
	son := time.Now().Add(zaman)
	buf, oob := make([]byte, 64), make([]byte, 512)
	for time.Now().Before(son) {
		_, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
		if err != nil {
			time.Sleep(30 * time.Millisecond)
			continue
		}
		cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return nil, err
		}
		for _, c := range cmsgs {
			if c.Header.Level != unix.IPPROTO_IP || c.Header.Type != unix.IP_RECVERR {
				continue
			}
			boy := int(unsafe.Sizeof(unix.SockExtendedErr{}))
			if len(c.Data) < boy+int(unsafe.Sizeof(unix.RawSockaddrInet4{})) {
				continue
			}
			ee := (*unix.SockExtendedErr)(unsafe.Pointer(&c.Data[0]))
			if ee.Origin != unix.SO_EE_ORIGIN_ICMP {
				continue
			}
			sain := (*unix.RawSockaddrInet4)(unsafe.Pointer(&c.Data[boy]))
			return net.IP(append([]byte{}, sain.Addr[:]...)), nil
		}
	}
	return nil, errZamanAsimi
}

// ---------------------------------------------------------------------------
// Yoklayıcı
// ---------------------------------------------------------------------------

type lYoklayici struct {
	arpSem    chan struct{}
	tcpUcusta sync.Map
	sonTCP    time.Time
	arpYetki  bool
}

func (y *lYoklayici) arp(a lArayuz, kaynak, gw net.IP, zaman time.Duration) arpSonucu {
	onb, _ := arpOnbellek(gw, a.Ad)
	if !y.arpYetki {
		return arpSonucu{sonuc: "yok_destek", onbellek: onb}
	}
	select {
	case y.arpSem <- struct{}{}:
	default:
		return arpSonucu{sonuc: "atlandi", onbellek: onb}
	}
	defer func() { <-y.arpSem }()
	bas := time.Now()
	mac, err := arpIstegi(a, kaynak, gw, zaman)
	r := arpSonucu{onbellek: onb, sureMs: time.Since(bas).Milliseconds()}
	switch {
	case err == nil:
		r.sonuc, r.oui = "cevap", ouiYaz(mac)
	case errors.Is(err, errZamanAsimi):
		r.sonuc = "zaman_asimi"
	case errors.Is(err, unix.ENETDOWN) || errors.Is(err, unix.ENXIO) || errors.Is(err, unix.ENODEV):
		r.sonuc = "yok"
	default:
		var e syscall.Errno
		if errors.As(err, &e) {
			r.sonuc = fmt.Sprintf("hata:%d", int(e))
		} else {
			r.sonuc = "hata"
		}
	}
	return r
}

func (y *lYoklayici) tcp(gw net.IP, port int, zaman time.Duration) string {
	v, _ := y.tcpUcusta.LoadOrStore(port, new(sync.Mutex))
	mu := v.(*sync.Mutex)
	if !mu.TryLock() {
		return "atlandi"
	}
	defer mu.Unlock()
	c, err := net.DialTimeout("tcp4", net.JoinHostPort(gw.String(), fmt.Sprint(port)), zaman)
	if err == nil {
		c.Close()
		return "acik"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "reddedildi"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "zaman_asimi"
	}
	var e syscall.Errno
	if errors.As(err, &e) {
		return fmt.Sprintf("hata:%d", int(e))
	}
	return "hata"
}

func (y *lYoklayici) tcpTuru(gw net.IP, p btParametreler) map[int]string {
	zaman := time.Duration(p.TCPZamanAsimiMs) * time.Millisecond
	var wg sync.WaitGroup
	var mu sync.Mutex
	tcp := map[int]string{}
	for _, port := range p.TCPPortlari {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			s := y.tcp(gw, port, zaman)
			mu.Lock()
			tcp[port] = s
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	return tcp
}

// ---------------------------------------------------------------------------
// Gözlemci
// ---------------------------------------------------------------------------

type linuxGozlemci struct {
	y      lYoklayici
	hedef  net.IP
	upnp   *upnpIGD
	testAd string
	gw     net.IP
	kaynak net.IP
}

func ilkIPv4(a lArayuz) net.IP {
	if len(a.IPv4) == 0 {
		return nil
	}
	return net.ParseIP(strings.SplitN(a.IPv4[0], "/", 2)[0]).To4()
}

func arayuzAdla(m map[int]lArayuz, ad string) (lArayuz, bool) {
	for _, a := range m {
		if a.Ad == ad {
			return a, true
		}
	}
	return lArayuz{}, false
}

func (g *linuxGozlemci) OnKontrol(ctx context.Context, p btParametreler, hedefStr string) (btOnKontrol, error) {
	g.hedef = net.ParseIP(hedefStr).To4()
	g.y.arpSem = make(chan struct{}, azamiEsZamanliARPLinux)
	g.y.arpYetki = arpYetkisiVar()
	o := btOnKontrol{Bilgi: map[string]any{}, Engeller: []string{}}
	engel := func(k string) {
		for _, e := range o.Engeller {
			if e == k {
				return
			}
		}
		o.Engeller = append(o.Engeller, k)
	}
	arayuzler, err := arayuzleriOkuLinux()
	if err != nil {
		return o, fmt.Errorf("arayüzler okunamadı: %v", err)
	}
	yol, bulundu := enIyiYolLinux(g.hedef)
	if !bulundu {
		o.Bilgi["yol"] = map[string]any{"hedef": hedefStr, "bulundu": false}
		engel("VARSAYILAN_YOL_YOK")
	}
	ta, taVar := arayuzAdla(arayuzler, yol.Arayuz)
	if bulundu {
		o.Bilgi["yol"] = map[string]any{"hedef": hedefStr, "bulundu": true, "arayuz_no": ta.No, "arayuz_adi": yol.Arayuz,
			"ag_gecidi": yol.AgGecidi.String(), "metrik": yol.Metrik}
	}
	g.testAd = yol.Arayuz
	if bulundu && !yol.AgGecidi.IsUnspecified() {
		g.gw = yol.AgGecidi
	} else if bulundu {
		engel("AG_GECIDI_YOK")
	}
	if taVar {
		g.kaynak = ilkIPv4(ta)
		if g.kaynak == nil {
			engel("IPV4_YOK")
		}
	}

	upnpC := make(chan *upnpIGD, 1)
	go func() {
		if !p.UPnP || g.kaynak == nil {
			upnpC <- nil
			return
		}
		uc, iptal := context.WithTimeout(ctx, 2500*time.Millisecond)
		defer iptal()
		igd, err := upnpBul(uc, g.kaynak.String(), 2*time.Second)
		if err != nil {
			igd = nil
		}
		upnpC <- igd
	}()

	if taVar {
		o.Bilgi["test_arayuzu"] = map[string]any{"no": ta.No, "ad": ta.Ad, "aciklama": ta.Surucu, "tur": ta.tur(),
			"arphrd": ta.Tip, "hiz_bps": int64(ta.HizMbps) * 1000000, "durum": map[bool]string{true: "up", false: "down"}[ta.up()],
			"operstate": ta.Durum, "carrier": ta.Carrier, "ipv4": ta.IPv4, "dhcp": nil, "dhcp_kira_suresi_s": nil}
		switch ta.tur() {
		case "tunel":
			engel("VPN_VARSAYILAN_YOLDA")
		case "sanal":
			engel("SANAL_ARAYUZ")
		}
		o.KartAcik = ta.up()
	}

	// Aktif arayüzler ve varsayılan yollar
	varsayilan := map[string]int{}
	for _, y := range yollariOku() {
		if y.Maske == 0 {
			if m, ok := varsayilan[y.Arayuz]; !ok || y.Metrik < m {
				varsayilan[y.Arayuz] = y.Metrik
			}
		}
	}
	// v2.1.0: IPv4 almış (APIPA hariç) ve bağlı TÜM fiziksel bağlantılar sayılır (Windows ile aynı kural).
	aktifler, digerler := []any{}, []any{}
	vpnler := []string{}
	for _, a := range arayuzler {
		ipler := apipasiz(a.IPv4)
		if !(a.up() || (a.Carrier == 1 && len(ipler) > 0)) {
			continue
		}
		met, vy := varsayilan[a.Ad]
		kayit := map[string]any{"no": a.No, "ad": a.Ad, "tur": a.tur(), "aciklama": a.Ad + " (" + a.Surucu + ")", "ipv4": ipler,
			"varsayilan_yol": vy, "metrik": met, "operstate": a.Durum}
		if fizikselTur(a.tur()) && len(ipler) > 0 {
			aktifler = append(aktifler, kayit)
			continue
		}
		if a.vpnMi() && a.up() {
			vpnler = append(vpnler, a.Ad)
		}
		digerler = append(digerler, kayit)
	}
	if len(aktifler) > 1 {
		engel("COKLU_AKTIF_ARAYUZ")
	}
	o.Bilgi["fiziksel_arayuz_sayisi"] = len(aktifler)
	o.Bilgi["diger_arayuzler"] = digerler
	if len(vpnler) > 0 {
		engel("VPN_ARAYUZU_VAR")
	}
	o.Bilgi["aktif_arayuzler"] = aktifler
	o.Bilgi["vpn"] = map[string]any{"var": len(vpnler) > 0, "varsayilan_yol_vpn": taVar && ta.vpnMi(), "arayuzler": vpnler}

	ipuclari := []string{}
	if g.gw != nil && hotspotAgGecitleri[g.gw.String()] {
		ipuclari = append(ipuclari, "AG_GECIDI_BILINEN_HOTSPOT_ADRESI")
	}
	if taVar && (ta.Surucu == "rndis_host" || ta.Surucu == "cdc_ether" || ta.Surucu == "ipheth" || ta.Surucu == "cdc_ncm") {
		ipuclari = append(ipuclari, "ARAYUZ_RNDIS")
	}
	if taVar && ta.tur() == "mobil" {
		ipuclari = append(ipuclari, "ARAYUZ_WWAN")
	}

	// Yoklamalar
	arpBilgi := map[string]any{"deneme": 0, "cevap": 0, "sureler_ms": []int64{}, "onbellek_durumu_once": "", "yetki": g.y.arpYetki}
	tcpOzet := map[string]map[string]int{}
	oui := ""
	arpCevap := 0
	if g.gw != nil && taVar {
		onb, onbOUI := arpOnbellek(g.gw, ta.Ad)
		arpBilgi["onbellek_durumu_once"], oui = onb, onbOUI
		var sureler []int64
		for i := 0; i < p.OnKontrolYoklamaSayisi; i++ {
			r := g.y.arp(ta, g.kaynak, g.gw, time.Duration(p.YoklamaZamanAsimiMs)*time.Millisecond)
			if r.sonuc != "yok_destek" {
				arpBilgi["deneme"] = arpBilgi["deneme"].(int) + 1
			}
			if r.sonuc == "cevap" {
				arpCevap++
				sureler = append(sureler, r.sureMs)
				oui = r.oui
			}
			for port, s := range g.y.tcpTuru(g.gw, p) {
				k := fmt.Sprint(port)
				if tcpOzet[k] == nil {
					tcpOzet[k] = map[string]int{"deneme": 0}
				}
				tcpOzet[k]["deneme"]++
				tcpOzet[k][s]++
			}
			select {
			case <-ctx.Done():
				return o, ctx.Err()
			case <-time.After(time.Duration(p.YoklamaAraligiMs) * time.Millisecond):
			}
		}
		if sureler != nil {
			arpBilgi["sureler_ms"] = sureler
		}
	}
	arpBilgi["cevap"] = arpCevap
	tcpCanli := false
	for _, s := range tcpOzet {
		tcpCanli = tcpCanli || s["acik"] > 0 || s["reddedildi"] > 0
	}
	if !g.y.arpYetki {
		engel("ARP_DESTEKLENMIYOR")
		arpBilgi["neden"] = "cap_net_raw_yok"
	}
	if g.gw != nil && arpCevap == 0 && !tcpCanli {
		engel("AG_GECIDI_ERISILEMEZ")
	}
	o.AgVar = arpCevap > 0 || tcpCanli
	agBilgi := map[string]any{"ipv4": nil, "oui": oui, "ozel_aralik": false, "yerel_yonetimli_mac": ouiYerelYonetimli(oui)}
	if g.gw != nil {
		agBilgi["ipv4"], agBilgi["ozel_aralik"] = g.gw.String(), ozelAralik(g.gw)
	}
	if ouiYerelYonetimli(oui) {
		ipuclari = append(ipuclari, "AG_GECIDI_RASTGELE_MAC")
	}
	if len(ipuclari) > 0 {
		engel("HOTSPOT_IPUCU")
	}
	o.Bilgi["hotspot_ipuclari"] = ipuclari
	o.Bilgi["ag_gecidi"] = agBilgi
	o.Bilgi["arp"] = arpBilgi
	o.Bilgi["tcp"] = tcpOzet

	iy := map[string]any{"ipucu": "bilinmiyor", "ikinci_atlama": nil, "ikinci_atlama_ozel": nil}
	kanit := []string{}
	if a, err := ttl2Linux(g.hedef, 1500*time.Millisecond); err == nil {
		iy["ikinci_atlama"], iy["ikinci_atlama_ozel"], iy["ipucu"] = a.String(), ozelAralik(a), "yok"
		if ozelAralik(a) {
			kanit = append(kanit, "ikinci_atlama_ozel")
		}
	} else {
		iy["ttl2_hata"] = err.Error()
	}
	if igd := <-upnpC; igd != nil {
		uc, iptal := context.WithTimeout(ctx, 2*time.Second)
		v, err := igd.oku(uc)
		iptal()
		if err == nil {
			g.upnp = igd
			v["durum"] = "var"
			o.Bilgi["upnp"] = v
			if ds, _ := v["dis_ip"].(string); ds != "" && ozelAralik(net.ParseIP(ds)) {
				kanit = append(kanit, "upnp_dis_ip_ozel")
			}
		} else {
			o.Bilgi["upnp"] = map[string]any{"durum": "yok", "hata": "okunamadi"}
		}
	} else {
		o.Bilgi["upnp"] = map[string]any{"durum": "yok"}
	}
	if len(kanit) > 0 {
		iy["ipucu"], iy["kanit"] = "olasi", kanit
	}
	o.Bilgi["ikinci_yonlendirici"] = iy
	return o, nil
}

const azamiEsZamanliARPLinux = 8

func (g *linuxGozlemci) Izle(ctx context.Context, p btParametreler, cikis chan<- btGozlem) {
	yolla := func(gl btGozlem) bool {
		select {
		case cikis <- gl:
			return true
		case <-ctx.Done():
			return false
		}
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("💥 [BAĞLANTI] Linux gözlemcisi çöktü: %v", r)
			yolla(btGozlem{Tur: "ic_hata", Veri: map[string]any{"mesaj": fmt.Sprint(r)}})
		}
	}()
	onceki, _ := arayuzleriOkuLinux()
	oncekiYol, _ := enIyiYolLinux(g.hedef)
	sonuclar := make(chan btGozlem, 16)
	yoklamaT := time.NewTicker(time.Duration(p.YoklamaAraligiMs) * time.Millisecond)
	defer yoklamaT.Stop()
	var upnpC <-chan time.Time
	if g.upnp != nil && p.UPnP {
		upnpT := time.NewTicker(time.Duration(p.UPnPAraligiMs) * time.Millisecond)
		defer upnpT.Stop()
		upnpC = upnpT.C
	}

	farklar := func() bool {
		simdi, err := arayuzleriOkuLinux()
		if err != nil {
			return true
		}
		eski, eskiVar := arayuzAdla(onceki, g.testAd)
		yeni, yeniVar := arayuzAdla(simdi, g.testAd)
		eskiUp, yeniUp := eskiVar && eski.up(), yeniVar && yeni.up()
		if eskiUp != yeniUp {
			if !yeniUp {
				neden := "bilinmiyor"
				switch {
				case !yeniVar || !yeni.Yonetim:
					neden = "devre_disi"
				case yeni.Carrier == 0 || yeni.Durum == "down" || yeni.Durum == "lowerlayerdown" || yeni.Durum == "dormant":
					neden = "medya_baglantisi_yok"
				}
				if !yolla(btGozlem{Tur: "kart", KartAcik: false, Neden: neden, Veri: map[string]any{"arayuz_no": eski.No, "tur": eski.tur(), "operstate": yeni.Durum}}) {
					return false
				}
			} else if !yolla(btGozlem{Tur: "kart", KartAcik: true, Veri: map[string]any{"arayuz_no": yeni.No}}) {
				return false
			}
		}
		ea, ya := map[string]bool{}, map[string]bool{}
		for _, a := range eski.IPv4 {
			ea[a] = true
		}
		for _, a := range yeni.IPv4 {
			ya[a] = true
		}
		for a := range ea {
			if !ya[a] && !yolla(btGozlem{Tur: "ipv4", Veri: map[string]any{"var": false, "adres": a}}) {
				return false
			}
		}
		for a := range ya {
			if !ea[a] && !yolla(btGozlem{Tur: "ipv4", Veri: map[string]any{"var": true, "adres": a}}) {
				return false
			}
		}
		if yeniVar && len(yeni.IPv4) > 0 {
			g.kaynak = ilkIPv4(yeni)
		}
		for no, y := range simdi {
			if y.Ad == g.testAd {
				continue
			}
			e, ev := onceki[no]
			if (ev && e.up()) == y.up() {
				continue
			}
			if y.vpnMi() {
				if !yolla(btGozlem{Tur: "vpn", Veri: map[string]any{"var": y.up(), "aciklama": y.Ad}}) {
					return false
				}
			} else if !yolla(btGozlem{Tur: "arayuz", Veri: map[string]any{"arayuz_no": no, "tur": y.tur(), "durum": map[bool]string{true: "up", false: "down"}[y.up()]}}) {
				return false
			}
		}
		onceki = simdi
		if y, ok := enIyiYolLinux(g.hedef); ok && (y.Arayuz != oncekiYol.Arayuz || !y.AgGecidi.Equal(oncekiYol.AgGecidi)) {
			eA, _ := arayuzAdla(simdi, oncekiYol.Arayuz)
			yA, _ := arayuzAdla(simdi, y.Arayuz)
			if !yolla(btGozlem{Tur: "yol", Veri: map[string]any{
				"onceki":            map[string]any{"arayuz": oncekiYol.Arayuz, "arayuz_no": eA.No, "tur": eA.tur(), "ag_gecidi": fmt.Sprint(oncekiYol.AgGecidi)},
				"yeni":              map[string]any{"arayuz": y.Arayuz, "arayuz_no": yA.No, "tur": yA.tur(), "ag_gecidi": y.AgGecidi.String()},
				"ag_gecidi_degisti": !y.AgGecidi.Equal(oncekiYol.AgGecidi)}}) {
				return false
			}
			oncekiYol = y
		}
		return true
	}

	for {
		select {
		case <-ctx.Done():
			return
		case gl := <-sonuclar:
			if !yolla(gl) {
				return
			}
		case <-yoklamaT.C:
			if !farklar() {
				return
			}
			if g.gw == nil {
				if !yolla(btGozlem{Tur: "yoklama", ARP: "yok_destek"}) {
					return
				}
				continue
			}
			if time.Since(g.y.sonTCP) >= time.Duration(p.TCPAraligiMs)*time.Millisecond-50*time.Millisecond && len(p.TCPPortlari) > 0 {
				g.y.sonTCP = time.Now()
				go func() {
					tcp := g.y.tcpTuru(g.gw, p)
					select {
					case sonuclar <- btGozlem{Tur: "yoklama", TCP: tcp}:
					case <-ctx.Done():
					}
				}()
			}
			ta, _ := arayuzAdla(onceki, g.testAd)
			kaynak := g.kaynak
			go func() {
				a := g.y.arp(ta, kaynak, g.gw, time.Duration(p.YoklamaZamanAsimiMs)*time.Millisecond)
				if a.oui != "" {
					select {
					case sonuclar <- btGozlem{Tur: "mac", Veri: map[string]any{"oui": a.oui}}:
					case <-ctx.Done():
						return
					}
				}
				select {
				case sonuclar <- btGozlem{Tur: "yoklama", ARP: a.sonuc, Onbellek: a.onbellek}:
				case <-ctx.Done():
				}
			}()
		case <-upnpC:
			uc, iptal := context.WithTimeout(ctx, 2*time.Second)
			v, err := g.upnp.oku(uc)
			iptal()
			if err == nil && !yolla(btGozlem{Tur: "upnp", Veri: v}) {
				return
			}
		}
	}
}
