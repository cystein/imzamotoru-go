//go:build windows

package main

// Windows ağ gözlemcisi (PROTOKOL.md §4–§5). Yönetici hakkı GEREKTİRMEZ: kullanılan tüm iphlpapi/
// icmp/powrprof çağrıları standart kullanıcıyla çalışır.
//
// SAHADA DOĞRULANMADI (2026-11-19): bu dosya Linux'ta çapraz derlendi, gerçek Windows'ta henüz
// çalıştırılmadı. Özellikle SendARP'ın önbellekten cevap verip vermediği (test matrisi satır 11)
// ölçülmeden "taze ARP" iddia edilmez; her ARP sonucunun yanında çağrı öncesi komşu tablosu durumu
// raporlanır ve ağ geçidine ayrıca TCP yoklaması yapılır.

/*
#cgo LDFLAGS: -liphlpapi -lws2_32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <netioapi.h>
#include <stdlib.h>
#include <string.h>

// En iyi IPv4 yolu (hedef ağ bayt sırasında).
static DWORD bt_en_iyi_yol(DWORD hedef, DWORD *ifidx, DWORD *nexthop, DWORD *metrik) {
	MIB_IPFORWARDROW r;
	DWORD e = GetBestRoute(hedef, 0, &r);
	if (e != NO_ERROR) return e;
	*ifidx = r.dwForwardIfIndex; *nexthop = r.dwForwardNextHop; *metrik = r.dwForwardMetric1;
	return NO_ERROR;
}

// ARP isteği. SendARP önbellekte geçerli kayıt varsa istek göndermeden dönebilir — çağıran,
// öncesindeki komşu durumunu ayrıca okur ve raporlar.
static DWORD bt_send_arp(DWORD hedef, unsigned char *mac) {
	ULONG buf[2] = {0, 0};
	ULONG uzunluk = 6;
	DWORD e = SendARP(hedef, 0, buf, &uzunluk);
	if (e == NO_ERROR && uzunluk >= 6) memcpy(mac, buf, 6);
	return e;
}

// Komşu (ARP) tablosu durumu: NL_NEIGHBOR_STATE (0 unreachable, 1 incomplete, 2 probe, 3 delay,
// 4 stale, 5 reachable, 6 permanent); kayıt yoksa -1.
static int bt_komsu_durumu(DWORD ifidx, DWORD ip, unsigned char *mac) {
	MIB_IPNET_ROW2 r;
	memset(&r, 0, sizeof r);
	r.Address.si_family = AF_INET;
	r.Address.Ipv4.sin_addr.S_un.S_addr = ip;
	r.InterfaceIndex = ifidx;
	if (GetIpNetEntry2(&r) != NO_ERROR) return -1;
	if (r.PhysicalAddressLength >= 6) memcpy(mac, r.PhysicalAddress, 6);
	return (int)r.State;
}

// TTL=2 ICMP yankısı: ikinci atlamanın adresi (yalnız bilgi amaçlı, PROTOKOL §4.4).
static DWORD bt_ttl2(DWORD hedef, DWORD *atlama, DWORD zaman_ms) {
	HANDLE h = IcmpCreateFile();
	if (h == INVALID_HANDLE_VALUE) return GetLastError();
	char veri[8] = "kolitkp";
	IP_OPTION_INFORMATION o;
	memset(&o, 0, sizeof o);
	o.Ttl = 2;
	DWORD boy = sizeof(ICMP_ECHO_REPLY) + sizeof(veri) + 8 + 128;
	void *yanit = calloc(1, boy);
	DWORD n = IcmpSendEcho(h, hedef, veri, sizeof(veri), &o, yanit, boy, zaman_ms);
	DWORD sonuc = n > 0 ? 0 : GetLastError();
	PICMP_ECHO_REPLY r = (PICMP_ECHO_REPLY)yanit;
	if (r->Status == IP_TTL_EXPIRED_TRANSIT || r->Status == IP_SUCCESS) { *atlama = r->Address; sonuc = 0; }
	free(yanit);
	IcmpCloseHandle(h);
	return sonuc;
}

// DHCP kirası (GetAdaptersInfo; IPv4).
static int bt_dhcp(DWORD ifidx, int *etkin, long long *alinma, long long *bitis) {
	ULONG boy = 0;
	GetAdaptersInfo(NULL, &boy);
	if (boy == 0) return -1;
	PIP_ADAPTER_INFO a = (PIP_ADAPTER_INFO)malloc(boy);
	if (GetAdaptersInfo(a, &boy) != NO_ERROR) { free(a); return -1; }
	for (PIP_ADAPTER_INFO p = a; p; p = p->Next) {
		if (p->Index == ifidx) {
			*etkin = (int)p->DhcpEnabled; *alinma = (long long)p->LeaseObtained; *bitis = (long long)p->LeaseExpires;
			free(a);
			return 0;
		}
	}
	free(a);
	return -2;
}
*/
import "C"

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func gercekGozlemciFabrikasi() func(t *btTest) btGozlemci {
	return func(t *btTest) btGozlemci { return &winGozlemci{} }
}

// ---------------------------------------------------------------------------
// Arayüz anlık görüntüsü
// ---------------------------------------------------------------------------

type wArayuz struct {
	No       uint32
	Ad       string
	Aciklama string
	IfType   uint32
	Oper     uint32
	Admin    uint32
	Medya    uint32 // MediaConnectState: 0 bilinmiyor, 1 bağlı, 2 bağlı değil
	HizBps   uint64
	IPv4     []string
	AgGecidi string
	Tunnel   uint32
}

func (a wArayuz) up() bool { return a.Oper == windows.IfOperStatusUp }

var vpnKelimeleri = []string{"tap-", "tap ", "tun ", "wintun", "wireguard", "vpn", "openvpn", "fortinet", "anyconnect",
	"cisco", "zerotier", "tailscale", "nordlynx", "proton", "pangp", "globalprotect", "juniper", "sonicwall", "check point",
	"checkpoint", "l2tp", "pptp", "sstp", "ikev2", "softether", "hamachi", "radmin"}
var tunelHaric = []string{"teredo", "ip-https", "6to4", "isatap", "loopback"}
var sanalKelimeleri = []string{"hyper-v", "vethernet", "virtualbox", "vmware", "virtual adapter", "docker", "wsl"}

func icerir(s string, liste []string) bool {
	s = strings.ToLower(s)
	for _, k := range liste {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func (a wArayuz) vpnMi() bool {
	if icerir(a.Aciklama, tunelHaric) {
		return false
	}
	return a.IfType == 23 || a.IfType == 131 || icerir(a.Aciklama, vpnKelimeleri) || icerir(a.Ad, vpnKelimeleri)
}

func (a wArayuz) tur() string {
	switch {
	case a.vpnMi():
		return "tunel"
	case icerir(a.Aciklama, sanalKelimeleri) || icerir(a.Ad, sanalKelimeleri) || a.IfType == 53:
		return "sanal"
	case a.IfType == 71:
		return "wifi"
	case a.IfType == 243 || a.IfType == 244:
		return "mobil"
	case a.IfType == 6:
		return "ethernet"
	}
	return "diger"
}

func utf16Dize(p *uint16) string {
	if p == nil {
		return ""
	}
	return windows.UTF16PtrToString(p)
}

// arayuzleriOku: tüm IPv4 arayüzleri (GetAdaptersAddresses) + durum ayrıntısı (GetIfEntry2Ex).
func arayuzleriOku() (map[uint32]wArayuz, error) {
	boy := uint32(15000)
	var buf []byte
	for i := 0; i < 3; i++ {
		buf = make([]byte, boy)
		err := windows.GetAdaptersAddresses(windows.AF_INET, windows.GAA_FLAG_INCLUDE_GATEWAYS|windows.GAA_FLAG_SKIP_ANYCAST|
			windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &boy)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return nil, err
		}
		if i == 2 {
			return nil, err
		}
	}
	sonuc := map[uint32]wArayuz{}
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		if a.IfType == 24 { // loopback
			continue
		}
		w := wArayuz{No: a.IfIndex, Ad: utf16Dize(a.FriendlyName), Aciklama: utf16Dize(a.Description), IfType: a.IfType,
			Oper: a.OperStatus, HizBps: a.TransmitLinkSpeed, Tunnel: a.TunnelType}
		for u := a.FirstUnicastAddress; u != nil; u = u.Next {
			if ip := u.Address.IP(); ip != nil && ip.To4() != nil {
				w.IPv4 = append(w.IPv4, fmt.Sprintf("%s/%d", ip.To4(), u.OnLinkPrefixLength))
			}
		}
		for g := a.FirstGatewayAddress; g != nil; g = g.Next {
			if ip := g.Address.IP(); ip != nil && ip.To4() != nil && w.AgGecidi == "" {
				w.AgGecidi = ip.To4().String()
			}
		}
		row := windows.MibIfRow2{InterfaceIndex: a.IfIndex}
		if windows.GetIfEntry2Ex(windows.MibIfEntryNormalWithoutStatistics, &row) == nil {
			w.Admin, w.Medya = row.AdminStatus, row.MediaConnectState
		}
		sonuc[w.No] = w
	}
	return sonuc, nil
}

// varsayilanYollar: ifIndex → varsayılan yol (0.0.0.0/0) metriği.
func varsayilanYollar() map[uint32]uint32 {
	var tablo *windows.MibIpForwardTable2
	m := map[uint32]uint32{}
	if windows.GetIpForwardTable2(windows.AF_INET, &tablo) != nil {
		return m
	}
	defer windows.FreeMibTable(unsafe.Pointer(tablo))
	for _, r := range tablo.Rows() {
		if r.DestinationPrefix.PrefixLength == 0 {
			if eski, ok := m[r.InterfaceIndex]; !ok || r.Metric < eski {
				m[r.InterfaceIndex] = r.Metric
			}
		}
	}
	return m
}

// ---------------------------------------------------------------------------
// Yardımcılar
// ---------------------------------------------------------------------------

func ipv4Sayi(ip net.IP) C.DWORD { return C.DWORD(binary.LittleEndian.Uint32(ip.To4())) } // ağ bayt sırası, bellekte
func sayiIPv4(v C.DWORD) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return net.IP(b).String()
}

type wYol struct {
	Arayuz   uint32
	AgGecidi string
	Metrik   uint32
}

func enIyiYol(hedef net.IP) (wYol, error) {
	var ifidx, nh, met C.DWORD
	if e := C.bt_en_iyi_yol(ipv4Sayi(hedef), &ifidx, &nh, &met); e != 0 {
		return wYol{}, syscall.Errno(e)
	}
	return wYol{Arayuz: uint32(ifidx), AgGecidi: sayiIPv4(nh), Metrik: uint32(met)}, nil
}

var komsuDurumAdi = map[int]string{-1: "yok", 0: "unreachable", 1: "incomplete", 2: "probe", 3: "delay", 4: "stale", 5: "reachable", 6: "permanent"}

func komsuDurumu(ifidx uint32, ip net.IP) (string, string) {
	mac := make([]byte, 6)
	d := int(C.bt_komsu_durumu(C.DWORD(ifidx), ipv4Sayi(ip), (*C.uchar)(unsafe.Pointer(&mac[0]))))
	ad, ok := komsuDurumAdi[d]
	if !ok {
		ad = fmt.Sprintf("durum_%d", d)
	}
	return ad, ouiYaz(mac)
}

func ouiYaz(mac []byte) string {
	if len(mac) < 3 || (mac[0] == 0 && mac[1] == 0 && mac[2] == 0) {
		return ""
	}
	return fmt.Sprintf("%02X:%02X:%02X", mac[0], mac[1], mac[2])
}

func ozelAralik(ip net.IP) bool {
	if ip == nil {
		return false
	}
	_, cgnat, _ := net.ParseCIDR("100.64.0.0/10")
	return ip.IsPrivate() || cgnat.Contains(ip)
}

var hotspotAgGecitleri = map[string]bool{"192.168.43.1": true, "172.20.10.1": true, "192.168.137.1": true, "192.168.42.129": true,
	"192.168.44.1": true, "192.168.49.1": true}

// ---------------------------------------------------------------------------
// Yoklayıcı: ARP + TCP, her biri en çok bir uçuşta; takılan yoklama sonrakini bekletmez.
// ---------------------------------------------------------------------------

// v2.0.1: ARP için aynı anda en çok 8 istek. SendARP cevapsız ağ geçidinde ~3–4 sn takılıyor;
// tek istek sınırıyla (2.0.0) modem kapalıyken ölçüm 4–5 sn'de bire düşüyor, "geri geldi" anı
// ±4 sn kayıyordu (saha raporu 2026-11-19). Her takılı istek bir OS iş parçacığı tutar; 8 makul.
const azamiEsZamanliARP = 8

type yoklayici struct {
	arpSem    chan struct{}
	tcpUcusta sync.Map // port → *atomic.Bool
	sonTCP    time.Time
}

func (y *yoklayici) sem() chan struct{} {
	if y.arpSem == nil {
		y.arpSem = make(chan struct{}, azamiEsZamanliARP)
	}
	return y.arpSem
}

type arpSonucu struct {
	sonuc, onbellek, oui string
	sureMs               int64
}

// arp: zaman aşımı içinde SendARP sonucu; uçuşta bir istek varsa "atlandi".
func (y *yoklayici) arp(ifidx uint32, gw net.IP, zaman time.Duration) arpSonucu {
	onb, _ := komsuDurumu(ifidx, gw)
	select {
	case y.sem() <- struct{}{}:
	default:
		return arpSonucu{sonuc: "atlandi", onbellek: onb}
	}
	c := make(chan arpSonucu, 1)
	go func() {
		defer func() { <-y.sem() }()
		bas := time.Now()
		mac := make([]byte, 6)
		e := C.bt_send_arp(ipv4Sayi(gw), (*C.uchar)(unsafe.Pointer(&mac[0])))
		r := arpSonucu{onbellek: onb, sureMs: time.Since(bas).Milliseconds()}
		switch e {
		case 0:
			r.sonuc, r.oui = "cevap", ouiYaz(mac)
		case 67, 1168, 31: // ERROR_BAD_NET_NAME, ERROR_NOT_FOUND, ERROR_GEN_FAILURE: cevap yok
			r.sonuc = "yok"
		default:
			r.sonuc = fmt.Sprintf("hata:%d", int(e))
		}
		c <- r
	}()
	select {
	case r := <-c:
		return r
	case <-time.After(zaman):
		return arpSonucu{sonuc: "zaman_asimi", onbellek: onb}
	}
}

func (y *yoklayici) tcp(gw net.IP, port int, zaman time.Duration) string {
	v, _ := y.tcpUcusta.LoadOrStore(port, &atomic.Bool{})
	ucus := v.(*atomic.Bool)
	if !ucus.CompareAndSwap(false, true) {
		return "atlandi"
	}
	defer ucus.Store(false)
	c, err := net.DialTimeout("tcp4", net.JoinHostPort(gw.String(), fmt.Sprint(port)), zaman)
	if err == nil {
		c.Close()
		return "acik"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && errno == 10061 { // WSAECONNREFUSED: cihaz canlı, port kapalı
		return "reddedildi"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "zaman_asimi"
	}
	if errors.As(err, &errno) {
		return fmt.Sprintf("hata:%d", int(errno))
	}
	return "hata"
}

// tcpTuru: tüm TCP portlarını eşzamanlı yoklar.
func (y *yoklayici) tcpTuru(gw net.IP, p btParametreler) map[int]string {
	tcpZaman := time.Duration(p.TCPZamanAsimiMs) * time.Millisecond
	var wg sync.WaitGroup
	var mu sync.Mutex
	tcp := map[int]string{}
	for _, port := range p.TCPPortlari {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			s := y.tcp(gw, port, tcpZaman)
			mu.Lock()
			tcp[port] = s
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	return tcp
}

// tur: ön kontrol için bir yoklama turu (ARP + tüm TCP portları, eşzamanlı).
func (y *yoklayici) tur(ifidx uint32, gw net.IP, p btParametreler) (arpSonucu, map[int]string) {
	zaman := time.Duration(p.YoklamaZamanAsimiMs) * time.Millisecond
	tcpZaman := time.Duration(p.TCPZamanAsimiMs) * time.Millisecond
	var wg sync.WaitGroup
	var mu sync.Mutex
	tcp := map[int]string{}
	for _, port := range p.TCPPortlari {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			s := y.tcp(gw, port, tcpZaman)
			mu.Lock()
			tcp[port] = s
			mu.Unlock()
		}(port)
	}
	a := y.arp(ifidx, gw, zaman)
	wg.Wait()
	return a, tcp
}

// ---------------------------------------------------------------------------
// Gözlemci
// ---------------------------------------------------------------------------

type winGozlemci struct {
	y      yoklayici
	hedef  net.IP
	upnp   *upnpIGD
	testNo uint32 // test arayüzü
	gw     string
}

func (g *winGozlemci) OnKontrol(ctx context.Context, p btParametreler, hedefStr string) (btOnKontrol, error) {
	g.hedef = net.ParseIP(hedefStr).To4()
	o := btOnKontrol{Bilgi: map[string]any{}, Engeller: []string{}}
	engel := func(k string) {
		for _, e := range o.Engeller {
			if e == k {
				return
			}
		}
		o.Engeller = append(o.Engeller, k)
	}

	// UPnP aramasını paralel başlat (en çok 2 sn).
	upnpC := make(chan *upnpIGD, 1)

	yol, yolHata := enIyiYol(g.hedef)
	arayuzler, err := arayuzleriOku()
	if err != nil {
		return o, fmt.Errorf("arayüzler okunamadı: %v", err)
	}
	vy := varsayilanYollar()
	if yolHata != nil {
		o.Bilgi["yol"] = map[string]any{"hedef": hedefStr, "bulundu": false, "hata": yolHata.Error()}
		engel("VARSAYILAN_YOL_YOK")
	} else {
		o.Bilgi["yol"] = map[string]any{"hedef": hedefStr, "bulundu": true, "arayuz_no": yol.Arayuz, "ag_gecidi": yol.AgGecidi, "metrik": yol.Metrik}
	}
	ta, taVar := arayuzler[yol.Arayuz]
	g.testNo = yol.Arayuz
	gwIP := net.ParseIP(yol.AgGecidi).To4()
	if gwIP == nil || gwIP.IsUnspecified() {
		gwIP = nil
		if yolHata == nil {
			engel("AG_GECIDI_YOK")
		}
	}
	if gwIP != nil {
		g.gw = gwIP.String()
	}
	yerelIP := ""
	if taVar {
		if len(ta.IPv4) > 0 {
			yerelIP = strings.SplitN(ta.IPv4[0], "/", 2)[0]
		} else {
			engel("IPV4_YOK")
		}
	}
	go func() {
		if !p.UPnP || yerelIP == "" {
			upnpC <- nil
			return
		}
		uc, iptal := context.WithTimeout(ctx, 2500*time.Millisecond)
		defer iptal()
		igd, err := upnpBul(uc, yerelIP, 2*time.Second)
		if err != nil {
			upnpC <- nil
			return
		}
		upnpC <- igd
	}()

	// Test arayüzü
	if taVar {
		ti := map[string]any{"no": ta.No, "ad": ta.Ad, "aciklama": ta.Aciklama, "tur": ta.tur(), "if_type": ta.IfType,
			"hiz_bps": ta.HizBps, "durum": map[bool]string{true: "up", false: "down"}[ta.up()], "ipv4": ta.IPv4,
			"medya_baglanti": ta.Medya, "tunnel_type": ta.Tunnel}
		var etkin C.int
		var alinma, bitis C.longlong
		if C.bt_dhcp(C.DWORD(ta.No), &etkin, &alinma, &bitis) == 0 {
			ti["dhcp"] = etkin != 0
			if etkin != 0 && bitis > alinma && alinma > 0 {
				ti["dhcp_kira_suresi_s"] = int64(bitis - alinma)
				ti["dhcp_kira_baslangic"] = time.Unix(int64(alinma), 0).UTC().Format(time.RFC3339)
				ti["dhcp_kira_bitis"] = time.Unix(int64(bitis), 0).UTC().Format(time.RFC3339)
			} else {
				ti["dhcp_kira_suresi_s"] = nil
			}
		}
		o.Bilgi["test_arayuzu"] = ti
		switch ta.tur() {
		case "tunel":
			engel("VPN_VARSAYILAN_YOLDA")
		case "sanal":
			engel("SANAL_ARAYUZ")
		}
		o.KartAcik = ta.up()
	}

	// Aktif arayüzler, VPN, çoklu kart
	var aktifler []any
	var vpnler []string
	varsayilanli := 0
	for _, a := range arayuzler {
		if !a.up() {
			continue
		}
		met, vyVar := vy[a.No]
		if a.vpnMi() {
			vpnler = append(vpnler, a.Aciklama)
		}
		if a.AgGecidi == "" && !vyVar {
			continue
		}
		if vyVar && !a.vpnMi() {
			varsayilanli++
		}
		aktifler = append(aktifler, map[string]any{"no": a.No, "tur": a.tur(), "aciklama": a.Aciklama, "ag_gecidi": a.AgGecidi,
			"varsayilan_yol": vyVar, "metrik": met})
	}
	if varsayilanli > 1 {
		engel("COKLU_AKTIF_ARAYUZ")
	}
	if vpnler == nil {
		vpnler = []string{}
	}
	if len(vpnler) > 0 {
		engel("VPN_ARAYUZU_VAR")
	}
	o.Bilgi["aktif_arayuzler"] = aktifler
	o.Bilgi["vpn"] = map[string]any{"var": len(vpnler) > 0, "varsayilan_yol_vpn": taVar && ta.vpnMi(), "arayuzler": vpnler}

	// Hotspot ipuçları
	ipuclari := []string{}
	if gwIP != nil && hotspotAgGecitleri[gwIP.String()] {
		ipuclari = append(ipuclari, "AG_GECIDI_BILINEN_HOTSPOT_ADRESI")
	}
	if taVar && icerir(ta.Aciklama, []string{"remote ndis", "rndis", "apple mobile device", "iphone"}) {
		ipuclari = append(ipuclari, "ARAYUZ_RNDIS")
	}
	if taVar && ta.tur() == "mobil" {
		ipuclari = append(ipuclari, "ARAYUZ_WWAN")
	}

	// Ağ geçidi yoklamaları (ARP + TCP)
	arpDeneme, arpCevap, tcpOzet := 0, 0, map[string]map[string]int{}
	var sureler []int64
	onbOnce, oui := "", ""
	if gwIP != nil && taVar {
		onbOnce, oui = komsuDurumu(ta.No, gwIP)
		for i := 0; i < p.OnKontrolYoklamaSayisi; i++ {
			a, tcp := g.y.tur(ta.No, gwIP, p)
			arpDeneme++
			if a.sonuc == "cevap" {
				arpCevap++
				sureler = append(sureler, a.sureMs)
				if a.oui != "" {
					oui = a.oui
				}
			}
			for port, s := range tcp {
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
	}
	tcpCanli := false
	for _, s := range tcpOzet {
		tcpCanli = tcpCanli || s["acik"] > 0 || s["reddedildi"] > 0
	}
	if gwIP != nil && arpCevap == 0 && !tcpCanli {
		engel("AG_GECIDI_ERISILEMEZ")
	}
	if taVar && (ta.IfType == 23 || ta.IfType == 243 || ta.IfType == 244) {
		engel("ARP_DESTEKLENMIYOR")
	}
	o.AgVar = arpCevap > 0 || tcpCanli
	ouiBilgi := map[string]any{"ipv4": nil, "oui": oui, "ozel_aralik": false, "yerel_yonetimli_mac": false}
	if gwIP != nil {
		ouiBilgi["ipv4"], ouiBilgi["ozel_aralik"] = gwIP.String(), ozelAralik(gwIP)
		if len(oui) >= 2 {
			var ilk byte
			fmt.Sscanf(oui[:2], "%02X", &ilk)
			ouiBilgi["yerel_yonetimli_mac"] = ilk&0x02 != 0 // telefonlar çoğu zaman rastgele MAC kullanır
			if ilk&0x02 != 0 {
				ipuclari = append(ipuclari, "AG_GECIDI_RASTGELE_MAC")
			}
		}
	}
	o.Bilgi["ag_gecidi"] = ouiBilgi
	o.Bilgi["arp"] = map[string]any{"deneme": arpDeneme, "cevap": arpCevap, "sureler_ms": sureler, "onbellek_durumu_once": onbOnce}
	o.Bilgi["tcp"] = tcpOzet
	if len(ipuclari) > 0 {
		engel("HOTSPOT_IPUCU")
	}
	o.Bilgi["hotspot_ipuclari"] = ipuclari

	// İkinci yönlendirici (TTL=2 ICMP + UPnP dış IP)
	iy := map[string]any{"ipucu": "bilinmiyor", "ikinci_atlama": nil, "ikinci_atlama_ozel": nil}
	kanit := []string{}
	var atlama C.DWORD
	if e := C.bt_ttl2(ipv4Sayi(g.hedef), &atlama, 1500); e == 0 && atlama != 0 {
		a := net.ParseIP(sayiIPv4(atlama))
		iy["ikinci_atlama"], iy["ikinci_atlama_ozel"] = a.String(), ozelAralik(a)
		iy["ipucu"] = "yok"
		if ozelAralik(a) {
			kanit = append(kanit, "ikinci_atlama_ozel")
		}
	} else {
		iy["ttl2_hata"] = int(e)
	}
	igd := <-upnpC
	if igd != nil {
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

// Izle: yoklama döngüsü + arayüz/yol farkları + ağ değişikliği ve güç bildirimleri.
func (g *winGozlemci) Izle(ctx context.Context, p btParametreler, cikis chan<- btGozlem) {
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
			log.Printf("💥 [BAĞLANTI] Windows gözlemcisi çöktü: %v", r)
			yolla(btGozlem{Tur: "ic_hata", Veri: map[string]any{"mesaj": fmt.Sprint(r)}})
		}
	}()

	uyandir := make(chan struct{}, 1)
	bildirimleriKaydet(ctx, uyandir, func(tur string) {
		yolla(btGozlem{Tur: "guc", Veri: map[string]any{"tur": tur}})
	})

	onceki, _ := arayuzleriOku()
	oncekiYol, _ := enIyiYol(g.hedef)
	gw := net.ParseIP(g.gw).To4()

	yoklamaT := time.NewTicker(time.Duration(p.YoklamaAraligiMs) * time.Millisecond)
	defer yoklamaT.Stop()
	var upnpC <-chan time.Time
	if g.upnp != nil && p.UPnP {
		upnpT := time.NewTicker(time.Duration(p.UPnPAraligiMs) * time.Millisecond)
		defer upnpT.Stop()
		upnpC = upnpT.C
	}
	sonuclar := make(chan btGozlem, 8)

	farklariBildir := func() bool {
		simdi, err := arayuzleriOku()
		if err != nil {
			return true
		}
		// Test arayüzü
		eski, eskiVar := onceki[g.testNo]
		yeni, yeniVar := simdi[g.testNo]
		eskiUp := eskiVar && eski.up()
		yeniUp := yeniVar && yeni.up()
		if eskiUp != yeniUp {
			if !yeniUp {
				neden := "bilinmiyor"
				switch {
				case !yeniVar || yeni.Oper == windows.IfOperStatusNotPresent || yeni.Admin == 2:
					neden = "devre_disi"
				case yeni.Medya == 2 || yeni.Oper == windows.IfOperStatusDown || yeni.Oper == windows.IfOperStatusLowerLayerDown:
					neden = "medya_baglantisi_yok"
				}
				if !yolla(btGozlem{Tur: "kart", KartAcik: false, Neden: neden, Veri: map[string]any{"arayuz_no": g.testNo, "tur": eski.tur(), "oper": yeni.Oper}}) {
					return false
				}
			} else if !yolla(btGozlem{Tur: "kart", KartAcik: true, Veri: map[string]any{"arayuz_no": g.testNo}}) {
				return false
			}
		}
		// Test arayüzünün IPv4 adresleri
		eskiAdr, yeniAdr := map[string]bool{}, map[string]bool{}
		for _, a := range eski.IPv4 {
			eskiAdr[a] = true
		}
		for _, a := range yeni.IPv4 {
			yeniAdr[a] = true
		}
		for a := range eskiAdr {
			if !yeniAdr[a] && !yolla(btGozlem{Tur: "ipv4", Veri: map[string]any{"var": false, "adres": a}}) {
				return false
			}
		}
		for a := range yeniAdr {
			if !eskiAdr[a] && !yolla(btGozlem{Tur: "ipv4", Veri: map[string]any{"var": true, "adres": a}}) {
				return false
			}
		}
		// Diğer arayüzler ve VPN
		for no, y := range simdi {
			if no == g.testNo {
				continue
			}
			e, ev := onceki[no]
			if (ev && e.up()) == y.up() {
				continue
			}
			if y.vpnMi() {
				if !yolla(btGozlem{Tur: "vpn", Veri: map[string]any{"var": y.up(), "aciklama": y.Aciklama}}) {
					return false
				}
			} else if !yolla(btGozlem{Tur: "arayuz", Veri: map[string]any{"arayuz_no": no, "tur": y.tur(), "durum": map[bool]string{true: "up", false: "down"}[y.up()]}}) {
				return false
			}
		}
		for no, e := range onceki {
			if _, var_ := simdi[no]; !var_ && no != g.testNo && e.up() {
				if !yolla(btGozlem{Tur: "arayuz", Veri: map[string]any{"arayuz_no": no, "tur": e.tur(), "durum": "kaldirildi"}}) {
					return false
				}
			}
		}
		onceki = simdi
		// Yol
		if y, err := enIyiYol(g.hedef); err == nil && (y.Arayuz != oncekiYol.Arayuz || y.AgGecidi != oncekiYol.AgGecidi) {
			if !yolla(btGozlem{Tur: "yol", Veri: map[string]any{
				"onceki": map[string]any{"arayuz_no": oncekiYol.Arayuz, "ag_gecidi": oncekiYol.AgGecidi},
				"yeni":   map[string]any{"arayuz_no": y.Arayuz, "ag_gecidi": y.AgGecidi}}}) {
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
		case <-uyandir:
			if !farklariBildir() {
				return
			}
		case gl := <-sonuclar:
			if !yolla(gl) {
				return
			}
		case <-yoklamaT.C:
			if !farklariBildir() { // bildirim kaçsa da her turda fark kontrolü
				return
			}
			if gw == nil {
				if !yolla(btGozlem{Tur: "yoklama", ARP: "yok_destek"}) {
					return
				}
				continue
			}
			// v2.0.1: ARP ve TCP ayrı gözlemler — TCP'nin uzun zaman aşımı ARP sonucunu geciktirmesin.
			if time.Since(g.y.sonTCP) >= time.Duration(p.TCPAraligiMs)*time.Millisecond-50*time.Millisecond && len(p.TCPPortlari) > 0 {
				g.y.sonTCP = time.Now()
				go func() {
					tcp := g.y.tcpTuru(gw, p)
					select {
					case sonuclar <- btGozlem{Tur: "yoklama", TCP: tcp}:
					case <-ctx.Done():
					}
				}()
			}
			go func() {
				a := g.y.arp(g.testNo, gw, time.Duration(p.YoklamaZamanAsimiMs)*time.Millisecond)
				if a.oui != "" { // motor yalnız değişince olay üretir
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

// ---------------------------------------------------------------------------
// Bildirimler: ağ arayüzü/adres değişikliği (NotifyIpInterfaceChange, NotifyUnicastIpAddressChange)
// ve uyku/uyanma (PowerRegisterSuspendResumeNotification, pencere gerektirmez).
// Geri çağrılar yalnız "uyandır" sinyali verir; asıl okuma gözlemci döngüsünde yapılır.
// ---------------------------------------------------------------------------

var (
	bildirimMu      sync.Mutex
	bildirimUyandir chan struct{}
	gucBildir       func(string)
	agGeriCagri     = windows.NewCallback(func(ctx, row, tip uintptr) uintptr { agDegisti(); return 0 })
	adresGeriCagri  = windows.NewCallback(func(ctx, row, tip uintptr) uintptr { agDegisti(); return 0 })
	gucGeriCagri    = windows.NewCallback(func(ctx, tip, ayar uintptr) uintptr { gucDegisti(uint32(tip)); return 0 })
	powrprof        = windows.NewLazySystemDLL("powrprof.dll")
	procGucKaydet   = powrprof.NewProc("PowerRegisterSuspendResumeNotification")
	procGucKaldir   = powrprof.NewProc("PowerUnregisterSuspendResumeNotification")
)

func agDegisti() {
	bildirimMu.Lock()
	c := bildirimUyandir
	bildirimMu.Unlock()
	if c != nil {
		select {
		case c <- struct{}{}:
		default:
		}
	}
}

func gucDegisti(tip uint32) {
	bildirimMu.Lock()
	f := gucBildir
	bildirimMu.Unlock()
	if f == nil {
		return
	}
	switch tip {
	case 4: // PBT_APMSUSPEND
		go f("uyku")
	case 7, 0x12: // PBT_APMRESUMESUSPEND, PBT_APMRESUMEAUTOMATIC
		go f("uyanma")
	}
}

type deviceNotifySubscribeParameters struct {
	Callback uintptr
	Context  uintptr
}

var gucParam = &deviceNotifySubscribeParameters{Callback: gucGeriCagri}

func bildirimleriKaydet(ctx context.Context, uyandir chan struct{}, guc func(string)) {
	bildirimMu.Lock()
	bildirimUyandir, gucBildir = uyandir, guc
	bildirimMu.Unlock()
	var h1, h2 windows.Handle
	if err := windows.NotifyIpInterfaceChange(windows.AF_INET, agGeriCagri, nil, false, &h1); err != nil {
		log.Printf("[BAĞLANTI] NotifyIpInterfaceChange: %v (yoklama turu yedek olarak çalışır)", err)
	}
	if err := windows.NotifyUnicastIpAddressChange(windows.AF_INET, adresGeriCagri, nil, false, &h2); err != nil {
		log.Printf("[BAĞLANTI] NotifyUnicastIpAddressChange: %v", err)
	}
	var gh uintptr
	if procGucKaydet.Find() == nil {
		const DEVICE_NOTIFY_CALLBACK = 2
		r, _, _ := procGucKaydet.Call(DEVICE_NOTIFY_CALLBACK, uintptr(unsafe.Pointer(gucParam)), uintptr(unsafe.Pointer(&gh)))
		if r != 0 {
			log.Printf("[BAĞLANTI] PowerRegisterSuspendResumeNotification: %d", r)
		}
	}
	go func() {
		<-ctx.Done()
		if h1 != 0 {
			windows.CancelMibChangeNotify2(h1)
		}
		if h2 != 0 {
			windows.CancelMibChangeNotify2(h2)
		}
		if gh != 0 && procGucKaldir.Find() == nil {
			procGucKaldir.Call(gh)
		}
		bildirimMu.Lock()
		bildirimUyandir, gucBildir = nil, nil
		bildirimMu.Unlock()
	}()
}
