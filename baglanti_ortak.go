package main

// Bağlantı testi gözlemcilerinin (Windows, Linux) ortak yardımcıları.

import (
	"fmt"
	"net"
	"strings"
)

var vpnKelimeleri = []string{"tap-", "tap ", "tun ", "wintun", "wireguard", "vpn", "openvpn", "fortinet", "anyconnect",
	"cisco", "zerotier", "tailscale", "nordlynx", "proton", "pangp", "globalprotect", "juniper", "sonicwall", "check point",
	"checkpoint", "l2tp", "pptp", "sstp", "ikev2", "softether", "hamachi", "radmin"}

var tunelHaric = []string{"teredo", "ip-https", "6to4", "isatap", "loopback"}

var sanalKelimeleri = []string{"hyper-v", "vethernet", "virtualbox", "vmware", "virtual adapter", "docker", "wsl", "npcap", "loopback", "wi-fi direct", "bluetooth"}

func icerir(s string, liste []string) bool {
	s = strings.ToLower(s)
	for _, k := range liste {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
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

// arpSonucu: tek bir ARP yoklamasının sonucu (Windows ve Linux gözlemcileri).
type arpSonucu struct {
	sonuc, onbellek, oui string
	sureMs               int64
}

// apipasiz: 169.254.x.x (APIPA — DHCP alamamış) adreslerini çıkarır; "a.b.c.d/n" biçimi.
func apipasiz(l []string) []string {
	out := []string{}
	for _, a := range l {
		if !strings.HasPrefix(a, "169.254.") {
			out = append(out, a)
		}
	}
	return out
}

// fizikselTur: sayıma giren fiziksel bağlantı türleri (VPN, sanal, köprü, loopback hariç).
func fizikselTur(tur string) bool { return tur == "ethernet" || tur == "wifi" || tur == "mobil" }
