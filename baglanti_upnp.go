package main

// UPnP IGD okuyucu (PROTOKOL §4.2 "upnp", isteğe bağlı kanıt). Modemin UPnP hizmeti açıksa
// WAN bağlantısının çalışma süresini (Uptime), durumunu ve dış IP'yi okur. Çoğu modemde kapalıdır;
// yoksa sessizce "yok" döner. Yalnız okuma yapar (port açma vb. YOK). Saf Go, platformdan bağımsız.

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type upnpIGD struct {
	kontrolURL string
	servis     string // urn:schemas-upnp-org:service:WANIPConnection:1 ya da WANPPPConnection
}

var upnpKonumDeseni = regexp.MustCompile(`(?im)^location:\s*(\S+)\s*$`)

// upnpBul, yerel ağda IGD arar. yerelIP boş değilse arama o arayüzden yapılır (test arayüzü).
func upnpBul(ctx context.Context, yerelIP string, sure time.Duration) (*upnpIGD, error) {
	var laddr *net.UDPAddr
	if yerelIP != "" {
		laddr = &net.UDPAddr{IP: net.ParseIP(yerelIP)}
	}
	c, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	hedef := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	for _, st := range []string{"urn:schemas-upnp-org:device:InternetGatewayDevice:1", "urn:schemas-upnp-org:device:InternetGatewayDevice:2"} {
		msg := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: " + st + "\r\n\r\n"
		c.WriteToUDP([]byte(msg), hedef)
	}
	son := time.Now().Add(sure)
	if d, ok := ctx.Deadline(); ok && d.Before(son) {
		son = d
	}
	c.SetReadDeadline(son)
	buf := make([]byte, 2048)
	for {
		n, _, err := c.ReadFromUDP(buf)
		if err != nil {
			return nil, fmt.Errorf("igd bulunamadı")
		}
		m := upnpKonumDeseni.FindSubmatch(buf[:n])
		if m == nil {
			continue
		}
		if igd, err := upnpAciklamaOku(ctx, string(m[1])); err == nil {
			return igd, nil
		}
	}
}

type upnpServis struct {
	Tip        string `xml:"serviceType"`
	KontrolURL string `xml:"controlURL"`
}

type upnpAygit struct {
	Servisler []upnpServis `xml:"serviceList>service"`
	Aygitlar  []upnpAygit  `xml:"deviceList>device"`
}

func (a upnpAygit) wanServisi() *upnpServis {
	for i, s := range a.Servisler {
		if strings.Contains(s.Tip, "WANIPConnection") || strings.Contains(s.Tip, "WANPPPConnection") {
			return &a.Servisler[i]
		}
	}
	for _, alt := range a.Aygitlar {
		if s := alt.wanServisi(); s != nil {
			return s
		}
	}
	return nil
}

func upnpAciklamaOku(ctx context.Context, konum string) (*upnpIGD, error) {
	u, err := url.Parse(konum)
	if err != nil || (u.Scheme != "http") || net.ParseIP(u.Hostname()) == nil {
		return nil, fmt.Errorf("geçersiz konum")
	}
	// Yalnız özel (yerel) adresler: bir yanıt bizi internete yönlendiremesin.
	if ip := net.ParseIP(u.Hostname()); !ip.IsPrivate() && !ip.IsLoopback() {
		return nil, fmt.Errorf("yerel olmayan igd adresi")
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", konum, nil)
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var kok struct {
		URLBase string    `xml:"URLBase"`
		Aygit   upnpAygit `xml:"device"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&kok); err != nil {
		return nil, err
	}
	s := kok.Aygit.wanServisi()
	if s == nil {
		return nil, fmt.Errorf("wan servisi yok")
	}
	taban := u
	if kok.URLBase != "" {
		if b, err := url.Parse(kok.URLBase); err == nil {
			taban = b
		}
	}
	k, err := taban.Parse(s.KontrolURL)
	if err != nil || net.ParseIP(k.Hostname()) == nil || !(net.ParseIP(k.Hostname()).IsPrivate() || net.ParseIP(k.Hostname()).IsLoopback()) {
		return nil, fmt.Errorf("geçersiz kontrol adresi")
	}
	return &upnpIGD{kontrolURL: k.String(), servis: s.Tip}, nil
}

func (g *upnpIGD) cagir(ctx context.Context, eylem string) (map[string]string, error) {
	govde := `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:` +
		eylem + ` xmlns:u="` + g.servis + `"/></s:Body></s:Envelope>`
	req, _ := http.NewRequestWithContext(ctx, "POST", g.kontrolURL, bytes.NewBufferString(govde))
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+g.servis+"#"+eylem+`"`)
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// Yanıt öğelerini ad → metin olarak topla (ad alanlarından bağımsız).
	sonuc := map[string]string{}
	d := xml.NewDecoder(io.LimitReader(resp.Body, 64<<10))
	var ad string
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			ad = t.Name.Local
		case xml.CharData:
			if ad != "" && strings.TrimSpace(string(t)) != "" {
				sonuc[ad] = strings.TrimSpace(string(t))
			}
		case xml.EndElement:
			ad = ""
		}
	}
	return sonuc, nil
}

// upnpOku: {uptime_s, baglanti, dis_ip}. Okunamayan alanlar boş/0 kalır.
func (g *upnpIGD) oku(ctx context.Context) (map[string]any, error) {
	durum, err := g.cagir(ctx, "GetStatusInfo")
	if err != nil {
		return nil, err
	}
	v := map[string]any{"baglanti": durum["NewConnectionStatus"], "uptime_s": float64(0), "dis_ip": ""}
	if s, err := strconv.ParseFloat(durum["NewUptime"], 64); err == nil {
		v["uptime_s"] = s
	}
	if ip, err := g.cagir(ctx, "GetExternalIPAddress"); err == nil {
		v["dis_ip"] = ip["NewExternalIPAddress"]
	}
	return v, nil
}
