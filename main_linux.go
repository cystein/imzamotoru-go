//go:build linux

package main

import (
	"log"
	"net"
)

// platformStartup, Linux'ta port'u ayırır (başarısız olursa orijinal davranışla aynı hata
// mesajıyla — "listen tcp 127.0.0.1:53911: bind: ..." — process'i sonlandırır), sonra
// donanım işçisini ve sunucuyu başlatır.
func platformStartup() {
	ln, err := net.Listen("tcp", "127.0.0.1:"+PORT)
	if err != nil {
		log.Fatal(err)
	}
	go cardWorker()
	startServer(ln)
}
