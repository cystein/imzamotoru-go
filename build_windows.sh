#!/bin/sh
# MX Linux'tan Windows exe cross-compile. mingw-w64 kurulu olmalı (x86_64-w64-mingw32-gcc).
#
# Bağlantı testi HMAC anahtarı (PROTOKOL §8.2) git'te DEĞİL. Varsa şu dosyadan okunur:
#   ${BT_ANAHTAR_DOSYASI:-$HOME/.kolitakip-release-key/baglanti-testi-hmac}
# Biçim tek satır: "<anahtar_no> <hex_anahtar>". Dosya yoksa anahtar_no=0 (herkese açık test anahtarı)
# ile derlenir — canlı sunucu bu derlemenin raporlarını reddeder.
#
# TESHIS=1 ./build_windows.sh → ayrıca saha test exe'si (KolitakipIMZA-teshis.exe, konsollu).
set -e
cd "$(dirname "$0")"

ANAHTAR_DOSYASI="${BT_ANAHTAR_DOSYASI:-$HOME/.kolitakip-release-key/baglanti-testi-hmac}"
BT_LDFLAGS=""
if [ -r "$ANAHTAR_DOSYASI" ]; then
	read -r BT_NO BT_HEX < "$ANAHTAR_DOSYASI"
	BT_LDFLAGS="-X main.btAnahtarNo=$BT_NO -X main.btAnahtarHex=$BT_HEX"
	echo "Bağlantı testi anahtarı: anahtar_no=$BT_NO"
else
	echo "UYARI: bağlantı testi anahtarı yok ($ANAHTAR_DOSYASI) — anahtar_no=0 ile derleniyor."
fi

CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
	go build -ldflags "-H=windowsgui $BT_LDFLAGS" -o KolitakipIMZA.exe .
echo "OK -> KolitakipIMZA.exe"

if [ "${TESHIS:-0}" = "1" ]; then
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
		go build -ldflags "$BT_LDFLAGS" -o KolitakipIMZA-teshis.exe .
	echo "OK -> KolitakipIMZA-teshis.exe (saha teşhis aracı, konsollu)"
fi
