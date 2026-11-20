#!/bin/sh
# Aşamalı (ADAY=1 ./release.sh) yayınlanmış bir sürümü HERKESE açar:
#   latest-aday.json → latest.json (var olan kurulumlar 6 saat içinde güncellenir) ve GitHub
#   Release'i pre-release'ten çıkarıp "latest" yapar (/releases/latest/ bağlantıları yeni Setup.exe'yi verir).
# Kullanım: ./yayina_al.sh 2.0.0
set -e
VERSION="$1"
[ -n "$VERSION" ] || { echo "Kullanım: $0 <versiyon>"; exit 1; }
DEST="$HOME/claude_projeler/sgk-imza-platformu/public/imza-motoru"
REPO="cystein/imzamotoru-go"
ADAY_SURUM=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$DEST/latest-aday.json")
if [ "$ADAY_SURUM" != "$VERSION" ]; then
	echo "HATA: latest-aday.json $ADAY_SURUM sürümünde, $VERSION değil."
	exit 1
fi
gh release view "v$VERSION" --repo "$REPO" --json assets -q '.assets[].name' | grep -qx 'KolitakipAsistan-Setup.exe' || {
	echo "HATA: v$VERSION release'inde KolitakipAsistan-Setup.exe yok — önce installer workflow'unu çalıştırın."; exit 1; }
cp "$DEST/latest-aday.json" "$DEST/latest.json"
gh release edit "v$VERSION" --repo "$REPO" --prerelease=false --latest
echo "OK -> v$VERSION herkese açıldı (latest.json güncellendi, release 'latest')."
