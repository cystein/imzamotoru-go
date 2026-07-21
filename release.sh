#!/bin/sh
# Var olan kurulumlar için self-update paketini yayınlar.
# Kullanım: ./release.sh 1.2.0
#
# NOT: Bu script SADECE self-update kanalını (KolitakipIMZA.exe.gz + latest.json)
# günceller — Program Files'a taze kurulum yapan installer'ı (KolitakipIMZA-Setup.exe)
# GÜNCELLEMEZ. Installer'ı da tazelemek istiyorsanız (yeni eczane kurulumları en son
# sürümü doğrudan alsın diye), üretilen KolitakipIMZA.exe'yi Windows'lu birine gönderip
# installer/KolitakipIMZA.iss'i Inno Setup ile yeniden derletip çıkan
# KolitakipIMZA-Setup.exe'yi de aynı $DEST klasörüne koymanız gerekiyor.
set -e

VERSION="$1"
if [ -z "$VERSION" ]; then
	echo "Kullanım: $0 <versiyon>  (örn: 1.2.0)"
	exit 1
fi

PRIVATE_KEY="$HOME/.kolitakip-release-key/release-private.pem"
if [ ! -f "$PRIVATE_KEY" ]; then
	echo "HATA: Özel anahtar bulunamadı: $PRIVATE_KEY"
	echo "Bu makinede yoksa, yayın yalnızca anahtarın bulunduğu makineden yapılabilir."
	exit 1
fi

cd "$(dirname "$0")"

sed -i "s/const APP_VERSION = \".*\"/const APP_VERSION = \"$VERSION\"/" version.go
sed -i "s/#define MyAppVersion \".*\"/#define MyAppVersion \"$VERSION\"/" installer/KolitakipIMZA.iss

./build_windows.sh

DEST="$HOME/claude_projeler/sgk-imza-platformu/public/imza-motoru"
DOWNLOAD_URL="https://itiraz.sgkkolitakip.web.tr/imza-motoru/KolitakipIMZA.exe.gz"

# sha256 + ECDSA imzası burada, imzalanmamış (gzip'siz) exe üzerinden üretiliyor — istemci de
# indirdiğini gzip'ten çıkardıktan SONRA aynı ham byte'ları doğruluyor.
go run ./tools/sign_release "$PRIVATE_KEY" KolitakipIMZA.exe "$VERSION" "$DOWNLOAD_URL" "$DEST/latest.json"

gzip -9 -f -c KolitakipIMZA.exe > KolitakipIMZA.exe.gz
cp KolitakipIMZA.exe.gz "$DEST/KolitakipIMZA.exe.gz"

echo ""
echo "OK -> v$VERSION imzalanıp self-update kanalına yayınlandı."
echo "Var olan kurulumlar 6 saat içinde (veya yeniden başlatılınca) otomatik güncellenecek."
echo ""
echo "Installer'ı da tazelemek isterseniz: KolitakipIMZA.exe'yi Windows'lu birine gönderip"
echo "installer/KolitakipIMZA.iss'i derletin, çıkan KolitakipIMZA-Setup.exe'yi $DEST içine koyun."
