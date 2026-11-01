#!/bin/sh
# Var olan kurulumlar için self-update paketini yayınlar.
# Kullanım: ./release.sh 1.2.0 [asgari-desteklenen-surum]
#
# İkinci argüman OPSİYONEL: verilirse latest.json'a min_supported_version yazılır, ondan eski
# istemciler bir sonraki kontrolde imzalamayı durdurup güncellenir (bkz. tools/sign_release,
# update_windows.go MinSupportedVersion). Normal yayında verilmez.
#
# NOT: Bu script SADECE self-update kanalını (KolitakipIMZA.exe.gz + latest.json)
# günceller — Program Files'a taze kurulum yapan installer'ı (KolitakipIMZA-Setup.exe)
# GÜNCELLEMEZ. Installer'ı da tazelemek istiyorsanız (yeni eczane kurulumları en son
# sürümü doğrudan alsın diye), .github/workflows/build-installer.yml'yi tetikleyin
# (bkz. EL_KITABI.md §7, Adım 5).
#
# KolitakipIMZA.exe.gz (~6-7MB) artık bizim sunucumuz yerine GitHub Releases'ten
# dağıtılıyor (2026-08-15) — sunucumuzun upload bant genişliği düşük, GitHub'ın CDN'i
# çok daha hızlı ve bizim hattımızı hiç yormuyor. latest.json HÂLÂ bizim sunucumuzda
# kalıyor (birkaç yüz bayt, sorun değil) — Go istemcisindeki latestVersionURL sabiti
# HİÇ DEĞİŞMEDİ, yani bu değişiklik mevcut hiçbir kurulumu etkilemiyor, yeni bir Go
# sürümü yayınlamaya gerek yok. Sadece latest.json'ın İÇİNDEKİ "url" alanı artık
# GitHub'ı gösteriyor.
set -e

VERSION="$1"
MIN_SURUM="$2"
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

if ! command -v gh >/dev/null 2>&1; then
	echo "HATA: gh (GitHub CLI) bulunamadı — GitHub Release'e yükleme için gerekli."
	exit 1
fi

cd "$(dirname "$0")"

REPO="cystein/imzamotoru-go"
TAG="v$VERSION"

sed -i "s/const APP_VERSION = \".*\"/const APP_VERSION = \"$VERSION\"/" version.go
sed -i "s/#define MyAppVersion \".*\"/#define MyAppVersion \"$VERSION\"/" installer/KolitakipIMZA.iss

./build_windows.sh

DEST="$HOME/claude_projeler/sgk-imza-platformu/public/imza-motoru"
# Büyük dosya (exe.gz) artık GitHub Releases'ten iniyor — DOWNLOAD_URL burayı gösteriyor.
# latest.json'ın kendisi küçük olduğu için hâlâ bizim sunucumuzdan servis ediliyor.
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$TAG/KolitakipIMZA.exe.gz"

# sha256 + ECDSA imzası burada, imzalanmamış (gzip'siz) exe üzerinden üretiliyor — istemci de
# indirdiğini gzip'ten çıkardıktan SONRA aynı ham byte'ları doğruluyor.
go run ./tools/sign_release "$PRIVATE_KEY" KolitakipIMZA.exe "$VERSION" "$DOWNLOAD_URL" "$DEST/latest.json" ${MIN_SURUM:+"$MIN_SURUM"}

gzip -9 -f -c KolitakipIMZA.exe > KolitakipIMZA.exe.gz

# Aynı $TAG altında installer job'ı (build-installer.yml) ile paylaşılan bir GitHub Release
# kullanılıyor — o etiket zaten varsa (installer önce yayınlanmışsa) asset eklenir/üzerine
# yazılır (--clobber, idempotent); yoksa burada oluşturulur.
if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
	gh release upload "$TAG" KolitakipIMZA.exe.gz --repo "$REPO" --clobber
else
	gh release create "$TAG" KolitakipIMZA.exe.gz --repo "$REPO" \
		--title "KolitakipIMZA $TAG" --notes "Self-update kanalı yayını."
fi

echo ""
echo "OK -> v$VERSION imzalanıp self-update kanalına yayınlandı."
echo "  - KolitakipIMZA.exe.gz -> GitHub Release $TAG ($REPO)"
echo "  - latest.json          -> $DEST/latest.json (bizim sunucumuz)"
echo "Var olan kurulumlar 6 saat içinde (veya yeniden başlatılınca) otomatik güncellenecek."
echo ""
echo "Installer'ı da tazelemek isterseniz: git push sonrası"
echo "  gh workflow run build-installer.yml --repo $REPO"
