#!/bin/sh
# MX Linux'tan Windows exe cross-compile. mingw-w64 kurulu olmalı (x86_64-w64-mingw32-gcc).
set -e
cd "$(dirname "$0")"

CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
	go build -ldflags "-H=windowsgui" -o KolitakipIMZA.exe .

echo "OK -> KolitakipIMZA.exe"
