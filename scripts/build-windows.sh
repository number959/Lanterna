#!/usr/bin/env bash
# Compila LANterna per Windows (da Linux, macOS o Windows con Git Bash).
#   scripts/build-windows.sh            -> build/LANterna/ e build/LANterna-windows-<arch>.zip
#   ARCH=arm64 scripts/build-windows.sh -> versione per Windows su ARM
# Requisiti: Node.js 20+, Go 1.24+.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
ARCH=${ARCH:-amd64}
VERSION=${VERSION:-0.1.0+$(git rev-parse --short HEAD 2>/dev/null || echo dev)}
export GOTOOLCHAIN=${GOTOOLCHAIN:-local}

echo "==> Nucleo web (interfaccia + motore di analisi)"
cd "$ROOT/core"
[ -d node_modules ] || npm ci --no-audit --no-fund
npm run build

echo "==> Risorse incorporate nell'eseguibile"
ASSETS="$ROOT/windows/internal/assets/dist"
find "$ASSETS" -mindepth 1 ! -name .gitkeep -exec rm -rf {} +
cp -r "$ROOT/core/dist/." "$ASSETS/"
cp "$ROOT/core/dist-engine/engine.js" "$ASSETS/engine.js"

echo "==> Icona, manifest e informazioni di versione"
cd "$ROOT/windows"
go run github.com/tc-hib/go-winres@v0.3.3 make --in winres/winres.json --out cmd/lanterna/rsrc --arch "$ARCH"

echo "==> Eseguibili Windows ($ARCH, versione $VERSION)"
OUT="$ROOT/build/LANterna"
rm -rf "$OUT" && mkdir -p "$OUT"
LDFLAGS="-s -w -X main.version=$VERSION"
CGO_ENABLED=0 GOOS=windows GOARCH=$ARCH go build -trimpath -ldflags "$LDFLAGS -H windowsgui" -o "$OUT/LANterna.exe" ./cmd/lanterna
CGO_ENABLED=0 GOOS=windows GOARCH=$ARCH go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/lanterna-cli.exe" ./cmd/lanterna
cp "$ROOT/windows/LEGGIMI.txt" "$ROOT/THIRD_PARTY_NOTICES.md" "$OUT/"

cd "$ROOT/build"
rm -f "LANterna-windows-$ARCH.zip"
if command -v zip >/dev/null; then
  zip -qr "LANterna-windows-$ARCH.zip" LANterna
else
  python3 -c "import shutil; shutil.make_archive('LANterna-windows-$ARCH', 'zip', '.', 'LANterna')"
fi
ls -la "$OUT" "$ROOT/build/LANterna-windows-$ARCH.zip"
