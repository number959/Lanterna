#!/usr/bin/env bash
# Programmi di terze parti inclusi nel pacchetto: le copie originali di
# CrystalDiskInfo e CrystalDiskMark (hiyohiyo, licenza MIT), come le pubblica il
# produttore su SourceForge, dove rimanda il sito ufficiale crystalmark.info, e
# di BlueScreenView (NirSoft, freeware ridistribuibile gratuitamente e senza
# modifiche), dal sito nirsoft.net.
# Ogni archivio si verifica con l'impronta SHA-256 fissata qui e si estrae, senza
# modificare nulla, in <pacchetto>/strumenti/<programma>/.
#   scripts/strumenti.sh build/STARNET-Polaris
# Gli archivi restano in build/cache-strumenti/ per le build successive.
#
# Per aggiornare un programma: versione pubblicata da almeno 14 giorni; impronta
# SHA-256 dell'archivio, dopo aver confrontato dimensione e MD5 con quelli
# pubblicati da SourceForge; nomi e impronte degli eseguibili in
# windows/internal/tools/bundled.go; versione in core/src/tools.ts e in
# scripts/notices.sh. Un test dell'agente controlla che coincidano.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
DEST=${1:?uso: scripts/strumenti.sh <cartella del pacchetto>}
CACHE="$ROOT/build/cache-strumenti"

# cartella, versione, archivio originale, SHA-256 dell'archivio.
# Dimensione e MD5 pubblicati da SourceForge, verificati sulla prima copia:
#   CrystalDiskInfo9_9_2.zip  8533389 byte, MD5 f27564837d3a4c77813bc69769bacf5c (25/07/2026)
#   CrystalDiskMark9_0_3.zip  3725706 byte, MD5 b93d7c56381d0d765a3fc8238da611f0 (23/05/2026)
# BlueScreenView 1.55 per Windows a 64 bit: 85380 byte, invariato dal 29/01/2015
# (data del server); l'eseguibile è firmato da Nir Sofer.
TOOLS=(
  "CrystalDiskInfo 9.9.2 https://downloads.sourceforge.net/project/crystaldiskinfo/9.9.2/CrystalDiskInfo9_9_2.zip 01acb3176851a85824d9589c6514e3eb9771eb7f9d5ee58ed9b4e057bd21c7df"
  "CrystalDiskMark 9.0.3 https://downloads.sourceforge.net/project/crystaldiskmark/9.0.3/CrystalDiskMark9_0_3.zip e0c1e76a8ca5df524ffb83b4553cc8f27e539feb3c2a692cc41189783c494b78"
  "BlueScreenView 1.55 https://www.nirsoft.net/utils/bluescreenview-x64.zip df57d4c9418dd2771035f2f7b70952caeb20d2269af683a0ab0665125c821479"
)

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# SourceForge rimanda a uno dei suoi mirror: se uno rifiuta, al tentativo
# successivo ne sceglie di solito un altro.
fetch() {
  local url=$1 out=$2 jar
  jar=$(mktemp)
  for wait in 2 4 0; do
    if curl -fsSL --max-time 300 -c "$jar" -b "$jar" -o "$out.part" "$url"; then
      mv "$out.part" "$out"
      rm -f "$jar"
      return 0
    fi
    if [ "$wait" != 0 ]; then
      echo "    nuovo tentativo tra $wait s" >&2
      sleep "$wait"
    fi
  done
  rm -f "$jar" "$out.part"
  return 1
}

extract() {
  if command -v unzip >/dev/null; then
    unzip -q "$1" -d "$2"
  else
    python3 -I -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$1" "$2"
  fi
}

mkdir -p "$CACHE"
rm -rf "$DEST/strumenti"
for t in "${TOOLS[@]}"; do
  read -r name version url sum <<<"$t"
  zip="$CACHE/$(basename "$url")"
  if [ ! -f "$zip" ] || [ "$(sha256 "$zip")" != "$sum" ]; then
    echo "    scarico $name $version da $url"
    fetch "$url" "$zip" || { echo "Download di $name non riuscito: riprova, oppure compila senza programmi inclusi con STRUMENTI=no" >&2; exit 1; }
  fi
  got=$(sha256 "$zip")
  if [ "$got" != "$sum" ]; then
    rm -f "$zip"
    echo "L'impronta SHA-256 di $(basename "$zip") non è quella attesa: $got" >&2
    exit 1
  fi
  mkdir -p "$DEST/strumenti/$name"
  extract "$zip" "$DEST/strumenti/$name"
  echo "    $name $version incluso (archivio originale verificato, SHA-256 $sum)"
done
