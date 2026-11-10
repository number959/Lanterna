#!/usr/bin/env bash
# Elenco dei produttori dei dispositivi di rete incorporato nell'agente
# (windows/internal/oui/oui.txt.gz): scarica l'elenco pubblico dei prefissi MAC
# della IEEE Registration Authority (MA-L, MA-M e MA-S, in CSV) in una cartella
# temporanea nuova e vuota, ne ricava con il generatore Go
# (windows/internal/oui/gen/main.go) le righe "prefisso<TAB>nome", con i nomi
# abbreviati, e riscrive il file; poi esegue i test del pacchetto. I file
# scaricati sono solo dati: si leggono, non si eseguono.
#   scripts/oui.sh
# Dopo l'aggiornamento: scripts/notices.sh, che riporta giorno del download e
# conteggi nelle note di terze parti.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
# Go scarica da solo la versione indicata in go.mod se quella installata è più vecchia.
export GOTOOLCHAIN=${GOTOOLCHAIN:-auto}
OUT=internal/oui/oui.txt.gz

URLS=(
  https://standards-oui.ieee.org/oui/oui.csv
  https://standards-oui.ieee.org/oui28/mam.csv
  https://standards-oui.ieee.org/oui36/oui36.csv
)

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
DATA=$(date -u +%Y-%m-%d)
for url in "${URLS[@]}"; do
  echo "    scarico $url"
  curl -fsSL --proto '=https' --proto-redir '=https' --max-time 300 -o "$TMP/$(basename "$url")" "$url" ||
    { echo "Download di $url non riuscito: l'elenco incorporato resta quello di prima" >&2; exit 1; }
done

cd "$ROOT/windows"
# Il generatore usa il pacchetto oui, che incorpora il file: alla prima
# generazione basta un segnaposto vuoto.
[ -f "$OUT" ] || : >"$OUT"
go run ./internal/oui/gen/main.go -data "$DATA" -out "$OUT" "$TMP" "${URLS[@]}"
go test ./internal/oui/
