#!/usr/bin/env bash
# Rigenera THIRD_PARTY_NOTICES.md con i testi di licenza originali di tutto
# ciò che finisce dentro l'eseguibile (moduli Go e librerie JS incluse nel bundle).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
export GOTOOLCHAIN=${GOTOOLCHAIN:-local}
OUT="$ROOT/THIRD_PARTY_NOTICES.md"
{
  echo "# Componenti di terze parti"
  echo
  echo "LANterna include i componenti elencati sotto. Ciascuno resta soggetto alla propria licenza, riportata integralmente."
  echo "File generato da \`scripts/notices.sh\`: non modificarlo a mano."
  echo
  cd "$ROOT/windows"
  for m in $(GOOS=windows go list -deps -f '{{if .Module}}{{.Module.Path}}@{{.Module.Version}}{{end}}' ./cmd/lanterna | sort -u | grep -v '^lanterna'); do
    dir=$(go list -m -f '{{.Dir}}' "${m%@*}")
    lic=$(ls "$dir" | grep -iE '^(license|licence|copying)' | head -1)
    echo "## ${m%@*} (${m#*@})"
    echo
    echo '```'
    cat "$dir/$lic"
    echo '```'
    echo
    if [ "${m%@*}" = "github.com/jchv/go-webview2" ]; then
      echo "### Microsoft WebView2Loader.dll (incluso da go-webview2)"
      echo
      echo '```'
      cat "$dir/webviewloader/sdk/LICENSE.txt"
      echo '```'
      echo
    fi
  done
  # Interfaccia: solo i pacchetti npm effettivamente inclusi (JavaScript dal bundle,
  # fogli di stile e font dai sorgenti), elencati da scripts/bundled-packages.mjs.
  cd "$ROOT/core"
  MAPS=$(mktemp -d)
  npx vite build --sourcemap --outDir "$MAPS" --emptyOutDir --logLevel error >&2
  for d in $(node "$ROOT/scripts/bundled-packages.mjs" "$MAPS/assets" src); do
    name=$(node -p "require('./$d/package.json').name")
    v=$(node -p "require('./$d/package.json').version")
    spdx=$(node -p "require('./$d/package.json').license")
    lic=$(ls "$d" | grep -iE '^(license|licence|copying|ofl)' | head -1)
    [ -n "$lic" ] || { echo "Licenza non trovata in $d" >&2; exit 1; }
    echo "## $name ($v, npm, $spdx)"
    echo
    case "$name" in
      @fontsource-variable/*) echo "Font incorporato (solo sottoinsiemi latini, file woff2 di Fontsource)."; echo ;;
    esac
    echo '```'
    cat "$d/$lic"
    echo '```'
    echo
  done
  rm -rf "$MAPS"
} > "$OUT"
echo "Scritto $OUT ($(grep -c '^## ' "$OUT") componenti)"
