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
  cd "$ROOT/core"
  for p in react react-dom scheduler; do
    v=$(node -p "require('./node_modules/$p/package.json').version")
    echo "## $p ($v, npm)"
    echo
    echo '```'
    cat "node_modules/$p/LICENSE"
    echo '```'
    echo
  done
} > "$OUT"
echo "Scritto $OUT ($(grep -c '^## ' "$OUT") componenti)"
