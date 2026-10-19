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
  echo "STARNET Polaris include i componenti elencati sotto. Ciascuno resta soggetto alla propria licenza, riportata integralmente."
  echo "Il marchio STARNET (logo e simbolo in brand/) appartiene al suo titolare e non è coperto da queste licenze."
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
  # Programmi inclusi nella cartella strumenti (scripts/strumenti.sh): copie
  # originali con i testi delle licenze nella loro sottocartella License.
  mit() {
    cat <<EOF
(C) $1 hiyohiyo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
EOF
  }
  cat <<'EOF'
# Programmi inclusi nella cartella strumenti

Il pacchetto contiene le copie originali e non modificate di tre programmi di terze parti, verificate con l'impronta SHA-256 dell'archivio: CrystalDiskInfo e CrystalDiskMark, scaricati dalla pagina SourceForge del produttore (a cui rimanda il sito ufficiale https://crystalmark.info/), con gli eseguibili firmati digitalmente da CrystalMark Inc. e i testi completi delle licenze nella sottocartella License; BlueScreenView, scaricato dal sito https://www.nirsoft.net/, con l'eseguibile firmato da Nir Sofer e la licenza nel suo readme.txt.

## CrystalDiskInfo 9.9.2 (hiyohiyo, MIT)

Archivio originale: CrystalDiskInfo9_9_2.zip, SHA-256 01acb3176851a85824d9589c6514e3eb9771eb7f9d5ee58ed9b4e057bd21c7df, in strumenti/CrystalDiskInfo.

Componenti con licenza propria, testi in strumenti/CrystalDiskInfo/License: PolyHook 2.0, win32-darkmode, win32-custom-menubar-aero-theme, NVMeInterpreter, SlotSpeedGetter, MailKit e MimeKit (MIT); libgcc (GPL 3 con GCC Runtime Library Exception); opus-tools (BSD, in strumenti/CrystalDiskInfo/CdiResource/opus/COPYING.txt).

Contiene anche la libreria AMD_RC2t7 versione 0b8 Rev.2 di Gakuto Matsumura (弦生ささと), con licenza propria (testo completo in License/AMD_RC2t7.COPYRIGHT-en.txt): si può ridistribuire solo dentro il pacchetto del programma che la usa, senza modifiche, indicando nome dei file, versione, impronta SHA-256 e licenza. File: CdiResource/dll/AMD_RC2t7x64.dll (SHA-256 bdb01316ec6f444049bfef2b13ca34ee2f5f1713df2007e611d3220bc1b3b8b0) e CdiResource/dll/AMD_RC2t7x86.dll (SHA-256 68d7f33a3fa41668a07e4febe68f15d1d0107024cbbafc938a1af283ca0ff07c). La licenza chiede un accordo aggiuntivo se le funzioni o i risultati della libreria vengono venduti o fatti pagare (articolo 6).

```
EOF
  mit 2008-2026
  cat <<'EOF'
```

## CrystalDiskMark 9.0.3 (hiyohiyo, MIT)

Archivio originale: CrystalDiskMark9_0_3.zip, SHA-256 e0c1e76a8ca5df524ffb83b4553cc8f27e539feb3c2a692cc41189783c494b78, in strumenti/CrystalDiskMark.

Componenti con licenza propria, testi in strumenti/CrystalDiskMark/License: DiskSpd di Microsoft, PolyHook 2.0, win32-darkmode e win32-custom-menubar-aero-theme (MIT).

```
EOF
  mit 2007-2026
  cat <<'EOF'
```

## BlueScreenView 1.55 (NirSoft, freeware)

Archivio originale: bluescreenview-x64.zip, SHA-256 df57d4c9418dd2771035f2f7b70952caeb20d2269af683a0ab0665125c821479, in strumenti/BlueScreenView (con BlueScreenView.chm e readme.txt). Si ridistribuisce solo gratuitamente e con tutti i file del pacchetto, senza modifiche: se Polaris venisse distribuito a pagamento, BlueScreenView andrebbe tolto.

```
License
=======

This utility is released as freeware. You are allowed to freely
distribute this utility via floppy disk, CD-ROM, Internet, or in any
other way, as long as you don't charge anything for this. If you
distribute this utility, you must include all files in the distribution
package, without any modification !

Disclaimer
==========

The software is provided "AS IS" without any warranty, either expressed
or implied, including, but not limited to, the implied warranties of
merchantability and fitness for a particular purpose. The author will not
be liable for any special, incidental, consequential or indirect damages
due to loss of data or any other reason.
```
EOF
} > "$OUT"
echo "Scritto $OUT ($(grep -c '^## ' "$OUT") componenti)"
