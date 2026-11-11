#!/usr/bin/env bash
# Rigenera THIRD_PARTY_NOTICES.md con i testi di licenza originali di tutto
# ciò che finisce dentro l'eseguibile (moduli Go e librerie JS incluse nel bundle)
# e i crediti di dati, voce delle videoguide e programmi inclusi.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
# Go scarica da solo la versione indicata in go.mod se quella installata è più vecchia.
export GOTOOLCHAIN=${GOTOOLCHAIN:-auto}
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
  # Dati incorporati nell'agente: l'elenco dei prefissi MAC della IEEE
  # (scripts/oui.sh). Giorno del download, fonti e conteggi vengono
  # dall'intestazione del file incorporato, così restano allineati.
  oui_meta() { gzip -dc "$ROOT/windows/internal/oui/oui.txt.gz" | sed -n "s/^# $1: //p"; }
  OUI_DATA=$(oui_meta scaricato)
  OUI_FONTI=$(oui_meta fonte | paste -sd, - | sed 's/,\([^,]*\)$/ e \1/; s/,/, /g')
  OUI_VOCI=$(oui_meta voci)
  [ -n "$OUI_DATA" ] && [ -n "$OUI_FONTI" ] && [ -n "$OUI_VOCI" ] || { echo "Intestazione di windows/internal/oui/oui.txt.gz incompleta" >&2; exit 1; }
  echo "## Elenco pubblico dei prefissi MAC della IEEE Registration Authority (MA-L, MA-M, MA-S)"
  echo
  echo "Elenco pubblico dei prefissi MAC (MA-L, MA-M, MA-S) della IEEE Registration Authority, scaricato il $OUI_DATA da $OUI_FONTI. L'agente lo incorpora in forma ridotta (windows/internal/oui/oui.txt.gz, generato da scripts/oui.sh) per riconoscere il produttore di un dispositivo dal suo indirizzo MAC senza collegarsi a Internet: per ogni blocco solo il prefisso e il nome dell'organizzazione, abbreviato (senza forme societarie, per i produttori più comuni con il nome del marchio), senza indirizzi; esclusi i blocchi \"Private\" e quelli che la IEEE Registration Authority suddivide in blocchi più piccoli. Voci: $OUI_VOCI."
  echo
  cat <<'EOF'
Le pagine della IEEE Registration Authority (https://standards.ieee.org/products-programs/regauth/) offrono l'elenco come pubblico, da scaricare, e non indicano una licenza: condizioni d'uso da verificare. Lo stesso elenco è ridistribuito, per esempio, dal pacchetto `ieee-data` di Debian (https://packages.debian.org/sid/ieee-data), il cui file di copyright attribuisce alla IEEE la dichiarazione che segue; sulle pagine attuali della IEEE non compare: da verificare.

```
IEEE does not assert any copyright in the OUI Public Listing or attempt
to restrict distribution of the listing in any way. The IEEE
Registration Authority does, however, strongly encourage those who use
the list to obtain it directly from IEEE (and to update it on a regular
basis) to ensure the integrity of the information.
```

EOF
  # Narrazione delle videoguide: registrazioni generate una volta con una voce
  # sintetica (scripts/narrazione). Voce, modello e licenza vengono dall'indice
  # delle registrazioni, così i crediti seguono la voce che c'è nel programma.
  node "$ROOT/scripts/narrazione/crediti.mjs"
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

Il pacchetto contiene le copie originali e non modificate di quattro programmi di terze parti, verificate con l'impronta SHA-256 dell'archivio: CrystalDiskInfo e CrystalDiskMark, scaricati dalla pagina SourceForge del produttore (a cui rimanda il sito ufficiale https://crystalmark.info/), con gli eseguibili firmati digitalmente da CrystalMark Inc. e i testi completi delle licenze nella sottocartella License; BlueScreenView, scaricato dal sito https://www.nirsoft.net/, con l'eseguibile firmato da Nir Sofer e la licenza nel suo readme.txt; UsbTreeView, scaricato dal sito https://www.uwe-sieber.de/, con l'eseguibile verificato dall'impronta SHA-256 (porta una firma digitale a nome di Uwe Sieber che Windows, sulla macchina di collaudo, non ha confermato; nel pacchetto solo la versione per l'architettura del pacchetto).

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

## UsbTreeView 4.8.0 (Uwe Sieber, freeware)

Archivi originali, uno per architettura: UsbTreeView_x64.zip (SHA-256 bce7e2d861d586904d57f7d6500b91c7931105aba3888ac761c90dc8aedbae06), UsbTreeView_arm64.zip (SHA-256 355ef6d8dcb8cc6588c8ba9e6dac8992ec030253b2a7b2e8fa02416dc6bf2b8f) e UsbTreeView_Win32.zip (SHA-256 83baa7abe12d8e489a6b70b7daa783c366ebcea0a9987f03abc147f28c178a5c), dal sito https://www.uwe-sieber.de/usbtreeview_e.html, in strumenti/UsbTreeView/<architettura>. Polaris lo include senza modifiche e non lo scarica mai su richiesta: la licenza vieta di offrirlo tramite un programma che lo scarica. Condizioni pubblicate dall'autore (pagina del programma, 9 novembre 2026):

```
UsbTreeView is Freeware.
Allowed:
- usage in any environment, including commercial
- include in software products, including commercial
- include on CD/DVD of computer magazines
- distribution by means of packet managers
Not allowed:
- modify any of the files
- offer for download by means of a "downloader" software
```
EOF
} > "$OUT"
echo "Scritto $OUT ($(grep -c '^## ' "$OUT") componenti)"
