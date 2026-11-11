#!/usr/bin/env python3
"""Costruisce una pagina per ascoltare tutta la narrazione, frase per frase.

Le nove videoguide una sotto l'altra, ogni frase con il suo numero (3.12 è la
dodicesima frase della terza videoguida) e la sua registrazione dentro la
pagina: si apre in un browser, si ascolta, e chi ascolta dice i numeri delle
frasi da rifare. È il controllo che gli script non sanno fare: sentire se la
voce va bene.

    node scripts/narrazione/frasi.mjs frasi.json
    python scripts/narrazione/ascolto.py --frasi frasi.json --uscita narrazione.html

L'audio della pagina è in MP3, che ogni browser legge (il programma usa le
registrazioni Ogg Opus originali, un poco più pulite). Serve ffmpeg.
"""
from __future__ import annotations

import argparse
import base64
import html
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from genera import CARTELLA, INDICE, leggi_indice  # noqa: E402

PAUSA_MS = 350  # la stessa del lettore (GAP_MS in core/src/ui/videoguide.tsx)


def mp3(file: Path) -> str:
    cmd = [
        "ffmpeg", "-hide_banner", "-loglevel", "error", "-i", str(file),
        "-c:a", "libmp3lame", "-b:a", "64k", "-ar", "24000", "-ac", "1",
        "-map_metadata", "-1", "-id3v2_version", "0", "-f", "mp3", "pipe:1",
    ]  # fmt: skip
    return "data:audio/mpeg;base64," + base64.b64encode(subprocess.run(cmd, capture_output=True, check=True).stdout).decode()


def durata(ms: float) -> str:
    s = round(ms / 1000)
    return f"{s // 60} min {s % 60:02d} s" if s >= 60 else f"{s} s"


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--frasi", required=True, help="JSON scritto da frasi.mjs")
    p.add_argument("--uscita", required=True, type=Path, help="pagina HTML da scrivere")
    p.add_argument("--cartella", type=Path, default=CARTELLA)
    p.add_argument("--indice", type=Path, default=INDICE)
    args = p.parse_args()

    frasi = json.loads(Path(args.frasi).read_text(encoding="utf-8"))
    voce, clip = leggi_indice(args.indice)
    mancanti = [f["testo"] for f in frasi if f["testo"] not in clip]
    if mancanti:
        raise SystemExit(f"{len(mancanti)} frasi senza registrazione: prima genera.py")

    guide, audio, indice, totale = [], [], [], 0.0
    video = list(dict.fromkeys(f["video"] for f in frasi))
    for g, v in enumerate(video, 1):
        blocco = [f for f in frasi if f["video"] == v]
        ms = sum(clip[f["testo"]]["ms"] + PAUSA_MS for f in blocco)
        totale += ms
        scene, n = [], 0
        for s in dict.fromkeys(f["scena"] for f in blocco):
            righe = []
            for f in (f for f in blocco if f["scena"] == s):
                n += 1
                audio.append(mp3(args.cartella / clip[f["testo"]]["file"]))
                righe.append(
                    f'<li><button class="frase" type="button" data-g="{g}" data-n="{g}.{n}">'
                    f'<span class="n">{g}.{n}</span><span class="t">{html.escape(f["testo"])}</span></button></li>'
                )
            titolo = next(f["titoloScena"] for f in blocco if f["scena"] == s)
            scene.append(f'<div class="scena"><h3>{html.escape(titolo)}</h3><ol>{"".join(righe)}</ol></div>')
        t = html.escape(blocco[0]["titolo"])
        indice.append(f'<a href="#g{g}"><b>{g}</b>{t}</a>')
        guide.append(
            f'<section class="guida" id="g{g}"><div class="capo"><span class="num" aria-hidden="true">{g}</span><h2>{t}</h2>'
            f'<span class="dur">{durata(ms)}</span></div><button class="tutta" type="button" data-g="{g}">Ascolta tutta</button>{"".join(scene)}</section>'
        )

    pagina = (Path(__file__).resolve().parent / "ascolto.html").read_text(encoding="utf-8")
    campi = {
        "@@VOCE@@": html.escape(voce.get("nome", "")),
        "@@FRASI@@": str(len(frasi)),
        "@@MINUTI@@": str(round(totale / 60000)),
        "@@INDICE@@": "".join(indice),
        "@@GUIDE@@": "\n".join(guide),
        "@@AUDIO@@": json.dumps(audio),
    }
    for k, val in campi.items():
        pagina = pagina.replace(k, val)
    args.uscita.write_text(pagina, encoding="utf-8")
    print(f"{args.uscita}: {len(pagina) / 1e6:.1f} MB, {len(audio)} frasi, {len(video)} videoguide, {totale / 60000:.1f} minuti")


if __name__ == "__main__":
    main()
