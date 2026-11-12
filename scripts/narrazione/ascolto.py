#!/usr/bin/env python3
"""Costruisce una pagina per ascoltare tutta la narrazione, frase per frase.

Le nove videoguide una sotto l'altra, ogni frase con il suo numero (3.12 è la
dodicesima frase della terza videoguida) e la sua registrazione dentro la
pagina: si apre in un browser, si ascolta, e chi ascolta dice i numeri delle
frasi da rifare. È il controllo che gli script non sanno fare: sentire se la
voce va bene. La pagina è un documento completo e non chiede nulla alla rete.
Con --frammento esce senza l'involucro del documento e con i caratteri del
marchio presi da Google Fonts: è la forma per gli ambienti che l'involucro lo
aggiungono da soli quando pubblicano la pagina.

    node scripts/narrazione/frasi.mjs frasi.json
    python scripts/narrazione/ascolto.py --frasi frasi.json --uscita narrazione.html

Con --rapporto si passa il rapporto di `genera.py --riascolta`: le frasi su cui
il riconoscitore o la misura dell'altezza hanno un dubbio vengono segnate, e
la pagina le elenca in cima, da ascoltare per prime.

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
CARATTERI = (
    '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600'
    '&family=JetBrains+Mono:wght@500;600&family=Saira:wdth,wght@112,600;112,700&display=swap">'
)


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
    p.add_argument("--rapporto", type=Path, help="rapporto di genera.py --riascolta: segna le frasi dubbie")
    p.add_argument("--soglia", type=float, default=0.04, help="scarto delle parole oltre il quale una frase è dubbia")
    p.add_argument("--tolleranza", type=float, default=0.10, help="distanza dall'altezza mediana oltre la quale una frase è dubbia")
    p.add_argument("--frammento", action="store_true", help="senza l'involucro del documento e con i caratteri da Google Fonts: per chi pubblica la pagina dentro un involucro suo")
    args = p.parse_args()

    frasi = json.loads(Path(args.frasi).read_text(encoding="utf-8"))
    voce, clip = leggi_indice(args.indice)
    mancanti = [f["testo"] for f in frasi if f["testo"] not in clip]
    if mancanti:
        raise SystemExit(f"{len(mancanti)} frasi senza registrazione: prima genera.py")

    # Le frasi su cui i controlli automatici hanno un dubbio, con il motivo.
    dubbi: dict[str, str] = {}
    if args.rapporto:
        esiti = json.loads(args.rapporto.read_text(encoding="utf-8"))
        if not isinstance(esiti, list) or not all(isinstance(e, dict) and "testo" in e and "scarto" in e for e in esiti):
            raise SystemExit("--rapporto: serve il rapporto di `genera.py --riascolta` (quello di controlla.py ha altre misure e qui non si legge)")
        altezze = sorted(e["hz"] for e in esiti if e.get("hz"))
        mediana = altezze[len(altezze) // 2] if altezze else 0
        for e in esiti:
            motivi = []
            if e.get("pronunce"):
                motivi.append("pronuncia da controllare: " + ", ".join(x.split(" (")[0] for x in e["pronunce"].split("), ")))
            # Lo scarto delle sole parole, se il rapporto lo ha: quello totale comprende la pena per la pronuncia.
            if e.get("parole", e["scarto"] if not e.get("pronunce") else 0) > args.soglia:
                motivi.append("parole da controllare")
            if mediana and e.get("hz") and abs(e["hz"] / mediana - 1) > args.tolleranza:
                motivi.append("tono più " + ("alto" if e["hz"] > mediana else "basso") + " delle altre")
            if motivi:
                dubbi[e["testo"]] = ", ".join(motivi)

    guide, audio, indice, totale, da_sentire = [], [], [], 0.0, []
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
                dubbio = dubbi.get(f["testo"])
                if dubbio:
                    da_sentire.append(f'<a href="#f{g}-{n}">{g}.{n}</a> ({html.escape(dubbio)})')
                righe.append(
                    f'<li><button class="frase{" dubbia" if dubbio else ""}" type="button" id="f{g}-{n}" data-g="{g}" data-n="{g}.{n}">'
                    f'<span class="n">{g}.{n}</span><span class="t">{html.escape(f["testo"])}'
                    + (f' <span class="dubbio">{html.escape(dubbio)}</span>' if dubbio else "")
                    + "</span></button></li>"
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
    if args.rapporto:
        controllo = (
            "Io non posso sentirle. Un riconoscitore vocale ha riascoltato ogni frase e l'altezza della voce è stata misurata: le frasi su cui "
            "resta un dubbio sono segnate. Accenti, intonazione e parole inglesi li giudica solo l'orecchio: sono quelli i punti dove vale la pena fare attenzione."
        )
    else:
        controllo = (
            "Io non posso sentirle, e su questa pagina non c'è l'esito di un riascolto automatico: parole, accenti, intonazione "
            "e parole inglesi li giudica solo l'orecchio."
        )
    if not args.frammento:
        # Aperta dal disco la pagina deve reggersi da sola: tipo di documento, lingua, codifica e larghezza per i telefoni.
        testa, corpo = pagina.split("</style>\n", 1)
        pagina = (
            '<!doctype html>\n<html lang="it">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            + testa + "</style>\n</head>\n<body>\n" + corpo + "</body>\n</html>\n"
        )
    campi = {
        "@@CARATTERI@@": CARATTERI if args.frammento else "",
        "@@CONTROLLO@@": controllo,
        "@@VIDEOGUIDE@@": str(len(video)),
        "@@VOCE@@": html.escape(voce.get("nome", "")),
        "@@FRASI@@": str(len(frasi)),
        "@@MINUTI@@": str(round(totale / 60000)),
        "@@INDICE@@": "".join(indice),
        "@@GUIDE@@": "\n".join(guide),
        "@@AUDIO@@": json.dumps(audio),
        "@@DUBBIE@@": (
            '<p class="dubbie"><b>Da ascoltare per prime.</b> I controlli automatici hanno un dubbio su: ' + "; ".join(da_sentire) + ". Non è detto che siano sbagliate.</p>"
            if da_sentire
            else ""
        ),
    }
    for k, val in campi.items():
        pagina = pagina.replace(k, val)
    args.uscita.write_text(pagina, encoding="utf-8")
    print(f"{args.uscita}: {len(pagina) / 1e6:.1f} MB, {len(audio)} frasi, {len(video)} videoguide, {totale / 60000:.1f} minuti")


if __name__ == "__main__":
    main()
