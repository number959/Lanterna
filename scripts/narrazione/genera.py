#!/usr/bin/env python3
"""Registra la narrazione delle videoguide con una voce neurale.

Per ogni frase di core/src/guides/video.ts produce una registrazione Ogg Opus
in core/src/guides/narrazione/ e riscrive l'indice core/src/guides/narrazione.ts
(dal testo della frase al file e alla durata). Le registrazioni finiscono nel
programma: chi lo usa non ha bisogno di questo script né di una voce installata.

Si lancia a mano quando cambia il testo di una videoguida o si cambia voce:

    node scripts/narrazione/frasi.mjs frasi.json
    python scripts/narrazione/genera.py --frasi frasi.json --motore piper \
        --modello it_IT-serena-high.onnx --nome Serena --licenza "..."

Con --solo-mancanti rifà soltanto le frasi nuove o cambiate (stessa voce).
Con --rifai "parole" rifà anche le frasi che contengono quelle parole.
Con --fonemi stampa i fonemi di ogni frase senza registrare nulla (solo Piper):
serve a controllare le pronunce di sigle e parole inglesi, vedi pronuncia.py.

Con --riascolta non registra nulla: riascolta le registrazioni che ci sono già
(quelle che finiscono nel programma) e dice quali non tornano.

I motori che campionano cambiano anche registro da una frase all'altra: una
calma e grave, la successiva acuta e concitata. Per questo, per quei motori,
di ogni presa si misura l'altezza della voce e le frasi che si staccano dalle
altre per più del 10% vengono rifatte come quelle con le parole sbagliate
(--tolleranza per cambiare il margine, --altezza per fissare l'altezza voluta,
--senza-altezza per rinunciare). Con --solo-mancanti --ricontrolla passano di
nuovo dall'esame anche le registrazioni già fatte.

Con --verifica ogni registrazione viene riascoltata da un riconoscitore vocale
(Whisper): se le parole capite si scostano da quelle scritte, la frase viene
rifatta con un altro seme e si tiene la presa migliore. Vale per i motori che
campionano (Qwen3-TTS), che ogni tanto saltano o storpiano una parola; per gli
altri la verifica segnala soltanto. Il riconoscitore sbaglia a sua volta su
sigle e parole inglesi: le frasi segnalate alla fine vanno riascoltate, non
sono per forza sbagliate.

Serve ffmpeg con libopus. I motori si installano a parte, in un ambiente
virtuale (vedi LEGGIMI.md in questa cartella): non sono dipendenze del
programma e non entrano nel pacchetto.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import unicodedata
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pronuncia import numeri_in_lettere, parlato, parlato_llm  # noqa: E402

RADICE = Path(__file__).resolve().parents[2]
CARTELLA = RADICE / "core" / "src" / "guides" / "narrazione"
INDICE = RADICE / "core" / "src" / "guides" / "narrazione.ts"


# ---------------------------------------------------------------- motori


class Piper:
    """Voci Piper (VITS, fonemi da espeak-ng): veloci, pronuncia controllabile dai fonemi."""

    casuale = False

    def __init__(self, args):
        from piper import PiperVoice

        self.v = PiperVoice.load(args.modello)
        self.sr = self.v.config.sample_rate

    def fonemi(self, testo: str) -> str:
        return " ".join("".join(p) for p in self.v.phonemize(parlato(testo)))

    def leggi(self, testi: list[str], seme: int) -> list[np.ndarray]:
        return [np.concatenate([c.audio_float_array for c in self.v.synthesize(parlato(t))]) for t in testi]


class Kokoro:
    """Kokoro-82M (ONNX): voci if_sara e im_nicola per l'italiano."""

    casuale = False

    def __init__(self, args):
        from kokoro_onnx import Kokoro as K

        modello = Path(args.modello)
        self.k = K(str(modello), str(modello.with_name("voices-v1.0.bin")))
        self.voce = args.voce or "if_sara"
        self.sr = 24000

    def leggi(self, testi: list[str], seme: int) -> list[np.ndarray]:
        audio = []
        for t in testi:
            a, self.sr = self.k.create(parlato(t), voice=self.voce, speed=1.0, lang="it")
            audio.append(a)
        return audio


class Qwen:
    """Qwen3-TTS: una voce predefinita (CustomVoice) oppure una voce clonata da un campione (Base)."""

    casuale = True

    def __init__(self, args):
        import torch
        from qwen_tts import Qwen3TTSModel

        self.torch = torch
        torch.set_num_threads(args.processi)
        self.m = Qwen3TTSModel.from_pretrained(args.modello, device_map="cpu", dtype=torch.float32)
        self.voce = args.voce
        self.prompt = None
        if args.riferimento:
            if not args.testo_riferimento:
                raise SystemExit("--riferimento chiede anche --testo-riferimento (le parole dette nel campione)")
            self.prompt = self.m.create_voice_clone_prompt(ref_audio=args.riferimento, ref_text=args.testo_riferimento)
        elif not self.voce:
            raise SystemExit("con --motore qwen serve --voce (voce predefinita) oppure --riferimento (campione da clonare)")
        self.sr = 24000

    def leggi(self, testi: list[str], seme: int) -> list[np.ndarray]:
        # Il campionamento è casuale: un seme per lotto rende la registrazione ripetibile.
        self.torch.manual_seed(seme)
        detti = [parlato_llm(t) for t in testi]
        lingue = ["Italian"] * len(testi)
        # Un tetto alla lunghezza: il modello produce 12,5 passi al secondo e, quando si perde, andrebbe avanti
        # per minuti. Oltre 150 ms per carattere detto (più due secondi) la presa è comunque da buttare.
        tetto = int(1.9 * max(len(d) for d in detti)) + 25
        if self.prompt is not None:
            wavs, self.sr = self.m.generate_voice_clone(text=detti, language=lingue, voice_clone_prompt=self.prompt, max_new_tokens=tetto)
        else:
            wavs, self.sr = self.m.generate_custom_voice(text=detti, language=lingue, speaker=[self.voce] * len(testi), max_new_tokens=tetto)
        return [np.asarray(w, dtype=np.float32) for w in wavs]


MOTORI = {"piper": Piper, "kokoro": Kokoro, "qwen": Qwen}


# ---------------------------------------------------------------- audio


def rifinisci(a: np.ndarray, sr: int) -> np.ndarray:
    """Toglie il silenzio in testa e in coda, porta tutte le frasi allo stesso volume, sfuma gli estremi."""
    a = np.asarray(a, dtype=np.float32).reshape(-1)
    passo = max(1, int(sr * 0.01))
    inviluppo = np.convolve(np.abs(a), np.ones(passo, dtype=np.float32) / passo, mode="same")
    voce = np.nonzero(inviluppo > 10 ** (-45 / 20))[0]
    if len(voce):
        a = a[max(0, voce[0] - int(0.04 * sr)) : min(len(a), voce[-1] + int(0.12 * sr))]
    efficace = float(np.sqrt(np.mean(a**2))) or 1e-9
    guadagno = 10 ** (-20 / 20) / efficace
    picco = float(np.max(np.abs(a))) * guadagno
    tetto = 10 ** (-1.5 / 20)
    if picco > tetto:
        guadagno *= tetto / picco
    a = a * guadagno
    n = min(len(a) // 2, int(0.008 * sr))
    if n > 1:
        rampa = np.linspace(0.0, 1.0, n, dtype=np.float32)
        a[:n] *= rampa
        a[-n:] *= rampa[::-1]
    return a.astype(np.float32)


def codifica(a: np.ndarray, sr: int, file: Path, kbit: int) -> None:
    """Ogg Opus mono: a 32 kbit/s la voce resta pulita e un minuto pesa circa 240 kB."""
    cmd = [
        "ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
        "-f", "f32le", "-ar", str(sr), "-ac", "1", "-i", "pipe:0",
        "-c:a", "libopus", "-b:a", f"{kbit}k", "-vbr", "on", "-application", "audio",
        "-map_metadata", "-1", "-fflags", "+bitexact", "-flags:a", "+bitexact",
        str(file),
    ]  # fmt: skip
    subprocess.run(cmd, input=a.astype("<f4").tobytes(), check=True)


def altezza(a: np.ndarray, sr: int) -> float:
    """Altezza mediana della voce in hertz, sui tratti in cui la voce c'è (0 se non si riesce a misurare)."""
    import librosa

    passo = max(1, sr // 50)
    f0 = librosa.yin(a.astype(np.float32), fmin=60, fmax=500, sr=sr, frame_length=passo * 4, hop_length=passo)
    liv = librosa.feature.rms(y=a, frame_length=passo * 4, hop_length=passo)[0]
    n = min(len(f0), len(liv))
    f0, liv = f0[:n], liv[:n]
    if not np.any(liv > 0):
        return 0.0
    buoni = f0[liv > 0.5 * np.median(liv[liv > 0])]
    buoni = buoni[(buoni > 65) & (buoni < 480)]
    return float(np.median(buoni)) if len(buoni) else 0.0


def carica(file: Path, sr: int) -> np.ndarray:
    """Una registrazione così com'è nel programma, come campioni a virgola mobile."""
    cmd = ["ffmpeg", "-hide_banner", "-loglevel", "error", "-i", str(file), "-f", "f32le", "-ar", str(sr), "-ac", "1", "pipe:1"]
    return np.frombuffer(subprocess.run(cmd, capture_output=True, check=True).stdout, dtype="<f4")


# ---------------------------------------------------------------- verifica


class Ascolto:
    """Riascolta una registrazione con Whisper e restituisce le parole capite."""

    def __init__(self, modello: str, cartella: str | None, processi: int):
        from faster_whisper import WhisperModel

        self.m = WhisperModel(modello, device="cpu", compute_type="int8", download_root=cartella, cpu_threads=processi)

    def trascrivi(self, a: np.ndarray, sr: int) -> str:
        # Il riconoscitore vuole 16 kHz: la conversione la fa ffmpeg, che serve comunque.
        cmd = [
            "ffmpeg", "-hide_banner", "-loglevel", "error",
            "-f", "f32le", "-ar", str(sr), "-ac", "1", "-i", "pipe:0",
            "-f", "f32le", "-ar", "16000", "-ac", "1", "pipe:1",
        ]  # fmt: skip
        r = subprocess.run(cmd, input=a.astype("<f4").tobytes(), capture_output=True, check=True)
        return self._capisci(r.stdout)

    def trascrivi_file(self, file: Path) -> str:
        """Riascolta una registrazione così com'è nel programma (Ogg Opus)."""
        return self._capisci(carica(file, 16000).tobytes())

    def _capisci(self, pcm: bytes) -> str:
        parti, _ = self.m.transcribe(np.frombuffer(pcm, dtype="<f4"), language="it", beam_size=5, condition_on_previous_text=False)
        return " ".join(x.text.strip() for x in parti)


def _piatto(s: str) -> str:
    """Solo lettere e cifre, senza accenti né spazi: «Wi-Fi», «wifi» e «wi fi» diventano uguali."""
    s = unicodedata.normalize("NFD", s.lower())
    return re.sub(r"[^a-z0-9]", "", "".join(c for c in s if unicodedata.category(c) != "Mn"))


# Il riconoscitore scrive volentieri le unità di misura abbreviate («100 GB» per «cento gigabyte»): non è un errore di lettura.
# Maiuscole e minuscole contano dove distinguono due unità (MB/s è megabyte, Mb/s è megabit).
_ABBREVIATE = [
    (r"\bMB/s\b", "megabyte al secondo"), (r"\bGB/s\b", "gigabyte al secondo"),
    (r"\b(?:Mbps|Mbit/s|Mb/s)\b", "megabit al secondo"), (r"\b(?:Gbps|Gbit/s|Gb/s)\b", "gigabit al secondo"),
    (r"\b[Gg][Bb]\b", "gigabyte"), (r"\b[Mm][Bb]\b", "megabyte"), (r"\b[Kk][Bb]\b", "kilobyte"), (r"\b[Tt][Bb]\b", "terabyte"),
    (r"\b[Gg][Hh]z\b", "gigahertz"), (r"\b[Mm][Hh]z\b", "megahertz"), (r"\b[Kk][Hh]z\b", "kilohertz"), (r"\b[Hh]z\b", "hertz"),
    (r"\bd[Bb]m\b", "decibel milliwatt"), (r"\bd[Bb]\b", "decibel"), (r"\bms\b", "millisecondi"), (r"%", " per cento"),
]  # fmt: skip


def _per_esteso(capito: str) -> str:
    for rx, parole in _ABBREVIATE:
        capito = re.sub(rx, parole, capito)
    return capito


def _distanza(a: str, b: str) -> int:
    """Quanti caratteri vanno cambiati, tolti o aggiunti per passare da a a b."""
    riga = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        nuova = [i]
        for j, cb in enumerate(b, 1):
            nuova.append(min(riga[j] + 1, nuova[j - 1] + 1, riga[j - 1] + (ca != cb)))
        riga = nuova
    return riga[-1]


def scarto(testo: str, capito: str) -> float:
    """Quota di caratteri che non tornano tra la frase scritta e quella capita (0 = identiche).

    Il riconoscitore può scrivere «169.254» o «centosessantanove punto...», «VLAN» o «vi lan»:
    si confronta con la frase com'è scritta, con i numeri in lettere e con la forma detta, e vale il confronto migliore.
    """
    capite = {_piatto(capito), _piatto(_per_esteso(capito))}
    forme = {_piatto(testo), _piatto(numeri_in_lettere(testo)), _piatto(parlato_llm(testo))}
    return min(_distanza(f, c) / max(1, len(f)) for f in forme for c in capite)


# ---------------------------------------------------------------- indice


def leggi_indice(indice: Path) -> tuple[dict, dict]:
    """Voce e frasi dell'indice esistente (vuoti se non c'è ancora)."""
    if not indice.exists():
        return {}, {}
    testo = indice.read_text(encoding="utf-8")
    voce = re.search(r"export const VOCE[^=]*= (\{.*?\});", testo, re.S)
    clip = re.search(r"export const CLIP[^=]*= (\{.*\});", testo, re.S)
    try:
        return (json.loads(voce.group(1)) if voce else {}), (json.loads(clip.group(1)) if clip else {})
    except json.JSONDecodeError:
        return {}, {}


def segnala(esiti: list[dict], soglia: float) -> None:
    """Le frasi in cui il riconoscitore ha capito altro: da riascoltare con le proprie orecchie."""
    dubbie = [e for e in esiti if e["scarto"] > soglia]
    if not dubbie:
        return
    print(f"\nDa riascoltare ({len(dubbie)}): il riconoscitore ha capito altro, oppure la durata è fuori misura.")
    for e in sorted(dubbie, key=lambda e: -e["scarto"]):
        print(f"  {100 * e['scarto']:3.0f}%  {e['testo']}\n        capito: {e['capito']}")


def segnala_registro(esiti: list[dict], obiettivo: float | None, tolleranza: float) -> None:
    """Le frasi in cui la voce è più acuta o più grave delle altre, oltre la tolleranza."""
    misurate = [e for e in esiti if e.get("hz")]
    if not obiettivo or not misurate:
        return
    hz = [e["hz"] for e in misurate]
    lontane = [e for e in misurate if abs(e["hz"] / obiettivo - 1) > tolleranza]
    print(f"\nAltezza della voce: mediana {np.median(hz):.0f} Hz, da {min(hz):.0f} a {max(hz):.0f}; riferimento {obiettivo:.0f} Hz; "
          f"{len(misurate) - len(lontane)} frasi su {len(misurate)} entro il {100 * tolleranza:.0f}%.")
    for e in sorted(lontane, key=lambda e: -abs(e["hz"] / obiettivo - 1)):
        print(f"  {e['hz']:3.0f} Hz ({100 * (e['hz'] / obiettivo - 1):+.0f}%)  {e['testo']}")


def riascolta(args, frasi: list[str]) -> None:
    """Riascolta le registrazioni esistenti senza rifarne nessuna."""
    voce, clip = leggi_indice(args.indice)
    ascolto = Ascolto(args.verifica or "small", args.cartella_verifica, args.processi)
    esiti = []
    for i, testo in enumerate(frasi):
        if testo not in clip:
            esiti.append({"testo": testo, "capito": "(manca la registrazione)", "scarto": 1.0})
            continue
        file = args.cartella / clip[testo]["file"]
        capito = ascolto.trascrivi_file(file)
        s = scarto(testo, capito) + (0.0 if 35 < clip[testo]["ms"] / len(testo) < 140 else 1.0)
        hz = 0.0 if args.senza_altezza else round(altezza(carica(file, 24000), 24000), 1)
        esiti.append({"testo": testo, "capito": capito, "scarto": round(s, 3), "hz": hz})
        print(f"[{i + 1}/{len(frasi)}] scarto {100 * s:3.0f}%  {hz:3.0f} Hz  {testo[:70]}", flush=True)
    uguali = sum(e["scarto"] == 0 for e in esiti)
    entro = sum(e["scarto"] <= args.soglia for e in esiti)
    print(f"\nVoce {voce.get('nome', '?')}: {len(esiti)} frasi, {uguali} capite identiche, {entro} entro la soglia del {100 * args.soglia:.0f}%.")
    misurate = [e["hz"] for e in esiti if e.get("hz")]
    obiettivo = args.altezza or (float(np.median(misurate)) if misurate else None)
    if args.rapporto:
        Path(args.rapporto).write_text(json.dumps(esiti, ensure_ascii=False, indent=1), encoding="utf-8")
    segnala(esiti, args.soglia)
    segnala_registro(esiti, obiettivo, args.tolleranza)


def scrivi_indice(indice: Path, voce: dict, clip: dict) -> None:
    righe = [
        "// File generato da scripts/narrazione/genera.py: non modificare a mano.",
        "// Le registrazioni della narrazione delle videoguide (una per frase) stanno in",
        "// src/guides/narrazione/; qui c'è l'indice dal testo della frase al file.",
        "",
        "export interface VoceRegistrata {",
        "  /** Nome mostrato nel lettore. */",
        "  nome: string;",
        "  /** Motore di sintesi e modello con cui è stata generata. */",
        "  motore: string;",
        "  modello: string;",
        "  /** Licenza del modello e attribuzione dovuta. */",
        "  licenza: string;",
        "}",
        "",
        f"export const VOCE: VoceRegistrata | undefined = {json.dumps(voce, ensure_ascii=False, indent=2)};",
        "",
        "/** Per ogni frase registrata: il file e la durata in millisecondi. */",
        f"export const CLIP: Record<string, {{ file: string; ms: number }}> = {json.dumps(clip, ensure_ascii=False, indent=2)};",
        "",
    ]
    indice.write_text("\n".join(righe), encoding="utf-8")


# ---------------------------------------------------------------- principale


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--frasi", required=True, help="JSON scritto da frasi.mjs")
    p.add_argument("--motore", choices=sorted(MOTORI))
    p.add_argument("--modello", help="file .onnx (Piper, Kokoro) o cartella del modello (Qwen3-TTS)")
    p.add_argument("--voce", help="Kokoro: if_sara, im_nicola; Qwen3-TTS CustomVoice: Serena, Ryan...")
    p.add_argument("--riferimento", help="Qwen3-TTS Base: campione WAV della voce da clonare")
    p.add_argument("--testo-riferimento", help="le parole dette nel campione")
    p.add_argument("--nome", help="nome della voce mostrato nel lettore")
    p.add_argument("--licenza", default="", help="licenza del modello e attribuzione, per l'indice")
    p.add_argument("--kbit", type=int, default=32)
    p.add_argument("--cartella", type=Path, default=CARTELLA, help="dove scrivere le registrazioni (per le prove)")
    p.add_argument("--indice", type=Path, default=INDICE, help="dove scrivere l'indice (per le prove)")
    p.add_argument("--processi", type=int, default=4, help="processori da usare (Qwen3-TTS, Whisper)")
    p.add_argument("--lotto", type=int, default=1, help="frasi lette insieme (Qwen3-TTS): 4 quasi dimezza i tempi, ma servono circa 9 GB di memoria")
    p.add_argument("--solo-mancanti", action="store_true", help="non rifare le frasi già registrate con questa voce")
    p.add_argument("--rifai", action="append", default=[], metavar="PAROLE", help="con --solo-mancanti: rifà anche le frasi che contengono queste parole (ripetibile)")
    p.add_argument("--seme", type=int, default=0, help="cambia la presa dei motori che campionano (0 = la prima)")
    p.add_argument("--verifica", metavar="MODELLO", help="riascolta ogni registrazione con Whisper (es. small) e rifà quelle che non tornano")
    p.add_argument("--cartella-verifica", metavar="DIR", help="dove tenere il modello di Whisper")
    p.add_argument("--tentativi", type=int, default=3, help="prese al massimo per frase, per i motori che campionano")
    p.add_argument("--soglia", type=float, default=0.04, help="scarto accettato subito tra frase scritta e frase capita")
    p.add_argument("--rapporto", metavar="FILE", help="scrive qui l'esito della verifica, frase per frase (JSON)")
    p.add_argument("--altezza", type=float, metavar="HZ", help="altezza della voce voluta (senza: la mediana delle registrazioni)")
    p.add_argument("--tolleranza", type=float, default=0.10, help="quanto una frase può staccarsi dall'altezza delle altre prima di essere rifatta")
    p.add_argument("--senza-altezza", action="store_true", help="non misura l'altezza della voce e non rifà le frasi fuori registro")
    p.add_argument("--ricontrolla", action="store_true", help="con --solo-mancanti: rimette all'esame anche le registrazioni già fatte")
    p.add_argument("--fonemi", action="store_true", help="stampa i fonemi di ogni frase e basta (Piper)")
    p.add_argument("--riascolta", action="store_true", help="non registra: riascolta con Whisper le registrazioni che ci sono già")
    args = p.parse_args()

    frasi = [x["testo"] for x in json.loads(Path(args.frasi).read_text(encoding="utf-8"))]
    if args.riascolta:
        riascolta(args, frasi)
        return
    if not args.motore or not args.modello:
        p.error("servono --motore e --modello")
    motore = MOTORI[args.motore](args)

    if args.fonemi:
        if not hasattr(motore, "fonemi"):
            raise SystemExit("--fonemi vale solo per Piper")
        for t in frasi:
            print(t)
            print("   ", motore.fonemi(t))
        return

    modello = Path(args.modello).name
    voce = {
        "nome": args.nome or args.voce or Path(args.modello).stem,
        "motore": {"piper": "Piper", "kokoro": "Kokoro-82M", "qwen": "Qwen3-TTS"}[args.motore],
        "modello": modello + (f", voce {args.voce}" if args.voce else "") + (f", voce di riferimento {Path(args.riferimento).name}" if args.riferimento else ""),
        "licenza": args.licenza,
    }
    chiave = f"{args.motore}|{modello}|{args.voce or ''}|{Path(args.riferimento).name if args.riferimento else ''}"
    vecchia, vecchie = leggi_indice(args.indice)
    stessa = args.solo_mancanti and vecchia.get("motore") == voce["motore"] and vecchia.get("modello") == voce["modello"]

    ascolto = Ascolto(args.verifica, args.cartella_verifica, args.processi) if args.verifica else None
    # L'altezza della voce si tiene d'occhio solo con i motori che campionano: gli altri non cambiano registro.
    registro = motore.casuale and not args.senza_altezza
    prese = args.tentativi if motore.casuale and (ascolto or registro) else 1
    obiettivo = args.altezza

    def fuori(e: dict) -> float:
        """Quanto la frase esce dal registro delle altre, oltre la tolleranza (0 = dentro)."""
        if not obiettivo or not e.get("hz"):
            return 0.0
        return max(0.0, abs(e["hz"] / obiettivo - 1) - args.tolleranza)

    def voto(e: dict) -> float:
        return e["scarto"] + fuori(e)

    def passa(e: dict) -> bool:
        return e["scarto"] <= args.soglia and fuori(e) == 0

    args.cartella.mkdir(parents=True, exist_ok=True)
    clip: dict[str, dict] = {}
    esiti: dict[str, dict] = {}
    coda: list[tuple[str, Path]] = []
    for testo in frasi:
        nome = hashlib.sha1(f"{chiave}|{testo}".encode("utf-8")).hexdigest()[:12] + ".ogg"
        file = args.cartella / nome
        da_rifare = any(r.lower() in testo.lower() for r in args.rifai)
        if stessa and not da_rifare and testo in vecchie and vecchie[testo]["file"] == nome and file.exists():
            clip[testo] = vecchie[testo]
            # Le registrazioni tenute dicono qual è il registro della voce; con --ricontrolla tornano anche all'esame.
            if registro or args.ricontrolla:
                e = {"testo": testo, "capito": "", "scarto": 0.0, "hz": 0.0, "tenuta": 0, "prese": 0, "gia": True}
                if registro:
                    e["hz"] = round(altezza(carica(file, 24000), 24000), 1)
                if args.ricontrolla and ascolto:
                    e["capito"] = ascolto.trascrivi_file(file)
                    e["scarto"] = round(scarto(testo, e["capito"]) + (0.0 if 35 < clip[testo]["ms"] / len(testo) < 140 else 1.0), 3)
                esiti[testo] = e
        else:
            coda.append((testo, file))

    def mediana_altezze() -> float | None:
        valori = [e["hz"] for e in esiti.values() if e.get("hz")]
        # Con meno di tre frasi non c'è un registro da cui staccarsi.
        return float(np.median(valori)) if len(valori) >= 3 else None

    if registro and not obiettivo:
        obiettivo = mediana_altezze()
    if obiettivo:
        print(f"Altezza della voce: {obiettivo:.0f} Hz, con il {100 * args.tolleranza:.0f}% di margine", flush=True)
    if args.ricontrolla:
        file_di = {t: args.cartella / clip[t]["file"] for t in clip}
        coda += [(t, file_di[t]) for t, e in esiti.items() if e.get("gia") and not passa(e)]
        print(f"Registrazioni già fatte da rifare: {sum(1 for t, e in esiti.items() if e.get('gia') and not passa(e))}", flush=True)

    # Nei lotti stanno insieme frasi di lunghezza simile: il lotto dura quanto la sua frase più lunga.
    coda.sort(key=lambda x: len(x[0]))
    for k in range(prese):
        fatte = 0
        for j in range(0, len(coda), max(1, args.lotto)):
            gruppo = coda[j : j + max(1, args.lotto)]
            seme = (int(hashlib.sha1(gruppo[0][0].encode("utf-8")).hexdigest()[:8], 16) + 104729 * args.seme + 7919 * k) % 2**31
            for (testo, file), a in zip(gruppo, motore.leggi([t for t, _ in gruppo], seme)):
                a = rifinisci(a, motore.sr)
                ms = round(1000 * len(a) / motore.sr)
                capito, s = "", 0.0
                if ascolto:
                    capito = ascolto.trascrivi(a, motore.sr)
                    s = scarto(testo, capito)
                # Una durata fuori misura dice che la frase è tagliata o ha parole in più: vale come presa sbagliata.
                if not 35 < ms / len(testo) < 140:
                    s += 1.0
                prima = esiti.get(testo)
                nuova = {"testo": testo, "capito": capito, "scarto": round(s, 3), "hz": round(altezza(a, motore.sr), 1) if registro else 0.0}
                nuova["prese"] = (prima["prese"] if prima else 0) + 1
                nuova["tenuta"] = nuova["prese"]
                if prima is None or voto(nuova) < voto(prima):
                    codifica(a, motore.sr, file, args.kbit)
                    clip[testo] = {"file": file.name, "ms": ms}
                    esiti[testo] = nuova
                else:
                    prima["prese"] = nuova["prese"]
                fatte += 1
                nota = (f"  scarto {100 * s:3.0f}%" if ascolto else "") + (f"  {nuova['hz']:3.0f} Hz" if registro else "")
                print(f"[presa {k + 1}, {fatte}/{len(coda)}] {ms / 1000:5.1f} s{nota}  {testo[:70]}", flush=True)
            # L'indice si aggiorna a ogni lotto: una registrazione lunga interrotta riparte con --solo-mancanti.
            scrivi_indice(args.indice, voce, {t: clip[t] for t in frasi if t in clip})
        # Il registro della voce si conosce dopo la prima passata: è la mediana di tutte le frasi.
        if registro and not obiettivo:
            obiettivo = mediana_altezze()
            if obiettivo:
                print(f"Altezza della voce: {obiettivo:.0f} Hz, con il {100 * args.tolleranza:.0f}% di margine", flush=True)
        coda = [x for x in coda if not passa(esiti[x[0]])]
        if not coda:
            break

    clip = {t: clip[t] for t in frasi}
    totale = sum(c["ms"] for c in clip.values()) / 1000

    # Le registrazioni di frasi che non esistono più (o di un'altra voce) si tolgono.
    tenuti = {c["file"] for c in clip.values()}
    for f in args.cartella.glob("*.ogg"):
        if f.name not in tenuti:
            f.unlink()
    scrivi_indice(args.indice, voce, clip)
    peso = sum(f.stat().st_size for f in args.cartella.glob("*.ogg"))
    print(f"{len(clip)} frasi, {totale / 60:.1f} minuti, {peso / 1e6:.1f} MB in {args.cartella}")
    esiti = [esiti[t] for t in frasi if t in esiti]
    for e in esiti:
        e.pop("gia", None)
        e["fuori"] = round(fuori(e), 3)
    if args.rapporto:
        Path(args.rapporto).write_text(json.dumps(esiti, ensure_ascii=False, indent=1), encoding="utf-8")
    if ascolto:
        segnala(esiti, args.soglia)
    segnala_registro(esiti, obiettivo, args.tolleranza)


if __name__ == "__main__":
    main()
