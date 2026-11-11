#!/usr/bin/env python3
"""Crea una voce nuova da una descrizione a parole (Qwen3-TTS VoiceDesign).

Il modello legge una frase di prova con la voce descritta in voci/voci.json e
il risultato diventa il campione di riferimento voci/<nome>.flac: genera.py lo
usa poi con il modello Base per leggere tutta la narrazione con quella voce.

    python scripts/narrazione/disegna.py --modello Qwen3-TTS-12Hz-1.7B-VoiceDesign giulia

La voce nasce dalla descrizione: non imita nessuna persona reale, e nelle
descrizioni non vanno messi nomi di persone. Il campione è la voce: con
un'altra versione del modello o delle librerie la stessa descrizione dà una
voce diversa, quindi un campione esistente non viene riscritto (a meno di
--sovrascrivi) e va tenuto nel repository finché la voce è in uso.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

import numpy as np

QUI = Path(__file__).resolve().parent / "voci"


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("voci", nargs="*", help="nomi in voci.json (tutti quelli senza campione, se non ne indichi)")
    p.add_argument("--modello", required=True, help="cartella del modello Qwen3-TTS VoiceDesign")
    p.add_argument("--processi", type=int, default=4)
    p.add_argument("--sovrascrivi", action="store_true", help="rifà anche i campioni che esistono già: la voce cambia")
    args = p.parse_args()

    scheda = json.loads((QUI / "voci.json").read_text(encoding="utf-8"))
    nomi = args.voci or [n for n in scheda["voci"] if not (QUI / f"{n}.flac").exists()]
    sconosciute = [n for n in nomi if n not in scheda["voci"]]
    if sconosciute:
        raise SystemExit(f"voci non descritte in voci.json: {', '.join(sconosciute)}")
    if not nomi:
        raise SystemExit("ogni voce descritta ha già il suo campione")

    import torch
    from qwen_tts import Qwen3TTSModel

    torch.set_num_threads(args.processi)
    m = Qwen3TTSModel.from_pretrained(args.modello, device_map="cpu", dtype=torch.float32)
    for nome in nomi:
        file = QUI / f"{nome}.flac"
        if file.exists() and not args.sovrascrivi:
            print(f"{nome}: il campione esiste già, lo lascio com'è")
            continue
        torch.manual_seed(scheda["seme"])
        t0 = time.time()
        wavs, sr = m.generate_voice_design(text=scheda["testo"], language="Italian", instruct=scheda["voci"][nome])
        a = np.clip(np.asarray(wavs[0], dtype=np.float32), -1.0, 1.0)
        # FLAC a 16 bit: senza perdita, e pesa la metà di un WAV.
        cmd = [
            "ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
            "-f", "f32le", "-ar", str(sr), "-ac", "1", "-i", "pipe:0",
            "-c:a", "flac", "-sample_fmt", "s16", "-compression_level", "8",
            "-map_metadata", "-1", "-fflags", "+bitexact", "-flags:a", "+bitexact",
            str(file),
        ]  # fmt: skip
        subprocess.run(cmd, input=a.astype("<f4").tobytes(), check=True)
        print(f"{nome}: {len(a) / sr:.1f} s di campione in {time.time() - t0:.0f} s", flush=True)


if __name__ == "__main__":
    main()
