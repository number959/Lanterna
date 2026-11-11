#!/usr/bin/env python3
"""Controlli sul suono delle registrazioni, senza riconoscitore vocale.

Per ogni registrazione misura ritmo (durata per carattere detto), volume, picchi, pause
interne e altezza della voce, e segnala quelle che si staccano dalle altre:
una frase molto più lenta o più veloce, una pausa lunga in mezzo, una voce
più acuta o più grave del resto (con i motori che campionano, ogni tanto la
voce "scivola"). Con --modello (Qwen3-TTS Base) confronta anche l'impronta
della voce di ogni registrazione con quella delle altre.

    python scripts/narrazione/controlla.py --frasi frasi.json [--modello M/Qwen3-TTS-12Hz-0.6B-Base]

Segnala, non giudica: le registrazioni elencate vanno riascoltate.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from genera import CARTELLA, INDICE, altezza, carica, leggi_indice  # noqa: E402
from pronuncia import parlato_llm  # noqa: E402

SR = 24000


def pausa_piu_lunga(a: np.ndarray) -> float:
    """La pausa interna più lunga, in secondi (sotto -40 dBFS, esclusi testa e coda)."""
    passo = int(SR * 0.01)
    n = len(a) // passo
    if n < 3:
        return 0.0
    liv = np.sqrt(np.mean(a[: n * passo].reshape(n, passo) ** 2, axis=1))
    zitto = liv < 10 ** (-40 / 20)
    voce = np.nonzero(~zitto)[0]
    if len(voce) < 2:
        return 0.0
    lunga = corrente = 0
    for z in zitto[voce[0] : voce[-1] + 1]:
        corrente = corrente + 1 if z else 0
        lunga = max(lunga, corrente)
    return lunga * 0.01


def scostamento(v: np.ndarray) -> np.ndarray:
    """Quante deviazioni (robuste) ogni valore dista dalla mediana."""
    med = np.median(v)
    mad = np.median(np.abs(v - med)) * 1.4826 or 1e-9
    return (v - med) / mad


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--frasi", required=True, help="JSON scritto da frasi.mjs")
    p.add_argument("--cartella", type=Path, default=CARTELLA)
    p.add_argument("--indice", type=Path, default=INDICE)
    p.add_argument("--modello", help="cartella di Qwen3-TTS Base: confronta anche l'impronta della voce")
    p.add_argument("--processi", type=int, default=4)
    p.add_argument("--rapporto", metavar="FILE", help="scrive qui le misure, frase per frase (JSON)")
    args = p.parse_args()

    frasi = [x["testo"] for x in json.loads(Path(args.frasi).read_text(encoding="utf-8"))]
    voce, clip = leggi_indice(args.indice)
    mancanti = [t for t in frasi if t not in clip]
    if mancanti:
        raise SystemExit(f"{len(mancanti)} frasi senza registrazione: prima genera.py")

    righe = []
    for t in frasi:
        a = carica(args.cartella / clip[t]["file"], SR)
        righe.append({
            "testo": t,
            "file": clip[t]["file"],
            # Il ritmo si misura sulla frase com'è detta: «169.254» scritto è corto, detto è lungo.
            "ms_car": 1000 * len(a) / SR / len(parlato_llm(t)),
            "picco": float(np.max(np.abs(a))),
            "volume": 20 * np.log10(float(np.sqrt(np.mean(a**2))) + 1e-9),
            "pausa": pausa_piu_lunga(a),
            "altezza": altezza(a, SR),
        })  # fmt: skip

    if args.modello:
        import torch
        from qwen_tts import Qwen3TTSModel

        torch.set_num_threads(args.processi)
        m = Qwen3TTSModel.from_pretrained(args.modello, device_map="cpu", dtype=torch.float32)
        impronte = []
        for r in righe:
            voce_clip = m.create_voice_clone_prompt(ref_audio=(carica(args.cartella / r["file"], SR), SR), x_vector_only_mode=True)[0]
            e = voce_clip.ref_spk_embedding.detach().float().reshape(-1)
            impronte.append(e / (e.norm() + 1e-9))
        centro = torch.stack(impronte).mean(dim=0)
        centro = centro / centro.norm()
        for r, e in zip(righe, impronte):
            r["somiglianza"] = float(e @ centro)

    def colonna(k: str) -> np.ndarray:
        return np.array([r[k] for r in righe])

    segnalate: dict[str, list[str]] = {}

    def segna(i: int, motivo: str) -> None:
        segnalate.setdefault(righe[i]["testo"], []).append(motivo)

    z_ritmo, z_alt = scostamento(colonna("ms_car")), scostamento(colonna("altezza"))
    for i, r in enumerate(righe):
        # Oltre a staccarsi dalle altre, la frase deve staccarsi di molto: un elenco con tante virgole è più lento, ed è giusto.
        if abs(z_ritmo[i]) > 4 and abs(r["ms_car"] / np.median(colonna("ms_car")) - 1) > 0.4:
            segna(i, f"ritmo insolito: {r['ms_car']:.0f} ms per carattere (mediana {np.median(colonna('ms_car')):.0f})")
        if r["altezza"] and abs(z_alt[i]) > 4 and abs(r["altezza"] / np.median(colonna("altezza")) - 1) > 0.12:
            segna(i, f"voce più {'acuta' if z_alt[i] > 0 else 'grave'} del resto: {r['altezza']:.0f} Hz (mediana {np.median(colonna('altezza')):.0f})")
        if r["pausa"] > 0.9:
            segna(i, f"pausa interna di {r['pausa']:.1f} s")
        if r["picco"] > 0.99:
            segna(i, "picco al massimo: possibile distorsione")
        if abs(r["volume"] - np.median(colonna("volume"))) > 3:
            segna(i, f"volume diverso dal resto: {r['volume']:.1f} dBFS")
    if args.modello:
        z_som = scostamento(colonna("somiglianza"))
        for i, r in enumerate(righe):
            # Quando le impronte sono tutte vicinissime, anche uno scarto minuscolo "si stacca": serve una distanza vera.
            if z_som[i] < -4 and r["somiglianza"] < np.median(colonna("somiglianza")) - 0.03:
                segna(i, f"impronta della voce lontana dalle altre: {r['somiglianza']:.3f} (mediana {np.median(colonna('somiglianza')):.3f})")

    print(f"Voce {voce.get('nome', '?')}: {len(righe)} registrazioni")
    print(f"  ritmo: mediana {np.median(colonna('ms_car')):.0f} ms per carattere (da {colonna('ms_car').min():.0f} a {colonna('ms_car').max():.0f})")
    print(f"  altezza della voce: mediana {np.median(colonna('altezza')):.0f} Hz (da {colonna('altezza').min():.0f} a {colonna('altezza').max():.0f})")
    print(f"  volume: mediana {np.median(colonna('volume')):.1f} dBFS; picco massimo {colonna('picco').max():.2f}; pausa interna più lunga {colonna('pausa').max():.2f} s")
    if args.modello:
        print(f"  somiglianza della voce con la media: mediana {np.median(colonna('somiglianza')):.3f}, minima {colonna('somiglianza').min():.3f}")
    if args.rapporto:
        Path(args.rapporto).write_text(json.dumps(righe, ensure_ascii=False, indent=1), encoding="utf-8")
    if not segnalate:
        print("Nessuna registrazione si stacca dalle altre.")
        return
    print(f"\nDa riascoltare ({len(segnalate)}):")
    for t, motivi in segnalate.items():
        print(f"  {t}\n        " + "; ".join(motivi))


if __name__ == "__main__":
    main()
