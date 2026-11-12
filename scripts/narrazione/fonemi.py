#!/usr/bin/env python3
"""Scrive i suoni di ogni registrazione, fonema per fonema, e controlla come sono dette le parole inglesi.

Whisper scrive le parole che riconosce: se la voce dice «vi-fi», scrive comunque
«Wi-Fi», e l'errore di pronuncia non si vede. Qui si usa invece un riconoscitore
di fonemi (wav2vec2, addestrato a scrivere i suoni e non le parole): dice che
cosa è stato pronunciato davvero, in alfabeto fonetico.

    python scripts/narrazione/fonemi.py --frasi frasi.json --modello M/wav2vec2-xlsr-53-espeak-cv-ft

Per ogni parola dell'elenco ATTESE cerca, nelle frasi che la contengono, il
tratto di suoni più vicino alle pronunce giuste e a quelle sbagliate già sentite,
e segnala le frasi dove vince una sbagliata o dove la giusta non si ritrova. Con --tutte stampa i suoni di ogni frase; con --rapporto li salva.
Con --file si ascoltano dei file qualunque (per provare una grafia prima di
registrare).

È un aiuto, non un giudice: il riconoscitore sbaglia qualche suono, soprattutto
vocali vicine e consonanti in fine di parola. Le frasi segnalate vanno ascoltate.

Serve torch e transformers (arrivano con qwen-tts) e il modello
`facebook/wav2vec2-xlsr-53-espeak-cv-ft` (Apache-2.0, 1,2 GB), che non sta nel
repository.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from genera import CARTELLA, INDICE, carica, leggi_indice  # noqa: E402

SR = 16000

# Come devono suonare le parole che una voce italiana rischia di leggere con le regole dell'italiano. Per ogni
# parola: l'espressione che la trova nel testo, le pronunce giuste e quelle sbagliate che si sono sentite davvero,
# scritte con i suoni che il riconoscitore usa (alfabeto fonetico, senza accenti né lunghezze). Una frase è
# segnalata quando il tratto di suoni somiglia più a una pronuncia sbagliata che a una giusta, o a nessuna delle due.
ATTESE: dict[str, tuple[str, list[str], list[str]]] = {
    "Wi-Fi": (r"\bwi-?fi\b", ["waifai", "uaifai"], ["waifi", "uaifi", "wifi", "uifi", "vifi", "wefi", "vaifai"]),
    "router": (r"\brouter\b", ["ruter"], ["rauter", "rater", "router"]),
    "access point": (r"\baccess point\b", ["aksespoint", "akspoint"], ["atʃespoint", "atʃespont", "atʃspont", "tʃespont", "aksespont"]),
    "file": (r"\bfile\b", ["fail"], ["file", "fal", "fil"]),
    # «ab» è troppo corto per cercarlo da solo: si cerca con il suono che lo precede nelle frasi («un hub», «e hub»).
    "hub": (r"\bhub\b", ["unab", "eab"], ["unub", "eub", "unob", "unhub"]),
    "traceroute": (r"\btraceroute\b", ["treisrut", "treizrut"], ["tratʃerut", "traizrut", "traisrut", "trairut", "treʃerut", "traserut"]),
    "gateway": (r"\bgateway\b", ["geitwei", "getwei"], ["gatewai", "gatevai", "getuai", "gatwai"]),
    "firewall": (r"\bfirewall\b", ["faierwol", "fairwol"], ["firewal", "fireval"]),
    "switch": (r"\bswitch\b", ["switʃ"], ["svitʃ", "switk"]),
    "Windows": (r"\bwindows\b", ["windous", "windos", "windoz"], ["vindovs", "windovs"]),
    "computer": (r"\bcomputer\b", ["kompiuter"], ["komputer"]),
    "server": (r"\bserver\b", ["server"], []),
    "Internet": (r"\binternet\b", ["internet"], []),
    "trunk": (r"\btrunk\b", ["trank", "traŋk"], ["trunk"]),
    "SuperSpeed": (r"\bsuperspeed\b", ["superspid"], ["supersped", "superspeed"]),
    "broadcast": (r"\bbroadcast\b", ["brodkast"], ["broadkast"]),
    "ransomware": (r"\bransomware\b", ["ransomwer", "ransamwer", "ransomuer"], ["ransomware", "ransomvare"]),
    "firmware": (r"\bfirmware\b", ["firmwer", "fermwer", "firmuer"], ["firmware", "firmvare"]),
    "BitLocker": (r"\bbitlocker\b", ["bitloker"], ["bitlotʃer"]),
    "byte": (r"\b(?:mega|giga)byte\b", ["gabait"], ["gabat", "gabate", "gabite"]),
    "hertz": (r"\b(?:mega|giga)hertz\b", ["erts", "herts"], []),
    "Memtest": (r"\bmemtest", ["memtest"], ["mempest", "mentest"]),
    "Polaris": (r"\bpolaris\b", ["polaris"], []),
}


def _piano(s: str) -> str:
    """I suoni senza i segni che qui non contano: accenti, lunghezze, spazi; qualche suono vicino si unifica."""
    s = re.sub(r"[ˈˌːˑ\s.‿|]", "", s.lower())
    for a, b in (("ɡ", "g"), ("ɛ", "e"), ("ɔ", "o"), ("ɪ", "i"), ("ʊ", "u"), ("ə", "e"), ("ɐ", "a"), ("ɑ", "a"), ("æ", "e"), ("ɾ", "r"), ("ɹ", "r"), ("j", "i")):
        s = s.replace(a, b)
    return s


def _distanza(a: str, b: str) -> int:
    riga = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        nuova = [i]
        for j, cb in enumerate(b, 1):
            nuova.append(min(riga[j] + 1, nuova[j - 1] + 1, riga[j - 1] + (ca != cb)))
        riga = nuova
    return riga[-1]


def vicino(suoni: str, attesa: str) -> tuple[int, str]:
    """Il tratto di `suoni` più vicino ad `attesa`: quanti suoni di differenza e il tratto trovato."""
    s, a = _piano(suoni), _piano(attesa)
    migliore = (len(a), "")
    for lung in range(max(1, len(a) - 2), len(a) + 3):
        for i in range(0, max(1, len(s) - lung + 1)):
            pezzo = s[i : i + lung]
            d = _distanza(pezzo, a)
            if d < migliore[0]:
                migliore = (d, pezzo)
    return migliore


def pronunce(testo: str, suoni: str, differenze: int = 2) -> dict[str, dict]:
    """Per ogni parola dell'elenco che compare nella frase: che cosa si è sentito e se la pronuncia è dubbia.

    È dubbia se il tratto di suoni somiglia più a una pronuncia sbagliata che a una giusta, o se la pronuncia
    giusta non si ritrova entro `differenze` suoni.
    """
    parole = {}
    for nome, (rx, giuste, sbagliate) in ATTESE.items():
        if not re.search(rx, testo, re.I):
            continue
        d, pezzo = min((vicino(suoni, pr) for pr in giuste), key=lambda x: x[0])
        ds, sbagliato = min((vicino(suoni, pr) for pr in sbagliate), key=lambda x: x[0], default=(99, ""))
        parole[nome] = {"differenze": d, "trovato": sbagliato if ds < d else pezzo, "atteso": giuste[0], "dubbia": ds < d or d > differenze}
    return parole


def dubbie(parole: dict[str, dict]) -> str:
    """Le parole dalla pronuncia dubbia, in breve: «Wi-Fi (sentito waifi)»."""
    return ", ".join(f"{nome} (sentito {x['trovato']})" for nome, x in parole.items() if x["dubbia"])


class Fonemi:
    """wav2vec2 che scrive i fonemi: si legge il vocabolario a mano, così non serve espeak."""

    def __init__(self, modello: str, processi: int):
        import torch
        from transformers import Wav2Vec2ForCTC

        self.torch = torch
        torch.set_num_threads(processi)
        self.m = Wav2Vec2ForCTC.from_pretrained(modello).eval()
        voci = json.loads((Path(modello) / "vocab.json").read_text(encoding="utf-8"))
        self.simboli = {i: s for s, i in voci.items()}
        self.vuoto = self.m.config.pad_token_id

    def ascolta(self, a: np.ndarray, sr: int = SR) -> str:
        """I suoni di una registrazione, uno dopo l'altro. Il modello lavora a 16 kHz."""
        if sr != SR:
            import librosa

            a = librosa.resample(np.asarray(a, dtype=np.float32), orig_sr=sr, target_sr=SR)
        a = (a - a.mean()) / (a.std() + 1e-7)
        with self.torch.no_grad():
            ids = self.m(self.torch.from_numpy(a.astype(np.float32))[None]).logits[0].argmax(-1).tolist()
        suoni, prima = [], None
        for i in ids:
            if i != prima and i != self.vuoto:
                s = self.simboli.get(i, "")
                if not s.startswith("<"):
                    suoni.append(s)
            prima = i
        return " ".join(suoni)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--frasi", help="JSON scritto da frasi.mjs")
    p.add_argument("--modello", required=True, help="cartella di wav2vec2-xlsr-53-espeak-cv-ft")
    p.add_argument("--cartella", type=Path, default=CARTELLA)
    p.add_argument("--indice", type=Path, default=INDICE)
    p.add_argument("--processi", type=int, default=4)
    p.add_argument("--file", nargs="+", type=Path, help="ascolta questi file invece delle registrazioni dell'indice")
    p.add_argument("--solo", metavar="PAROLE", help="solo le frasi che contengono queste parole")
    p.add_argument("--tutte", action="store_true", help="stampa i suoni di ogni frase")
    p.add_argument("--differenze", type=int, default=2, help="suoni di differenza oltre i quali la pronuncia giusta non si considera ritrovata")
    p.add_argument("--rapporto", metavar="FILE", help="scrive qui i suoni di ogni frase e l'esito parola per parola (JSON)")
    args = p.parse_args()

    f = Fonemi(args.modello, args.processi)
    if args.file:
        for file in args.file:
            print(f"{file.name}: {f.ascolta(carica(file, SR))}")
        return
    if not args.frasi:
        p.error("serve --frasi (oppure --file)")

    frasi = [x["testo"] for x in json.loads(Path(args.frasi).read_text(encoding="utf-8"))]
    _, clip = leggi_indice(args.indice)
    if args.solo:
        frasi = [t for t in frasi if args.solo.lower() in t.lower()]
    else:
        # Senza --solo si ascoltano soltanto le frasi con almeno una parola dell'elenco (con --tutte, tutte).
        frasi = [t for t in frasi if args.tutte or any(re.search(v[0], t, re.I) for v in ATTESE.values())]
    esiti, segnalate = [], []
    for i, t in enumerate(frasi):
        if t not in clip:
            raise SystemExit(f"manca la registrazione di: {t}")
        suoni = f.ascolta(carica(args.cartella / clip[t]["file"], SR))
        parole = pronunce(t, suoni, args.differenze)
        segnalate += [(nome, x["differenze"], x["trovato"], t) for nome, x in parole.items() if x["dubbia"]]
        esiti.append({"testo": t, "suoni": suoni, "parole": parole})
        if args.tutte or args.solo:
            print(f"[{i + 1}/{len(frasi)}] {t}\n      {suoni}", flush=True)

    if args.rapporto:
        Path(args.rapporto).write_text(json.dumps(esiti, ensure_ascii=False, indent=1), encoding="utf-8")
    conta: dict[str, list[bool]] = {}
    for e in esiti:
        for nome, x in e["parole"].items():
            conta.setdefault(nome, []).append(x["dubbia"])
    print(f"\n{len(esiti)} frasi ascoltate. Per ogni parola: frasi in cui compare e frasi in cui si ritrova la pronuncia giusta.")
    for nome, d in conta.items():
        print(f"  {nome:14} {len(d):3} frasi, {sum(1 for x in d if not x):3} con la pronuncia giusta")
    if segnalate:
        print(f"\nDa ascoltare ({len(segnalate)}): la pronuncia giusta non si ritrova. Può sbagliare anche il riconoscitore.")
        for nome, d, pezzo, t in sorted(segnalate):
            print(f"  {nome}: sentito «{pezzo}» (dalla pronuncia giusta: {d} suoni di differenza)  {t}")


if __name__ == "__main__":
    main()
