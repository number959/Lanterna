#!/usr/bin/env python3
"""Prove veloci delle parti che non hanno bisogno di un motore: numeri in lettere, pronunce, confronto con il testo capito.

    python scripts/narrazione/prova.py

Serve solo numpy (lo importa genera.py). Non registra e non scarica nulla.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from genera import scarto  # noqa: E402
from pronuncia import in_lettere, numeri_in_lettere, parlato, parlato_llm  # noqa: E402


def uguale(avuto, atteso) -> None:
    if avuto != atteso:
        raise SystemExit(f"atteso {atteso!r}\n avuto {avuto!r}")


# Numeri in lettere, con le elisioni dell'italiano.
for n, parole in {0: "zero", 8: "otto", 21: "ventuno", 23: "ventitré", 28: "ventotto", 40: "quaranta", 86: "ottantasei", 100: "cento",
                  101: "centouno", 168: "centosessantotto", 180: "centottanta", 192: "centonovantadue", 254: "duecentocinquantaquattro",
                  480: "quattrocentottanta", 999: "novecentonovantanove"}.items():  # fmt: skip
    uguale(in_lettere(n), parole)
uguale(numeri_in_lettere("2,4 e 5 gigahertz"), "due virgola quattro e cinque gigahertz")

# Per i motori che leggono come una persona: sigle per esteso, indirizzi con i punti detti, numeri in lettere.
uguale(parlato_llm("Un esempio è 192.168.1.20."), "Un esempio è centonovantadue punto centosessantotto punto uno punto venti.")
uguale(parlato_llm("Il DHCP assegna un indirizzo IP al PC."), "Il di acca ci pi assegna un indirizzo ai pi al pi ci.")
uguale(parlato_llm("Premi F12 o Esc."), "Premi effe dodici o esc.")
# Per i motori con espeak-ng: le parole inglesi riscritte come suonano.
assert "ghèit-uei" in parlato("Il gateway risponde."), parlato("Il gateway risponde.")
assert "fàier uòl" in parlato("Il firewall filtra."), parlato("Il firewall filtra.")

# Confronto tra frase scritta e frase capita dal riconoscitore: 0 quando cambia solo la grafia.
uguale(scarto("Le reti Wi-Fi sono separate.", "le reti wifi sono separate"), 0.0)
uguale(scarto("Inizia con 169.254.", "Inizia con centosessantanove punto duecentocinquantaquattro."), 0.0)
uguale(scarto("Copiare 100 gigabyte richiede 40 minuti.", "Copiare 100 GB richiede 40 minuti."), 0.0)
uguale(scarto("A 480 megabit al secondo, circa 40 megabyte al secondo.", "A 480 Mbps, circa 40 MB/s."), 0.0)
uguale(scarto("Il DHCP assegna gli indirizzi.", "Il di acca ci pi assegna gli indirizzi."), 0.0)
# Una parola saltata o cambiata si vede.
assert scarto("Anche un solo errore è un problema serio.", "Anche un solo errore è un problema.") > 0.1
assert scarto("Dividere la rete in zone limita i danni.", "Dividere la rete in zone limita gli anni.") > 0.04

print("tutto bene")
