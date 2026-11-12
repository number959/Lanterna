#!/usr/bin/env python3
"""Prove veloci delle parti che non hanno bisogno di un motore: numeri in lettere, pronunce, confronto con il testo capito.

    python scripts/narrazione/prova.py

Serve solo numpy (lo importa genera.py). Non registra e non scarica nulla.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from genera import durata_credibile, esame, scarto  # noqa: E402
from pronuncia import in_lettere, numeri_in_lettere, parlato, parlato_llm  # noqa: E402


def uguale(avuto, atteso) -> None:
    if avuto != atteso:
        raise SystemExit(f"atteso {atteso!r}\n avuto {avuto!r}")


# Numeri in lettere, con le elisioni dell'italiano.
for n, parole in {0: "zero", 8: "otto", 21: "ventuno", 23: "ventitré", 28: "ventotto", 40: "quaranta", 86: "ottantasei", 100: "cento",
                  101: "centouno", 168: "centosessantotto", 180: "centottanta", 192: "centonovantadue", 254: "duecentocinquantaquattro",
                  480: "quattrocentottanta", 999: "novecentonovantanove", 1000: "mille", 1001: "milleuno", 2000: "duemila",
                  8080: "ottomilaottanta", 23000: "ventitremila", 65535: "sessantacinquemilacinquecentotrentacinque",
                  100000: "centomila", 999999: "novecentonovantanovemilanovecentonovantanove"}.items():  # fmt: skip
    uguale(in_lettere(n), parole)
uguale(numeri_in_lettere("2,4 e 5 gigahertz"), "due virgola quattro e cinque gigahertz")
# Dopo la virgola le cifre si dicono una per una, zeri compresi; un numero attaccato a una sigla si stacca.
uguale(numeri_in_lettere("una perdita dello 0,05 per cento"), "una perdita dello zero virgola zero cinque per cento")
uguale(numeri_in_lettere("la porta 8080 e il WPA2"), "la porta ottomilaottanta e il WPA due")
uguale(numeri_in_lettere("Il router è 10.0.0.1."), "Il router è dieci punto zero punto zero punto uno.")

# Per i motori che leggono come una persona: sigle per esteso, indirizzi con i punti detti, numeri in lettere.
uguale(parlato_llm("Un esempio è 192.168.1.20."), "Un esempio è centonovantadue punto centosessantotto punto uno punto venti.")
uguale(parlato_llm("Il DHCP assegna un indirizzo IP al PC."), "Il di acca ci pi assegna un indirizzo ai pi al pi ci.")
uguale(parlato_llm("Premi F12 o Esc."), "Premi effe dodici o esc.")
# Le parole inglesi che il motore leggerebbe all'italiana si scrivono come suonano; quelle che sa restano.
uguale(parlato_llm("Il Wi-Fi e il router: un access point, un hub, un file."), "Il uài-fài e il rùter: un àkses pòint, un àb, un fàil.")
uguale(parlato_llm("Il gateway e il firewall dello switch."), "Il gateway e il firewall dello switch.")
# La frase capita si confronta anche nella forma detta: «Wi-Fi» scritto bene dal riconoscitore non è uno scarto.
uguale(scarto("Le reti Wi-Fi sono VLAN separate.", "Le reti Wi-Fi sono vi lan separate."), 0.0)
# Per i motori con espeak-ng: le parole inglesi riscritte come suonano.
assert "ghèit-uei" in parlato("Il gateway risponde."), parlato("Il gateway risponde.")
assert "fàier uòl" in parlato("Il firewall filtra."), parlato("Il firewall filtra.")

# Confronto tra frase scritta e frase capita dal riconoscitore: 0 quando cambia solo la grafia.
uguale(scarto("Le reti Wi-Fi sono separate.", "le reti wifi sono separate"), 0.0)
uguale(scarto("Inizia con 169.254.", "Inizia con centosessantanove punto duecentocinquantaquattro."), 0.0)
uguale(scarto("Copiare 100 gigabyte richiede 40 minuti.", "Copiare 100 GB richiede 40 minuti."), 0.0)
uguale(scarto("A 480 megabit al secondo, circa 40 megabyte al secondo.", "A 480 Mbps, circa 40 MB/s."), 0.0)
uguale(scarto("Il DHCP assegna gli indirizzi.", "Il di acca ci pi assegna gli indirizzi."), 0.0)
uguale(scarto("Un indirizzo IP: quattro numeri da 0 a 255.", "Un indirizzo IP 4 numeri da 0 a 255."), 0.0)
# Una parola saltata o cambiata si vede.
assert scarto("Anche un solo errore è un problema serio.", "Anche un solo errore è un problema.") > 0.1
assert scarto("Dividere la rete in zone limita i danni.", "Dividere la rete in zone limita gli anni.") > 0.04

# In una frase lunga una parola corta saltata resta sotto la soglia del 4%: è il limite del confronto sull'intera frase.
lunga = "Se il router non risponde entro pochi secondi, Polaris lo segnala e propone di controllare il cavo, l'alimentazione e le luci."
assert scarto(lunga, lunga.replace(" non ", " ")) < 0.04
# Per questo le negazioni si contano a parte: una in meno, o una in più, e la presa non passa.
assert esame(lunga, lunga.replace(" non ", " ")) > 0.4
assert esame("Il test è riuscito.", "Il test non è riuscito.") > 0.4
uguale(esame(lunga, lunga), 0.0)
uguale(esame("Non serve nessun programma in più.", "non serve nessun programma in più"), 0.0)

# Una durata credibile per la frase com'è scritta e com'è detta: fuori ci sono le prese tagliate o con parole ripetute.
breve = "Un esempio è 192.168.1.20."
assert durata_credibile(breve, 3200)
assert not durata_credibile(breve, 700)  # tagliata
assert not durata_credibile(lunga, 20000)  # parole ripetute o un lungo silenzio

# Il controllo della pronuncia guarda ogni volta che la parola compare, nel suo punto della frase, senza modelli:
# qui i suoni sono scritti a mano come li darebbe il riconoscitore di fonemi.
from fonemi import pronunce  # noqa: E402

hub = "Evita prolunghe e hub vecchi: se serve un hub, che sia USB 3 e con l'alimentatore."
giusti = "e v i t a p r o l u ŋ ɡ e e a b v e k i s e s e r v e u n a b k e s i a u e s e b i t r e e k o n l a l i m e n t a t o r e"
assert not pronunce(hub, giusti)["hub"]["dubbia"]
# Una delle due volte detta «ub»: prima bastava l'altra, giusta, a far passare la frase.
assert pronunce(hub, giusti.replace("u n a b", "u n u b"))["hub"]["dubbia"]
assert pronunce(hub, giusti.replace("e a b v", "e u b v"))["hub"]["dubbia"]
tr = "Il traceroute mostra i router attraversati per arrivare a una destinazione."
giusti = "i l t r eɪ z r u t m o s t r a r u t e r a t r a v e r s a t i p e r a r i v a r e a u n a d e s t i n a ts j o n e"
assert not pronunce(tr, giusti)["router"]["dubbia"]
# «router» detto «rater»: la «rut» di «traceroute», poco prima, non deve far da pronuncia giusta.
assert pronunce(tr, giusti.replace("m o s t r a r u t e r", "m o s t r a r a t e r"))["router"]["dubbia"]
uguale(pronunce(tr, giusti)["router"]["volte"], 1)

print("tutto bene")
