"""Dal testo dei sottotitoli al testo da far leggere alla voce.

Le frasi delle videoguide (core/src/guides/video.ts) sono scritte per essere
lette, ma contengono sigle e parole inglesi che un motore di sintesi italiano
pronuncerebbe a caso ("file" come è scritto, "VLAN" in una sillaba, un
indirizzo IP come un numero con le migliaia). Qui si riscrivono come si dicono.

Due insiemi di regole, secondo il motore:
- parlato():     per i motori che passano da espeak-ng (Piper, Kokoro), dove
                 ogni parola va scritta come si pronuncia in italiano; i fonemi
                 che ne escono si controllano con "genera.py --fonemi";
- parlato_llm(): per i motori che leggono il testo da soli (Qwen3-TTS): le
                 parole inglesi restano come sono, si scrivono per esteso solo
                 le sigle e gli indirizzi.
"""
import re

REGOLE = [
    (r"\b192\.168\.1\.20\b", "192 punto 168 punto 1 punto 20"),
    (r"\b169\.254\b", "169 punto 254"),
    (r"\baccess point\b", "àcses pòint"),
    (r"\bVLAN\b", "vilàn"),
    (r"\bgateway\b", "ghèit-uei"),
    (r"\bbroadcast\b", "bròdcast"),
    (r"\bransomware\b", "rànsom uèr"),
    (r"\bfile\b", "fàil"),
    (r"\bBitLocker\b", "bit lòcher"),
    (r"\bSuperSpeed\b", "super spìd"),
    (r"\bfirmware\b", "fèrm-uer"),
    (r"\btraceroute\b", "tréis rùt"),
    (r"\broaming\b", "ròming"),
    (r"\btrunk\b", "trank"),
    (r"\bhub\b", "ab"),
    (r"\bRAM\b", "ram"),
    (r"\bIP\b", "ai pi"),
    (r"\bmegabyte\b", "megabàit"),
    (r"\bgigabyte\b", "gigabàit"),
    (r"\bgigabit\b", "gìgabit"),
    (r"\bmegabit\b", "mègabit"),
    (r"\bgigahertz\b", "gigaèrz"),
    (r"\bmegahertz\b", "megaèrz"),
    (r"\bfirewall\b", "fàier uòl"),
    (r"\bdecibel milliwatt\b", "decibèl millivàt"),
    (r"\bdecibel\b", "decibèl"),
    (r"\bWindows\b", "uìndous"),
    (r"\bmaschera\b", "màschera"),
    (r"\bindizio\b", "indìzio"),
]

def parlato(testo: str) -> str:
    for rx, sost in REGOLE:
        testo = re.sub(rx, sost, testo)
    return testo

# Per i motori che leggono il testo da soli (Qwen3-TTS): le parole inglesi restano come sono,
# si scrivono per esteso solo le sigle e gli indirizzi, che altrimenti verrebbero letti a caso.
REGOLE_LLM = [
    (r"\b192\.168\.1\.20\b", "192 punto 168 punto 1 punto 20"),
    (r"\b169\.254\b", "169 punto 254"),
    (r"\bMemtest86\+", "Memtest ottantasei più"),
    (r"\bVLAN\b", "vi-lan"),
    (r"\bDHCP\b", "di acca ci pi"),
    (r"\bSNMP\b", "esse enne emme pi"),
    (r"\bLLDP\b", "elle elle di pi"),
    (r"\bCDP\b", "ci di pi"),
    (r"\bDTP\b", "di ti pi"),
    (r"\bUSB\b", "u esse bi"),
    (r"\bPDF\b", "pi di effe"),
    (r"\bPC\b", "pi ci"),
    (r"\bIP\b", "ai pi"),
    (r"\bTV\b", "tivù"),
    (r"\bRAM\b", "ram"),
    (r"\bDD\b", "di di"),
    (r"\bSS\b", "esse esse"),
    (r"\bF12\b", "effe dodici"),
    (r"\bEsc\b", "esc"),
]

_UNITA = "zero uno due tre quattro cinque sei sette otto nove dieci undici dodici tredici quattordici quindici sedici diciassette diciotto diciannove".split()
_DECINE = ["", "", "venti", "trenta", "quaranta", "cinquanta", "sessanta", "settanta", "ottanta", "novanta"]


def in_lettere(n: int) -> str:
    """Un numero da 0 a 999 in parole: 169 -> centosessantanove, 23 -> ventitré, 480 -> quattrocentottanta."""
    if not 0 <= n <= 999:
        raise ValueError(n)
    if n < 20:
        return _UNITA[n]
    if n < 100:
        d, u = divmod(n, 10)
        if u == 0:
            return _DECINE[d]
        base = _DECINE[d][:-1] if u in (1, 8) else _DECINE[d]
        return base + ("tré" if u == 3 else _UNITA[u])
    c, resto = divmod(n, 100)
    cento = ("" if c == 1 else _UNITA[c]) + "cento"
    if resto == 0:
        return cento
    # "cento" perde la vocale davanti a ottanta: centottanta, quattrocentottanta.
    return (cento[:-1] if 80 <= resto < 90 else cento) + in_lettere(resto)


def numeri_in_lettere(testo: str) -> str:
    """Le cifre scritte in lettere: «169» diventa «centosessantanove», «2,4» diventa «due virgola quattro»."""
    testo = re.sub(r"(\d+),(\d+)", lambda m: f"{in_lettere(int(m.group(1)))} virgola {in_lettere(int(m.group(2)))}", testo)
    return re.sub(r"\d+", lambda m: in_lettere(int(m.group(0))), testo)


def parlato_llm(testo: str) -> str:
    for rx, sost in REGOLE_LLM:
        testo = re.sub(rx, sost, testo)
    # I numeri in parole: scritti in cifre, questi motori a volte li leggono in un'altra lingua o li storpiano.
    return numeri_in_lettere(testo)
