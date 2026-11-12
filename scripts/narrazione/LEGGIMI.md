# Narrazione delle videoguide

Le videoguide hanno una narrazione **registrata**: una registrazione per frase, in
`core/src/guides/narrazione/` (Ogg Opus), con l'indice `core/src/guides/narrazione.ts` che porta dal testo della
frase al file e alla durata. Le registrazioni finiscono nel programma; gli script di questa cartella servono solo
a chi le rifà, quando cambia il testo di una videoguida o si cambia voce. Chi usa il programma non ha bisogno di
nulla di tutto questo.

La voce è **sintetica**: la genera una volta, su un computer, un modello di sintesi vocale aperto. Durante
l'ascolto non c'è nessuna sintesi e nulla esce dal computer.

## Che cosa c'è qui

| File | A che cosa serve |
|---|---|
| `frasi.mjs` | Scrive in JSON tutte le frasi della narrazione (`core/src/guides/video.ts`). |
| `genera.py` | Registra le frasi con un motore di sintesi, le riascolta, scrive file e indice. |
| `pronuncia.py` | Come vanno dette sigle, parole inglesi e numeri (due profili, uno per tipo di motore). |
| `controlla.py` | Misura ritmo, volume, pause e altezza della voce di ogni registrazione e segnala quelle che si staccano. |
| `fonemi.py` | Scrive i suoni di ogni registrazione, fonema per fonema, e controlla come sono dette le parole inglesi. |
| `ascolto.py`, `ascolto.html` | Costruisce una pagina per ascoltare tutta la narrazione, con ogni frase numerata. |
| `disegna.py` | Crea una voce nuova da una descrizione a parole (Qwen3-TTS VoiceDesign). |
| `voci/voci.json` | Le descrizioni delle voci create così e la frase di prova. |
| `voci/<nome>.flac` | Il campione di ogni voce creata: **è** la voce, va tenuto. |
| `crediti.mjs` | Scrive i crediti della voce in `THIRD_PARTY_NOTICES.md` (lo chiama `scripts/notices.sh`). |
| `prova.py` | Prove veloci di numeri in lettere, pronunce, confronto con il testo capito, negazioni e durate (serve solo numpy). |

## Rifare una frase cambiata

Un test (`core/test/narrazione.test.ts`) fallisce se una frase di `video.ts` non ha la sua registrazione con il
testo di oggi. L'indice non si corregge a mano: il nome di ogni file viene dal testo della frase (le prime 12 cifre di
`sha1(chiave|testo)`, con la `chiave` scritta nell'indice) e il test lo ricalcola, quindi una frase cambiata anche
nell'indice senza rifare la registrazione non passa. Per rimettere le cose a posto, con la stessa voce:

```sh
node scripts/narrazione/frasi.mjs frasi.json
python scripts/narrazione/genera.py --frasi frasi.json --solo-mancanti <le stesse opzioni della voce in uso>
bash scripts/notices.sh
```

`--solo-mancanti` rifà soltanto le frasi nuove o cambiate e toglie le registrazioni di quelle che non esistono
più. Le opzioni della voce in uso sono qui sotto, alla voce che `narrazione.ts` dichiara in `VOCE`. Se le opzioni
indicano un'altra voce (un altro modello, o un campione diverso da quello con cui sono state fatte le registrazioni:
nell'indice c'è la sua impronta SHA-256), lo script si ferma e lo dice, invece di rifare tutto o di mescolare due voci.

## Le voci provate

Tutti i comandi partono dalla radice del repository; `M` è la cartella dove hai scaricato i modelli.

**Qwen3-TTS, voce creata da una descrizione** (Giulia, Chiara, Marco, Andrea: i campioni sono in `voci/`):

```sh
python scripts/narrazione/genera.py --frasi frasi.json --motore qwen \
  --modello M/Qwen3-TTS-12Hz-0.6B-Base \
  --riferimento scripts/narrazione/voci/giulia.flac \
  --testo-riferimento "$(node -p "require('./scripts/narrazione/voci/voci.json').testo")" \
  --nome Giulia --licenza "Qwen3-TTS di Alibaba Cloud, licenza Apache-2.0" \
  --lotto 4 --verifica small --tentativi 4
```

**Qwen3-TTS, voce predefinita** (Serena, Aiden e le altre del modello CustomVoice):

```sh
python scripts/narrazione/genera.py --frasi frasi.json --motore qwen \
  --modello M/Qwen3-TTS-12Hz-0.6B-CustomVoice --voce Serena \
  --nome Serena --licenza "Qwen3-TTS di Alibaba Cloud, licenza Apache-2.0" --lotto 4 --verifica small
```

**Kokoro-82M** (`if_sara`, `im_nicola`; accanto al modello serve `voices-v1.0.bin`):

```sh
python scripts/narrazione/genera.py --frasi frasi.json --motore kokoro \
  --modello M/kokoro-v1.0.onnx --voce if_sara \
  --nome Sara --licenza "Kokoro-82M di hexgrad, licenza Apache-2.0" --verifica small
```

**Piper** (una voce italiana, file `.onnx` con il suo `.onnx.json`):

```sh
python scripts/narrazione/genera.py --frasi frasi.json --motore piper \
  --modello M/it_IT-paola-medium.onnx --nome Paola --licenza "<licenza e crediti della voce>" --verifica small
```

Il nome della cartella o del file del modello entra nell'indice e nei nomi dei file: conviene lasciare i nomi
ufficiali, così `--solo-mancanti` riconosce la voce già registrata.

### Creare una voce nuova

Si aggiunge una descrizione in `voci/voci.json` (in inglese, è la lingua che il modello capisce meglio: sesso, età,
timbro, ritmo, tono) e si lancia:

```sh
python scripts/narrazione/disegna.py --modello M/Qwen3-TTS-12Hz-1.7B-VoiceDesign <nome>
```

Nasce `voci/<nome>.flac`, pochi secondi con la frase di prova: da lì in poi la voce è quel campione. La stessa
descrizione, con un'altra versione del modello o delle librerie, dà una voce diversa: per questo `disegna.py` non
riscrive un campione che esiste e i campioni stanno nel repository.

Due regole, che valgono più della comodità:

- nelle descrizioni non si mettono nomi di persone, e come campione non si usa la registrazione di una persona:
  niente voci imitate;
- si usano solo modelli la cui licenza permette di distribuire l'audio generato, e la licenza si scrive in
  `--licenza`: finisce nell'indice e nei crediti del programma.

## Pronunce

I motori non leggono sigle, parole inglesi e numeri allo stesso modo, quindi `pronuncia.py` ha due profili.

- **Piper e Kokoro** trasformano il testo in fonemi con espeak-ng, che legge tutto con le regole dell'italiano:
  le parole inglesi vanno riscritte come suonano («gateway» diventa «ghèit-uei»). Si controlla senza registrare:
  `genera.py --frasi frasi.json --motore piper --modello ... --fonemi` stampa i fonemi di ogni frase.
- **Qwen3-TTS** legge il testo come farebbe una persona e molte parole inglesi le sa («gateway», «firewall»,
  «switch»): gli si scrivono per esteso le sigle («DHCP» diventa «di acca ci pi»), i numeri in lettere, perché
  scritti in cifre a volte li legge in un'altra lingua, e le parole inglesi che invece legge con le regole
  dell'italiano. Al primo ascolto di una persona è stato segnalato «Wi-Fi», detto «uai-fi» o «ui-fi»; il
  riconoscitore di fonemi ha poi trovato «router» in tre modi diversi, «access point» con la c dolce, «file» com'è
  scritto, «hub» detto «ub», «traceroute» con la c dolce. Ora hanno una regola ciascuna (uài-fài, rùter, àkses pòint,
  fàil, àb, treisrùt), con le pronunce dei dizionari (Treccani, DiPI, De Mauro, Olivetti; «treisrùt» è ricostruita,
  perché nessun dizionario ha la parola).

**Come si trova una pronuncia sbagliata senza poterla sentire.** Whisper non serve: scrive «Wi-Fi» anche quando la
voce dice «ui-fi», perché riconosce le parole e le scrive per bene. Serve un riconoscitore di **fonemi**, che scrive
i suoni: `fonemi.py --frasi frasi.json --modello M/wav2vec2-xlsr-53-espeak-cv-ft` ascolta le frasi che contengono
una parola dell'elenco `ATTESE` e, ogni volta che la parola compare, guarda i suoni nel punto della frase dove dovrebbe
cadere (lo stima dalla frase com'è detta): segnala le frasi in cui lì i suoni somigliano più a una pronuncia sbagliata
che a quella giusta, o non somigliano alla giusta (`--tutte` stampa i suoni di ogni frase, `--solo "parola"` quelli di
alcune). Per trovare la grafia che fa dire bene una parola nuova se ne scrivono alcune in una frase breve, in un file
di frasi di prova (lo stesso formato di `frasi.json`, con le grafie già scritte come devono essere lette), si
registrano in una cartella a parte (`genera.py --frasi prove.json ... --cartella /tmp/prove --indice
/tmp/prove/indice.ts`, magari due volte con `--seme` diversi, perché la stessa grafia non esce sempre uguale) e si
ascoltano con `fonemi.py --modello M/wav2vec2-xlsr-53-espeak-cv-ft --frasi prove.json --cartella /tmp/prove --indice
/tmp/prove/indice.ts --tutte`; `--file prova1.wav prova2.wav`, sempre con `--modello`, ascolta file qualunque.
Con `genera.py ... --verifica small --pronunce M/wav2vec2-xlsr-53-espeak-cv-ft` lo stesso controllo entra nell'esame
di ogni presa: una frase con una parola inglese detta male si rifà come quelle con le parole sbagliate o fuori registro
(senza `--verifica` lo script si ferma: le prese rifatte per la pronuncia vanno controllate anche nelle parole). È un
aiuto, non un giudice: sbaglia qualche suono, non sente gli accenti, la posizione di ogni parola è una stima e con le
parole molto corte («hub») va guidato dai suoni vicini. Una parola inglese nuova va aggiunta all'elenco, con le
pronunce giuste e quelle sbagliate già sentite. L'ultima parola resta a chi ascolta.

Se una parola suona male si aggiunge una riga a `REGOLE` o a `REGOLE_LLM` e si rifanno le frasi che la contengono:
`genera.py ... --solo-mancanti --rifai "parola"`. Con Qwen3-TTS, se una frase è venuta male senza un motivo,
basta un'altra presa: `--solo-mancanti --rifai "inizio della frase"`. A ogni ripresa (`--rifai`, `--ricontrolla`) lo
script parte da un seme nuovo e lo stampa, così non ripete le prese già scartate; `--seme N` serve a rifarne una uguale.

## La verifica all'ascolto

Qwen3-TTS sceglie a caso tra pronunce e intonazioni possibili: la stessa frase non esce mai uguale. Ha due difetti,
e `genera.py` li tiene a bada rifacendo le frasi che non passano l'esame, con un altro seme, fino a `--tentativi`
prese (tre, se non dici altro), e tenendo la migliore.

- **Ogni tanto salta o storpia una parola.** Con `--verifica small` ogni registrazione viene riascoltata da un
  riconoscitore vocale (Whisper, modello `small`): non passa se il testo capito si scosta da quello scritto per più
  del 4% dei caratteri (`--soglia`) o se la durata è fuori misura (tra 35 e 140 ms per carattere scritto e tra 30 e
  110 per carattere detto: fuori ci sono le prese tagliate e quelle con parole ripetute). Lo scarto si misura
  sull'intera frase, quindi in una frase lunga una parola corta saltata resterebbe sotto la soglia: per questo le
  **negazioni** («non», «mai», «senza», «nessuno») si contano a parte, e una in meno o una in più basta a bocciare la
  presa, perché il senso si rovescia. Le altre parole corte restano un limite del controllo.
- **Cambia registro da una frase all'altra**: una calma e grave, la successiva acuta e concitata. Di ogni presa si
  misura l'altezza mediana della voce; dopo la prima passata il riferimento è la mediana di tutte le frasi, e non
  passa chi se ne stacca per più del 10% (`--tolleranza`; `--altezza 260` fissa il riferimento a mano,
  `--senza-altezza` rinuncia al controllo). Nella prima registrazione di prova, senza questo controllo, le frasi
  andavano da 220 a 360 Hz.

`--solo-mancanti --ricontrolla` rimette all'esame anche le registrazioni già fatte: serve dopo un'interruzione, o
per stringere i margini senza rifare tutto. Una regola di pronuncia nuova non cambia il nome dei file (viene dal
testo della frase, non da come è detta): le frasi con quella parola si rifanno con `--solo-mancanti --rifai "parola"`.

Alla fine lo script elenca le frasi rimaste fuori dai margini. **Vanno riascoltate, non sono per forza sbagliate**:
il riconoscitore sbaglia a sua volta, soprattutto su sigle e parole inglesi («VLAN separate» capito «villan
separate»). `--rapporto file.json` salva che cosa ha capito frase per frase.

`genera.py --frasi frasi.json --riascolta` non registra nulla: riascolta le registrazioni che ci sono già, cioè
quelle che finiscono nel programma, ne misura l'altezza e dà gli stessi elenchi.

`controlla.py --frasi frasi.json` fa un controllo diverso, sul suono: per ogni registrazione misura il ritmo, il
volume, le pause interne e l'altezza della voce e segnala quelle fuori misura: ritmo oltre il 40% dalla mediana,
altezza oltre il 12%, una pausa interna oltre 0,9 secondi, volume oltre 3 dB dal resto, picco al massimo. Con
`--modello M/Qwen3-TTS-12Hz-0.6B-Base` confronta anche l'impronta della voce di ogni registrazione con la media: serve a
trovare le frasi in cui la voce è «scivolata».

I due controlli dicono se le parole si capiscono e se le registrazioni si somigliano. **Non dicono se la voce è
gradevole**: quello si sente solo con le orecchie.

Per questo c'è `ascolto.py`: `python scripts/narrazione/ascolto.py --frasi frasi.json --uscita narrazione.html` scrive
una pagina con tutte le videoguide, ogni frase numerata (3.12 è la dodicesima della terza) e ascoltabile da sola o di
seguito, con le stesse pause del programma. Chi ascolta dice i numeri delle frasi da rifare. La pagina è un documento
completo, si apre dal disco e non chiede nulla alla rete; l'audio è in MP3 (nel programma resta Ogg Opus) ed Esc mette
in pausa e riprende. Con `--rapporto file.json` (quello di `genera.py --riascolta --rapporto file.json`) le frasi su cui
i controlli hanno un dubbio sono segnate ed elencate in cima; senza, la pagina dice che un riascolto automatico non
c'è. `--frammento` serve solo a chi pubblica la pagina in un ambiente che aggiunge da sé l'involucro del documento.

## Che cosa serve

- Python 3.10 o successivo e `ffmpeg` con `libopus` (per `ascolto.py` anche con `libmp3lame`).
- Node, con le dipendenze dell'interfaccia installate (`npm ci` in `core/`): `frasi.mjs` legge le frasi da `video.ts`
  con esbuild, e `crediti.mjs` scrive i crediti.
- I motori si installano in un ambiente virtuale: non sono dipendenze del programma e non entrano nel pacchetto.
  Conviene non prendere versioni uscite da pochi giorni: `pip install --uploaded-prior-to <data di due settimane
  fa> ...` (serve un pip recente: provato con il 26.2).

```sh
python -m venv .venv-voce && . .venv-voce/bin/activate
pip install qwen-tts faster-whisper soundfile        # Qwen3-TTS e la verifica
pip install kokoro-onnx piper-tts                    # solo se servono Kokoro o Piper
```

Le misure dell'altezza della voce usano `librosa`, che arriva insieme a `qwen-tts`.

Versioni con cui sono state fatte le registrazioni (novembre 2026, Linux, solo processore): qwen-tts 0.1.1,
torch 2.15.0, transformers 4.57.3, faster-whisper 1.2.1, ctranslate2 4.8.4, kokoro-onnx 0.6.1, piper-tts 1.8.0,
onnxruntime 1.31.1, numpy 2.5.4.

I modelli si scaricano dalle pagine dei rispettivi progetti (per Qwen3-TTS: `Qwen/Qwen3-TTS-12Hz-0.6B-Base`,
`Qwen/Qwen3-TTS-12Hz-0.6B-CustomVoice` e `Qwen/Qwen3-TTS-12Hz-1.7B-VoiceDesign` su Hugging Face) e non stanno nel
repository: pesano da 60 MB (Piper) a oltre 4 GB (VoiceDesign). Il riconoscitore di fonemi è
`facebook/wav2vec2-xlsr-53-espeak-cv-ft` (1,2 GB, licenza Apache-2.0): serve solo a controllare, non lascia nulla nel
programma. Su un computer senza scheda grafica conviene la versione di torch per il solo processore
(`pip install --index-url https://download.pytorch.org/whl/cpu torch==2.15.0 torchaudio==2.11.1`, le versioni usate
qui), molto più leggera.

Tempi su quattro processori senza scheda grafica: Piper e Kokoro leggono tutta la narrazione (147 frasi, circa
12 minuti) in pochi minuti; Qwen3-TTS 0.6B impiega quasi cinque secondi per ogni secondo di voce a una frase per
volta (4,7) e meno di tre con `--lotto 8` (2,7, con circa 12 GB di memoria); `--lotto 4` non è stato misurato da solo.
Con `--lotto 4`, la verifica e le prese rifatte, tutta la narrazione ha chiesto intorno a un'ora e mezza. Se si
interrompe, `--solo-mancanti` riprende da dov'era: l'indice viene riscritto dopo ogni registrazione.

## Licenze

| Modello | Licenza | Note |
|---|---|---|
| Qwen3-TTS (Alibaba Cloud) | Apache-2.0 | Base, CustomVoice e VoiceDesign. |
| Kokoro-82M (hexgrad) | Apache-2.0 | Voci italiane `if_sara` e `im_nicola`. |
| wav2vec2-xlsr-53-espeak-cv-ft (Meta) | Apache-2.0 | Riconoscitore di fonemi, solo per i controlli. |
| Piper, voce `paola` | dati di addestramento CC0-1.0 | Registrazioni rese pubbliche da chi le ha fatte. |
| Piper, voce `serena` | dati di addestramento CC BY 4.0 | Va citato «serena-synthetic-it-27h by Marco Baccarani». |

Le licenze vanno ricontrollate sulla pagina del modello quando lo si scarica: possono cambiare. Nel programma
entrano solo le registrazioni; i modelli, il loro codice e gli strumenti usati per generarle (Piper ed espeak-ng
sono GPL) restano fuori dal pacchetto. Questa tabella è un promemoria, non una consulenza legale.
