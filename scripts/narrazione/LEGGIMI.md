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
| `ascolto.py`, `ascolto.html` | Costruisce una pagina per ascoltare tutta la narrazione, con ogni frase numerata. |
| `disegna.py` | Crea una voce nuova da una descrizione a parole (Qwen3-TTS VoiceDesign). |
| `voci/voci.json` | Le descrizioni delle voci create così e la frase di prova. |
| `voci/<nome>.flac` | Il campione di ogni voce creata: **è** la voce, va tenuto. |
| `crediti.mjs` | Scrive i crediti della voce in `THIRD_PARTY_NOTICES.md` (lo chiama `scripts/notices.sh`). |
| `prova.py` | Prove veloci di numeri in lettere, pronunce e confronto con il testo capito (serve solo numpy). |

## Rifare una frase cambiata

Un test (`core/test/narrazione.test.ts`) fallisce se una frase di `video.ts` non ha la sua registrazione con il
testo di oggi. Per rimettere le cose a posto, con la stessa voce:

```sh
node scripts/narrazione/frasi.mjs frasi.json
python scripts/narrazione/genera.py --frasi frasi.json --solo-mancanti <le stesse opzioni della voce in uso>
bash scripts/notices.sh
```

`--solo-mancanti` rifà soltanto le frasi nuove o cambiate e toglie le registrazioni di quelle che non esistono
più. Le opzioni della voce in uso sono qui sotto, alla voce che `narrazione.ts` dichiara in `VOCE`.

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
  `genera.py --motore piper --modello ... --fonemi` stampa i fonemi di ogni frase.
- **Qwen3-TTS** legge il testo come farebbe una persona e le parole inglesi le sa: gli si scrivono per esteso solo
  le sigle («DHCP» diventa «di acca ci pi») e i numeri in lettere, perché scritti in cifre a volte li legge in
  un'altra lingua.

Se una parola suona male si aggiunge una riga a `REGOLE` o a `REGOLE_LLM` e si rifanno le frasi che la contengono:
`genera.py ... --solo-mancanti --rifai "parola"`. Con Qwen3-TTS, se una frase è venuta male senza un motivo,
basta un'altra presa: `--solo-mancanti --rifai "inizio della frase" --seme 1`.

## La verifica all'ascolto

Qwen3-TTS sceglie a caso tra pronunce e intonazioni possibili, ed è per questo che suona naturale. Ha due difetti,
e `genera.py` li tiene a bada rifacendo le frasi che non passano l'esame, con un altro seme, fino a `--tentativi`
prese (tre, se non dici altro), e tenendo la migliore.

- **Ogni tanto salta o storpia una parola.** Con `--verifica small` ogni registrazione viene riascoltata da un
  riconoscitore vocale (Whisper, modello `small`): non passa se il testo capito si scosta da quello scritto per più
  del 4% dei caratteri (`--soglia`) o se la durata è fuori misura.
- **Cambia registro da una frase all'altra**: una calma e grave, la successiva acuta e concitata. Di ogni presa si
  misura l'altezza mediana della voce; dopo la prima passata il riferimento è la mediana di tutte le frasi, e non
  passa chi se ne stacca per più del 10% (`--tolleranza`; `--altezza 260` fissa il riferimento a mano,
  `--senza-altezza` rinuncia al controllo). Nella prima registrazione di prova, senza questo controllo, le frasi
  andavano da 220 a 360 Hz.

`--solo-mancanti --ricontrolla` rimette all'esame anche le registrazioni già fatte: serve dopo un'interruzione, o
per stringere i margini senza rifare tutto.

Alla fine lo script elenca le frasi rimaste fuori dai margini. **Vanno riascoltate, non sono per forza sbagliate**:
il riconoscitore sbaglia a sua volta, soprattutto su sigle e parole inglesi («VLAN separate» capito «villan
separate»). `--rapporto file.json` salva che cosa ha capito frase per frase.

`genera.py --frasi frasi.json --riascolta` non registra nulla: riascolta le registrazioni che ci sono già, cioè
quelle che finiscono nel programma, ne misura l'altezza e dà gli stessi elenchi.

`controlla.py --frasi frasi.json` fa un controllo diverso, sul suono: per ogni registrazione misura il ritmo, il
volume, le pause interne e l'altezza della voce e segnala quelle che si staccano dalle altre (una frase molto più
lenta, una pausa lunga in mezzo, una voce più acuta del resto). Con `--modello M/Qwen3-TTS-12Hz-0.6B-Base` confronta
anche l'impronta della voce di ogni registrazione con la media: serve a trovare le frasi in cui la voce è «scivolata».

I due controlli dicono se le parole si capiscono e se le registrazioni si somigliano. **Non dicono se la voce è
gradevole**: quello si sente solo con le orecchie.

Per questo c'è `ascolto.py`: `python scripts/narrazione/ascolto.py --frasi frasi.json --uscita narrazione.html` scrive
una pagina con le nove videoguide, ogni frase numerata (3.12 è la dodicesima della terza) e ascoltabile da sola o di
seguito, con le stesse pause del programma. Chi ascolta dice i numeri delle frasi da rifare.

## Che cosa serve

- Python 3.10 o successivo e `ffmpeg` con `libopus`.
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
repository: pesano da 60 MB (Piper) a oltre 4 GB (VoiceDesign).

Tempi su quattro processori senza scheda grafica: Piper e Kokoro leggono tutta la narrazione (147 frasi, circa
12 minuti) in pochi minuti; Qwen3-TTS 0.6B impiega quasi cinque secondi per ogni secondo di voce a una frase per
volta e meno di tre con `--lotto 8` (misurati; `--lotto 4` sta in mezzo e chiede circa 9 GB di memoria, `--lotto 8`
circa 12). Con `--lotto 4`, la verifica e le prese rifatte, tutta la narrazione chiede intorno a un'ora e mezza. Se si
interrompe, `--solo-mancanti` riprende da dov'era.

## Licenze

| Modello | Licenza | Note |
|---|---|---|
| Qwen3-TTS (Alibaba Cloud) | Apache-2.0 | Base, CustomVoice e VoiceDesign. |
| Kokoro-82M (hexgrad) | Apache-2.0 | Voci italiane `if_sara` e `im_nicola`. |
| Piper, voce `paola` | dati di addestramento CC0-1.0 | Registrazioni rese pubbliche da chi le ha fatte. |
| Piper, voce `serena` | dati di addestramento CC BY 4.0 | Va citato «serena-synthetic-it-27h by Marco Baccarani». |

Le licenze vanno ricontrollate sulla pagina del modello quando lo si scarica: possono cambiare. Nel programma
entrano solo le registrazioni; i modelli, il loro codice e gli strumenti usati per generarle (Piper ed espeak-ng
sono GPL) restano fuori dal pacchetto. Questa tabella è un promemoria, non una consulenza legale.
