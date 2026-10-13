# Marchio STARNET

Master del marchio STARNET, versione 22 ("Stella Fortezza" rifinita), dal pacchetto ufficiale
`STARNET_22_Pacchetto_Alta_Qualita`. I file sono copiati senza modifiche: le impronte SHA-256 coincidono con quelle del
`MANIFEST.json` del pacchetto. Il marchio appartiene al suo titolare e non è coperto dalle licenze di `THIRD_PARTY_NOTICES.md`.

| File | Uso in STARNET Polaris |
| --- | --- |
| `STARNET_22_Logo_Colore.svg` | fonte dei tracciati: `node scripts/brand.mjs` genera `core/src/ui/brand-paths.ts` |
| `STARNET_22_Simbolo_Colore.svg` | fonte dell'icona di Windows (`windows/winres/icon.ico`) |
| `STARNET_22_Logo_Bianco.svg`, `STARNET_22_Logo_Colore.svg` | logo nel README, nelle due versioni per tema scuro e chiaro |
| `STARNET_22_Favicon.ico` | favicon dell'interfaccia (`core/public/favicon.ico`) |
| altri file | riferimento: varianti nere, icona web 512 px, note del pacchetto (`LEGGIMI-pacchetto.txt`) |

Regole della guida applicate nell'interfaccia:

- versione a colori (blu profondo `#022D62`, ciano `#00B9FE`) sui fondi chiari, versione bianca sui fondi scuri;
- solo il simbolo negli spazi piccoli (barra superiore su mobile, icona, favicon);
- proporzioni e forme invariate, nessuna ombra né effetto sul marchio. L'animazione d'entrata rivela le parti originali
  (cornice, metà della stella, lettere) e termina sempre sul logo esatto.

L'icona di Windows mette il simbolo a colori su una piastra bianca arrotondata, come l'icona Apple del pacchetto, perché il solo
simbolo blu non si vedrebbe sulla barra delle applicazioni scura. È renderizzata dal vettoriale a ogni dimensione (16-256 px)
invece di ridurre un'immagine grande.
