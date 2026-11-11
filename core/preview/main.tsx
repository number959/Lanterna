// Anteprima autonoma della mappa della rete con i dati dimostrativi: lo stesso
// componente dell'applicazione (src/ui/netmap.tsx), compilato in un'unica
// pagina con scripts/preview-netmap.mjs. Il tema segue quello di chi guarda:
// attributo data-theme della pagina che la ospita oppure preferenza di sistema.
import '@radix-ui/colors/green.css';
import '@radix-ui/colors/green-alpha.css';
import '@radix-ui/colors/indigo.css';
import '@radix-ui/colors/indigo-alpha.css';
import '@radix-ui/colors/amber.css';
import '@radix-ui/colors/amber-alpha.css';
import '@radix-ui/colors/red.css';
import '@radix-ui/colors/red-alpha.css';
import '@radix-ui/colors/green-dark.css';
import '@radix-ui/colors/green-dark-alpha.css';
import '@radix-ui/colors/indigo-dark.css';
import '@radix-ui/colors/indigo-dark-alpha.css';
import '@radix-ui/colors/amber-dark.css';
import '@radix-ui/colors/amber-dark-alpha.css';
import '@radix-ui/colors/red-dark.css';
import '@radix-ui/colors/red-dark-alpha.css';
import '../src/ui/fonts.css';
import '../src/ui/styles.css';
import './preview.css';
import { LazyMotion, MotionConfig, domMax } from 'motion/react';
import { StrictMode, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { analyze } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { BrandSymbol } from '../src/ui/brand';
import { Segmented } from '../src/ui/components';
import { NetMap } from '../src/ui/netmap';
import { TrafficExplorer } from '../src/ui/traffic';

/** Classe dark/light su <html> dal tema di chi guarda (data-theme, poi preferenza di sistema). */
function syncTheme() {
  const el = document.documentElement;
  const attr = el.getAttribute('data-theme');
  const dark = attr === 'dark' || (attr !== 'light' && !window.matchMedia?.('(prefers-color-scheme: light)').matches);
  el.classList.toggle('dark', dark);
  el.classList.toggle('light', !dark);
}
syncTheme();
new MutationObserver(syncTheme).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
window.matchMedia?.('(prefers-color-scheme: light)').addEventListener?.('change', syncTheme);

type DemoId = 'casa' | 'clinica';

function Preview() {
  const [demo, setDemo] = useState<DemoId>('clinica');
  const scan = demo === 'casa' ? demoScan : clinicScan;
  const analysis = useMemo(() => analyze(scan), [scan]);
  return (
    <main className="pv">
      <header className="pv-head">
        <BrandSymbol size={34} title="STARNET" />
        <div className="pv-titles">
          <h1>Mappa della rete e traffico</h1>
          <p>Anteprima della versione 0.13.1 di STARNET Polaris, con i dati dimostrativi di una casa e di un poliambulatorio.</p>
        </div>
      </header>
      <section className="card pv-card">
        <div className="card-head">
          <h2>{demo === 'casa' ? 'Casa · rete Wi-Fi con un router' : 'Poliambulatorio · VLAN, firewall e access point'}</h2>
          <span className="spacer" />
          <Segmented
            value={demo}
            onChange={setDemo}
            label="Rete dimostrativa"
            options={[
              { id: 'clinica', label: 'Poliambulatorio' },
              { id: 'casa', label: 'Casa' },
            ]}
          />
        </div>
        <NetMap key={demo} scan={scan} analysis={analysis} height={640} />
      </section>
      <section className="card pv-card">
        <div className="card-head">
          <h2>Il traffico passo passo</h2>
          <span className="sub">che cosa passa in rete quando il PC apre un sito, riceve l'indirizzo, fa un ping o stampa</span>
        </div>
        <TrafficExplorer key={demo} scan={scan} analysis={analysis} />
      </section>
      <section className="pv-notes">
        <h2>Cosa mostra</h2>
        <ul>
          <li>
            <b>Il tipo di ogni dispositivo</b>, riconosciuto da segnali che non richiedono di forzare nulla: ruolo nella rete, produttore dal MAC, servizi che il
            dispositivo annuncia da solo (mDNS, UPnP), nome, TTL delle risposte. Tocca un dispositivo per vedere perché è stato riconosciuto così e con quale
            confidenza; il punto interrogativo segna le ipotesi da verificare.
          </li>
          <li>
            <b>Da dove passa il traffico</b> di questo PC: verso Internet, verso il server DNS e verso i servizi verificati. I percorsi bloccati come previsto
            dal firewall si fermano con un segnale di stop; quelli che passano anche se non dovrebbero sono in rosso.
          </li>
          <li>
            <b>Il traffico passo passo</b>: per alcune azioni comuni (aprire un sito, ricevere l'indirizzo, un ping, il percorso verso Internet, i servizi
            verificati, una stampa) i pacchetti che il protocollo prevede, con gli indirizzi e i tempi misurati dall'analisi: vista della rete, vista a
            sequenza e tabella dei pacchetti come in un analizzatore di rete. È una ricostruzione didattica, non una registrazione del traffico.
          </li>
          <li>
            <b>Le zone</b>: la rete del PC, le altre sottoreti e VLAN scoperte e le reti Wi-Fi trasmesse dagli stessi access point, che di solito sono VLAN
            separate.
          </li>
        </ul>
        <p className="faint">Dati dimostrativi. Polaris vede il traffico del PC su cui gira, non quello degli altri dispositivi.</p>
      </section>
    </main>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <LazyMotion features={domMax} strict>
      <MotionConfig reducedMotion="user">
        <Preview />
      </MotionConfig>
    </LazyMotion>
  </StrictMode>,
);
