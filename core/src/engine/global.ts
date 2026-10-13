// Entry point per gli ambienti senza moduli ES (goja nell'eseguibile Windows,
// in futuro il WebView di Android): espone il motore come variabile globale.
import { analyze, ENGINE_VERSION } from './analyze';
import { renderText } from './report';
import type { Scan } from './types';

const api = {
  version: ENGINE_VERSION,
  analyze,
  renderText,
  /** Comodità per gli host: JSON in ingresso, JSON in uscita. */
  analyzeJson(scanJson: string): string {
    return JSON.stringify(analyze(JSON.parse(scanJson) as Scan));
  },
  reportText(scanJson: string, verbose: boolean): string {
    const scan = JSON.parse(scanJson) as Scan;
    return renderText(scan, analyze(scan), { verbose });
  },
};

(globalThis as unknown as { PolarisEngine: typeof api }).PolarisEngine = api;
