import type { AnswerValue } from '../types';

// Autovalutazione delle misure organizzative per le strutture sanitarie (e
// per qualunque rete con servizi critici). Le domande coprono ciò che una
// misura di rete non può vedere; ogni risposta "no" o "in parte" porta nel
// piano l'azione indicata. Le aree rimandano alla guida che le approfondisce.

export type AssessAreaId = 'segmentazione' | 'medicali' | 'accessi' | 'backup' | 'continuita' | 'incidenti';

export interface AssessArea {
  id: AssessAreaId;
  title: string;
  summary: string;
  /** Guida di riferimento (identificativo della biblioteca). */
  guide: string;
}

export interface AssessQuestion {
  id: string;
  area: AssessAreaId;
  text: string;
  /** Forma breve usata nei giudizi e nel rapporto. */
  short: string;
  /** Peso nel punteggio dell'area: 3 = essenziale. */
  weight: 1 | 2 | 3;
  /** Azione del catalogo da aggiungere al piano se la misura manca. */
  action: string;
}

export const ASSESS_AREAS: AssessArea[] = [
  { id: 'segmentazione', title: 'Segmentazione', summary: 'Zone di rete separate per funzione, con regole documentate e verificate.', guide: 'segmentazione' },
  { id: 'medicali', title: 'Dispositivi medicali', summary: 'Inventario, documentazione di sicurezza e aggiornamenti concordati con i produttori.', guide: 'dispositivi-medicali-in-rete' },
  { id: 'accessi', title: 'Accessi e fornitori', summary: 'Credenziali, autenticazione a più fattori, aggiornamenti e accessi remoti dei fornitori.', guide: 'credenziali-aggiornamenti' },
  { id: 'backup', title: 'Backup', summary: 'Copie automatiche, almeno una offline, e prove di ripristino.', guide: 'backup-continuita' },
  { id: 'continuita', title: 'Continuità', summary: 'Procedure alternative, alimentazione, linee e ricambi per i servizi critici.', guide: 'continuita-servizi-critici' },
  { id: 'incidenti', title: 'Gestione degli incidenti', summary: 'Procedura, notifiche, log e formazione del personale.', guide: 'privacy-normativa-sanita' },
];

export const ASSESS_QUESTIONS: AssessQuestion[] = [
  // Segmentazione
  { id: 'seg-ospiti', area: 'segmentazione', weight: 3, action: 'plan-segmentation', short: 'rete ospiti separata', text: 'La rete ospiti è separata da quella interna e non raggiunge PC, server e dispositivi?' },
  { id: 'seg-medicali', area: 'segmentazione', weight: 3, action: 'medical-devices', short: 'zona dedicata ai dispositivi medicali', text: 'I dispositivi medicali sono in una zona dedicata, con regole che consentono solo i flussi necessari?' },
  { id: 'seg-iot', area: 'segmentazione', weight: 2, action: 'separate-iot', short: 'stampanti, telecamere e impianti separati', text: 'Stampanti, telecamere, impianti e domotica sono separati dalle postazioni di lavoro?' },
  { id: 'seg-gestione', area: 'segmentazione', weight: 2, action: 'plan-segmentation', short: 'gestione degli apparati isolata', text: 'Le interfacce di gestione di firewall, switch e access point sono raggiungibili solo da una rete o da postazioni dedicate?' },
  { id: 'seg-verifica', area: 'segmentazione', weight: 2, action: 'segment-network', short: 'regole documentate e verificate', text: 'Le regole tra le zone sono documentate e verificate dopo ogni modifica, per esempio con il test di segmentazione?' },
  // Dispositivi medicali
  { id: 'med-inventario', area: 'medicali', weight: 3, action: 'medical-devices', short: 'inventario condiviso con l\'ingegneria clinica', text: 'Esiste un inventario dei dispositivi medicali in rete, condiviso tra servizi informatici e ingegneria clinica?' },
  { id: 'med-mds2', area: 'medicali', weight: 2, action: 'medical-devices', short: 'schede MDS2 disponibili', text: 'Per i dispositivi in rete sono disponibili la scheda MDS2 o le indicazioni di sicurezza del produttore?' },
  { id: 'med-aggiornamenti', area: 'medicali', weight: 2, action: 'medical-devices', short: 'aggiornamenti concordati e registrati', text: 'Gli aggiornamenti dei dispositivi medicali sono concordati con il produttore e registrati?' },
  { id: 'med-obsoleti', area: 'medicali', weight: 2, action: 'medical-devices', short: 'piano per i dispositivi non più aggiornabili', text: 'Per i dispositivi non più aggiornabili ci sono misure compensative e un piano di sostituzione?' },
  // Accessi e fornitori
  { id: 'acc-fornitori', area: 'accessi', weight: 3, action: 'vendor-access', short: 'accessi remoti dei fornitori controllati', text: 'I fornitori accedono da remoto solo da un canale controllato, con account nominativi e accesso attivato quando serve?' },
  { id: 'acc-mfa', area: 'accessi', weight: 3, action: 'credentials-mfa', short: 'autenticazione a più fattori', text: 'L\'autenticazione a più fattori è attiva per accessi remoti, posta e account amministrativi?' },
  { id: 'acc-default', area: 'accessi', weight: 2, action: 'credentials-mfa', short: 'credenziali di fabbrica cambiate', text: 'Le credenziali predefinite di apparati e dispositivi sono state tutte cambiate?' },
  { id: 'acc-aggiornamenti', area: 'accessi', weight: 2, action: 'patch-management', short: 'aggiornamenti regolari di sistemi e apparati', text: 'Sistemi, PC e apparati di rete vengono aggiornati con una procedura regolare?' },
  { id: 'acc-contratti', area: 'accessi', weight: 1, action: 'vendor-access', short: 'contratti e nomine dei fornitori', text: 'I fornitori che trattano dati personali hanno contratti con requisiti di sicurezza e la nomina a responsabile del trattamento?' },
  // Backup
  { id: 'bak-quotidiano', area: 'backup', weight: 2, action: 'backup-offline', short: 'backup quotidiano automatico', text: 'I dati clinici e amministrativi vengono salvati ogni giorno, in automatico?' },
  { id: 'bak-offline', area: 'backup', weight: 3, action: 'backup-offline', short: 'copia offline o immutabile', text: 'Almeno una copia è offline o immutabile, cioè non cancellabile da un account compromesso?' },
  { id: 'bak-prova', area: 'backup', weight: 3, action: 'backup-offline', short: 'prove di ripristino', text: 'Il ripristino viene provato periodicamente, misurando il tempo necessario?' },
  { id: 'bak-config', area: 'backup', weight: 1, action: 'backup-offline', short: 'configurazioni degli apparati salvate', text: 'Le configurazioni di firewall, switch e access point sono salvate dopo ogni modifica?' },
  // Continuità
  { id: 'con-procedure', area: 'continuita', weight: 3, action: 'continuity-plan', short: 'procedure alternative per i servizi critici', text: 'Ogni servizio critico ha una procedura alternativa, nota al personale, per quando il sistema o la rete si fermano?' },
  { id: 'con-ups', area: 'continuita', weight: 2, action: 'continuity-plan', short: 'apparati di rete sotto UPS', text: 'Gli apparati di rete principali sono protetti da UPS con batterie verificate?' },
  { id: 'con-linea', area: 'continuita', weight: 1, action: 'continuity-plan', short: 'linea Internet di riserva', text: 'C\'è una seconda linea Internet, se i servizi in cloud sono indispensabili?' },
  { id: 'con-ricambi', area: 'continuita', weight: 2, action: 'continuity-plan', short: 'ricambi o assistenza con tempi garantiti', text: 'Per gli apparati centrali ci sono ricambi o assistenza con tempi di intervento garantiti?' },
  { id: 'con-contatti', area: 'continuita', weight: 1, action: 'continuity-plan', short: 'documenti consultabili senza rete', text: 'Contatti, schemi e procedure di emergenza sono consultabili anche senza rete?' },
  // Incidenti
  { id: 'inc-procedura', area: 'incidenti', weight: 3, action: 'incident-response', short: 'procedura per gli incidenti', text: 'Esiste una procedura scritta per gli incidenti informatici, con ruoli e primi passi, nota al personale?' },
  { id: 'inc-notifiche', area: 'incidenti', weight: 2, action: 'incident-response', short: 'notifiche previste', text: 'Sono chiari tempi e destinatari delle notifiche (Garante entro 72 ore; CSIRT Italia per i soggetti NIS2)?' },
  { id: 'inc-log', area: 'incidenti', weight: 2, action: 'incident-response', short: 'log conservati e consultabili', text: 'I log di firewall, server e accessi amministrativi sono conservati e consultabili?' },
  { id: 'inc-formazione', area: 'incidenti', weight: 2, action: 'incident-response', short: 'formazione del personale', text: 'Il personale riceve formazione periodica su phishing e segnalazione degli incidenti?' },
  { id: 'inc-esercitazione', area: 'incidenti', weight: 1, action: 'incident-response', short: 'esercitazioni', text: 'Almeno una volta l\'anno si simula un incidente, per esempio un ransomware, per provare la procedura?' },
];

const POINTS: Record<Exclude<AnswerValue, 'na'>, number> = { yes: 1, partial: 0.5, no: 0 };

export interface AreaScore {
  area: AssessArea;
  /** 0-100; null se nessuna domanda applicabile ha una risposta. */
  score: number | null;
  /** Domande con risposta (escluse le non applicabili). */
  answered: number;
  /** Domande dell'area senza risposta. */
  open: number;
  total: number;
  /** Misure assenti o parziali, con la risposta data. */
  gaps: { q: AssessQuestion; answer: 'no' | 'partial' }[];
}

export function scoreAssessment(answers: Record<string, AnswerValue | undefined>): AreaScore[] {
  return ASSESS_AREAS.map((area) => {
    const qs = ASSESS_QUESTIONS.filter((q) => q.area === area.id);
    let got = 0;
    let max = 0;
    let answered = 0;
    let open = 0;
    const gaps: AreaScore['gaps'] = [];
    for (const q of qs) {
      const a = answers[q.id];
      if (!a) {
        open++;
        continue;
      }
      if (a === 'na') continue;
      answered++;
      got += POINTS[a] * q.weight;
      max += q.weight;
      if (a === 'no' || a === 'partial') gaps.push({ q, answer: a });
    }
    return { area, score: max ? Math.round((100 * got) / max) : null, answered, open, total: qs.length, gaps };
  });
}
