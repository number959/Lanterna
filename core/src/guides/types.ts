// Modello delle guide di STARNET Polaris.
//
// Le guide sono dati, non pagine: un articolo è una sequenza di blocchi
// tipizzati che l'interfaccia (e in futuro le versioni Android ed ESP32)
// impagina a modo suo. Nel testo dei blocchi è ammesso un markup minimo:
//   **grassetto**   `codice`   [[id-guida]] o [[id-guida|testo del collegamento]]

export type ChapterId = 'fondamenti' | 'wifi' | 'cablata' | 'servizi' | 'sicurezza' | 'complesse' | 'diagnosi';

export type DiagramId = 'osi' | 'subnet' | 'dhcp' | 'channels24' | 'roaming' | 'vlan' | 'clinic';

export type NoteKind = 'tip' | 'warn' | 'clinic';

export type Block =
  | { t: 'p'; text: string }
  | { t: 'h'; text: string }
  | { t: 'list'; items: string[]; ordered?: boolean }
  | { t: 'table'; head: string[]; rows: string[][]; caption?: string }
  | { t: 'note'; kind: NoteKind; title?: string; text: string }
  | { t: 'code'; text: string; caption?: string }
  | { t: 'diagram'; id: DiagramId; caption: string };

export type Level = 'base' | 'intermedio' | 'avanzato';

export interface Guide {
  /** Identificativo stabile (usato nei collegamenti e nelle preferenze). */
  id: string;
  chapter: ChapterId;
  title: string;
  /** Una o due frasi: cosa si impara. */
  summary: string;
  level: Level;
  blocks: Block[];
  /** Valori misurati (chiavi delle metriche) e azioni (chiavi del catalogo) collegati. */
  metrics?: string[];
  actions?: string[];
  /** Parole chiave aggiuntive per la ricerca. */
  tags?: string[];
}

export interface Chapter {
  id: ChapterId;
  title: string;
  summary: string;
}

export interface GlossaryTerm {
  term: string;
  /** Forma estesa della sigla, se è una sigla. */
  full?: string;
  def: string;
  /** Guida in cui l'argomento è spiegato per esteso. */
  guide?: string;
}
