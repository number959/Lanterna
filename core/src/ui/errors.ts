// Errori delle letture dal vivo (scheda Processi, confronto con l'elenco
// ufficiale di Windows 11), in italiano e con lo stesso testo ovunque.

/** Errore di una lettura dal vivo in italiano: un errore di rete del browser (TypeError di fetch) vuol dire che l'agente non risponde. */
export function readError(e: unknown): string {
  if (e instanceof TypeError) return 'Polaris non risponde: controlla che il programma sia ancora aperto e riprova';
  return e instanceof Error ? e.message : String(e);
}
