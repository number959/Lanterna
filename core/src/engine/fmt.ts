// Formattazione numerica senza Intl: il motore gira anche in goja (exe
// Windows), dove toLocaleString ignorerebbe le opzioni.
export const fmt = (n: number, d = 0) => n.toFixed(d).replace('.', ',');
export const thousands = (n: number) => String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, '.');
/** Coda per gli elenchi troncati: " (e altri 3)". */
export const more = (total: number, shown: number) => (total > shown ? ` (e altri ${total - shown})` : '');
/** Numero seguito dal verbo concordato: "1 risponde", "3 rispondono". */
export const num = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
