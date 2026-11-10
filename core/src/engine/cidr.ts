// Indirizzi IPv4 e sottoreti in notazione CIDR, per la mappa e la scoperta
// delle reti. Gira anche in goja: niente Intl, niente operatori sui bit oltre
// i 31 bit (si lavora con numeri interi in virgola mobile).

export function ipNum(ip?: string): number | undefined {
  if (!ip) return undefined;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
  if (!m) return undefined;
  const o = [m[1], m[2], m[3], m[4]].map(Number);
  if (o.some((x) => x > 255)) return undefined;
  return ((o[0] * 256 + o[1]) * 256 + o[2]) * 256 + o[3];
}

export const numIp = (n: number) => [Math.floor(n / 16777216) % 256, Math.floor(n / 65536) % 256, Math.floor(n / 256) % 256, n % 256].join('.');

export interface Cidr {
  net: number;
  prefix: number;
}

export function parseCidr(c?: string): Cidr | undefined {
  if (!c) return undefined;
  const [ip, p] = c.split('/');
  const n = ipNum(ip);
  // Il prefisso, se c'è, è un numero intero da 0 a 32 ("/24", mai "/24.5" o "/").
  if (p !== undefined && !/^\d{1,2}$/.test(p)) return undefined;
  const prefix = p === undefined ? 32 : Number(p);
  if (n === undefined || !(prefix >= 0 && prefix <= 32)) return undefined;
  const size = Math.pow(2, 32 - prefix);
  return { net: n - (n % size), prefix };
}

export const cidrText = (c: Cidr) => `${numIp(c.net)}/${c.prefix}`;

export function inCidr(ip: string | undefined, c: Cidr | undefined): boolean {
  const n = ipNum(ip);
  if (n === undefined || !c) return false;
  const size = Math.pow(2, 32 - c.prefix);
  return n >= c.net && n < c.net + size;
}

/** Indirizzi privati (RFC 1918) e dello spazio condiviso degli operatori (RFC 6598). */
export function privateKind(ip?: string): 'private' | 'cgnat' | 'public' | undefined {
  const n = ipNum(ip);
  if (n === undefined) return undefined;
  const a = Math.floor(n / 16777216);
  const b = Math.floor(n / 65536) % 256;
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'private';
  if (a === 100 && b >= 64 && b <= 127) return 'cgnat';
  return 'public';
}

