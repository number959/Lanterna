import type { Adapter, Scan } from './types';

/** Scheda principale: quella attiva con il gateway, preferendo quella del gateway misurato. */
export function primaryAdapter(scan: Scan): Adapter | undefined {
  const up = scan.adapters.filter((a) => a.up && a.kind !== 'loopback');
  const gw = scan.gateway?.ip;
  return (
    (gw && up.find((a) => a.gateways.includes(gw))) ||
    up.find((a) => a.gateways.length > 0 && a.ipv4.length > 0) ||
    up.find((a) => a.ipv4.length > 0)
  );
}
