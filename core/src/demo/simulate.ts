import type { CpuBench, DiskBench, Inventory, InventoryHost, ReachData, ReachResult, ReachTarget, Scan } from '../engine/types';

// Simulazioni per le reti dimostrative: senza agente l'interfaccia mostra
// comunque come funzionano inventario e verifiche, sempre indicandole come
// simulate. I risultati sono deterministici (stessi dati, stesso esito).

function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isPrivate(ip: string): boolean {
  const m = ipv4.exec(ip);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

const NAMES = ['nas', 'stampante', 'tv-soggiorno', 'portatile-anna', 'telefono', 'tablet', 'presa-smart', 'telecamera-ingresso', 'console'];

/** Inventario plausibile: quello della demo, se c'è, altrimenti ricavato dai dispositivi della scansione. */
export function simulatedInventory(scan: Scan): Inventory {
  const now = new Date().toISOString();
  if (scan.infra?.inventory) return { ...scan.infra.inventory, startedAt: now };
  const ad = scan.adapters.find((a) => a.up && a.ipv4.length && a.gateways.length) ?? scan.adapters[0];
  const [ip = '192.168.1.2', prefixText = '24'] = (ad?.ipv4[0] ?? '').split('/');
  // Come l'agente: oltre /22 si esamina solo il blocco /24 del PC.
  const p = Number(prefixText);
  const prefix = p >= 22 && p <= 30 ? p : 24;
  const toNum = (a: string) => a.split('.').reduce((s, x) => s * 256 + Number(x), 0);
  const toIp = (v: number) => [24, 16, 8, 0].map((sh) => (v >>> sh) & 255).join('.');
  const base = (toNum(ip) & ((0xffffffff << (32 - prefix)) >>> 0)) >>> 0;
  const net = `${toIp(base)}/${prefix}`;
  const suffix = scan.agent.domain ? `.${scan.agent.domain}` : '.home';
  const hosts: InventoryHost[] = [];
  const gw = scan.gateway;
  if (gw) hosts.push({ ip: gw.ip, mac: gw.mac, name: `router${suffix}`, rttMs: gw.ping?.avgMs ?? 2, gateway: true });
  (scan.lan?.neighbors ?? [])
    .filter((n) => n.ip !== gw?.ip && n.ip !== ip)
    .forEach((n, i) => {
      const h = hash(n.ip);
      const random = !!n.mac && (parseInt(n.mac.slice(0, 2), 16) & 2) === 2;
      const name = random ? undefined : NAMES[i % NAMES.length];
      hosts.push({
        ip: n.ip,
        mac: n.mac,
        ...(name ? { name: `${name}${suffix}` } : {}),
        ...(name && i % 3 === 0 ? { netbios: name.toUpperCase().slice(0, 15) } : {}),
        ...(i % 4 === 3 ? {} : { rttMs: 2 + (h % 180) / 10 }),
        ...(random ? { randomMac: true } : {}),
      });
    });
  hosts.push({ ip, mac: ad?.mac, ...(scan.agent.host ? { name: `${scan.agent.host.toLowerCase()}${suffix}` } : {}), self: true });
  hosts.sort((a, b) => toNum(a.ip) - toNum(b.ip));
  return {
    subnet: net,
    adapter: ad?.name,
    scanned: Math.pow(2, 32 - prefix) - 3,
    ...(p < 22 ? { note: `La sottorete /${p} contiene troppi indirizzi per un esame prudente: è stato esaminato solo il blocco ${net} in cui si trova il PC.` } : {}),
    startedAt: now,
    durationMs: 9000 + (hash(net) % 4000),
    hosts,
  };
}

/** Esiti plausibili: quelli già presenti nella demo per le stesse destinazioni, altrimenti coerenti con l'attesa. */
export function simulatedReach(scan: Scan, targets: ReachTarget[]): ReachData {
  const known = scan.infra?.reach?.results ?? [];
  const from = scan.adapters.find((a) => a.up && a.ipv4.length)?.ipv4[0]?.split('/')[0];
  const results = targets.map((t): ReachResult => {
    const port = t.port || 0;
    const k = known.find((r) => r.host === t.host && (r.port || 0) === port && r.expect === t.expect);
    if (k) return { ...k, label: t.label };
    const h = hash(`${t.host}:${port}`);
    const ip = ipv4.test(t.host) ? t.host : `10.20.${h % 200}.${((h >>> 8) % 250) + 2}`;
    const base: ReachResult = { ...t, ip, status: 'error', ok: false };
    if (!isPrivate(ip)) return { ...base, status: 'refused', error: 'destinazione non privata: le verifiche si fanno solo verso indirizzi della rete interna' };
    if (t.expect === 'reachable') return { ...base, status: port ? 'open' : 'reply', rttMs: Math.round(20 + (h % 120)) / 10, ok: true };
    return { ...base, status: port ? 'filtered' : 'noreply', ok: true };
  });
  return { startedAt: new Date().toISOString(), from, results };
}

// ---------------------------------------------------------------- Test di velocità

/**
 * Test del processore plausibile per il PC della demo: un portatile scalda e
 * dopo pochi secondi rallenta, un PC fisso resta stabile.
 */
export function simulatedCpuBench(scan: Scan): CpuBench {
  const threads = scan.pc?.cpu?.threads ?? 8;
  const laptop = !!scan.pc?.power?.hasBattery;
  const single = laptop ? 31.6 : 44.2;
  const peak = single * (laptop ? 3.8 : 7.1);
  const samples = Array.from({ length: 20 }, (_, i) => {
    const drop = laptop ? Math.max(0.7, 1 - Math.max(0, i - 3) * 0.035) : 1 - (i % 3) * 0.004;
    return Math.round(peak * drop * (1 + ((hash(`${i}`) % 7) - 3) / 400) * 10) / 10;
  });
  const avg = (xs: number[]) => Math.round((xs.reduce((a, b) => a + b, 0) / xs.length) * 10) / 10;
  let best = 0;
  for (let i = 0; i + 3 <= 10; i++) best = Math.max(best, avg(samples.slice(i, i + 3)));
  return {
    startedAt: new Date().toISOString(),
    threads,
    singleMBs: single,
    multiMBs: best,
    sustainedMBs: avg(samples.slice(15)),
    samples,
    onAC: scan.pc?.power?.onAC,
    loadBeforePct: 6,
    durationMs: 23400,
  };
}

/** Test di un'unità coerente con il tipo e lo stato del disco della demo. */
export function simulatedDiskBench(scan: Scan, drive: string): DiskBench {
  const vol = scan.pc?.volumes?.find((v) => v.letter.toUpperCase() === drive.toUpperCase());
  const disk = scan.pc?.disks?.find((d) => d.id !== undefined && d.id === vol?.disk);
  const full = vol ? vol.freeGB / vol.sizeGB < 0.1 : false;
  const failing = disk?.health === 'warning' || disk?.health === 'unhealthy';
  const usb = vol?.kind === 'removable' || /usb/i.test(disk?.bus ?? '');
  // [lettura seq., scrittura seq., lettura 4K, scrittura 4K] in MB/s
  let v: [number, number, number, number];
  let fileMB = 1024;
  let note: string | undefined;
  if (usb) {
    v = [32.4, 7.5, 3.1, 0.04];
    fileMB = 75;
    note = 'Raggiunto il tempo massimo della scrittura (10 s): file di prova di 75 MB.';
  } else if (disk?.media === 'hdd') v = failing ? [38.2, 41.5, 0.31, 0.86] : [162, 151, 0.92, 1.7];
  else if (disk?.media === 'ssd') v = /nvme/i.test(disk.bus ?? '') ? (full ? [1640, 590, 41.8, 61.5] : [2870, 1410, 58.6, 152]) : [512, 468, 31.2, 88];
  else v = [120, 96, 8.4, 4.1];
  const iops = (mbs: number) => Math.round((mbs * 1e6) / 4096);
  return {
    startedAt: new Date().toISOString(),
    drive: drive.toUpperCase(),
    fileMB,
    seqReadMBs: v[0],
    seqWriteMBs: v[1],
    rndReadMBs: v[2],
    rndReadIops: iops(v[2]),
    rndWriteMBs: v[3],
    rndWriteIops: iops(v[3]),
    durationMs: usb ? 22000 : 31000,
    note,
  };
}

