import { certNormalize } from '../engine/certs';
import type { CertData, CertResult, CertTarget, CpuBench, DiskBench, Inventory, InventoryHost, ReachData, ReachResult, ReachTarget, Scan, SpeedLatency, SpeedTest } from '../engine/types';

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

// ---------------------------------------------------------------- Certificati

const DAY = 86_400_000;
/** Porte di servizi che non usano TLS diretto: il controllo non riesce, come con l'agente. */
const PLAIN_PORTS = new Set([21, 22, 23, 53, 80, 104, 110, 139, 143, 389, 445, 554, 1883, 2575, 8080, 11112]);

/** Impronta plausibile e stabile (64 cifre esadecimali), non quella di un certificato reale. */
function demoFingerprint(seed: string): string {
  let out = '';
  for (let i = 0; out.length < 64; i++) out += hash(`${seed}#${i}`).toString(16).toUpperCase().padStart(8, '0');
  return out.slice(0, 64);
}

/** Date coerenti con il momento del controllo: stessi giorni residui e stessa durata. */
function datesFrom(now: number, daysLeft: number, lifetimeDays: number) {
  const notAfter = now + daysLeft * DAY + 5 * 3_600_000;
  return { notAfter: new Date(notAfter).toISOString().replace(/\.\d{3}Z$/, 'Z'), notBefore: new Date(notAfter - lifetimeDays * DAY).toISOString().replace(/\.\d{3}Z$/, 'Z') };
}

/**
 * Esiti plausibili del controllo dei certificati: quelli già presenti nella
 * demo per gli stessi servizi (con le date spostate a oggi), un certificato
 * autofirmato per il pannello del router, porta chiusa se l'analisi l'ha vista
 * chiusa o ha visto il pannello solo in HTTP, nessun TLS sulle porte dei servizi in chiaro, altrimenti un
 * certificato coerente con la rete (CA interna nei domini, autofirmato a casa).
 */
export function simulatedCerts(scan: Scan, targets: CertTarget[], now = Date.now()): CertData {
  const known = scan.infra?.certs?.results ?? [];
  const gw = scan.gateway;
  const pcIp = scan.adapters.find((a) => a.up && a.ipv4.length)?.ipv4[0]?.split('/')[0] ?? '192.168.1.2';
  const prefix = pcIp.split('.').slice(0, 3).join('.');
  const domain = scan.agent.domain;
  const results = targets.map((t): CertResult => {
    const n = certNormalize(t.host, t.port);
    const host = 'error' in n ? t.host : n.host;
    const port = 'error' in n ? t.port || 443 : n.port;
    const base: CertResult = { ...(t.label ? { label: t.label } : {}), host, port, ok: false, daysLeft: 0, nameMatch: false };
    if ('error' in n) return { ...base, error: n.error };
    const k = known.find((r) => r.host.toLowerCase() === host.toLowerCase() && r.port === port);
    if (k) return { ...k, label: t.label, ...(k.ok && k.lifetimeDays ? datesFrom(now, k.daysLeft, k.lifetimeDays) : {}) };
    const h = hash(`${host}:${port}`);
    const isV4 = ipv4.test(host);
    const isIp = isV4 || host.includes(':');
    if (isV4 && !isPrivate(host) && !host.startsWith('127.')) return { ...base, error: 'indirizzo pubblico: si controllano solo i servizi della rete locale' };
    const ip = isIp ? host : `${prefix}.${(h % 200) + 20}`;
    const at = { ...base, ip };
    if (gw && ip === gw.ip && gw.ports?.some((p) => p.port === port && !p.open)) return { ...at, error: 'porta chiusa: nessun servizio in ascolto' };
    // L'analisi ha visto il pannello solo in HTTP: non si inventa un pannello cifrato su un'altra porta.
    if (gw && ip === gw.ip && gw.web?.https === false && !gw.ports?.some((p) => p.port === port && p.open))
      return { ...at, error: 'porta chiusa: nessun servizio in ascolto' };
    // Il Desktop remoto passa a TLS solo dopo una sua negoziazione: il controllo diretto non riesce.
    if (port === 3389) return { ...at, error: 'negoziazione TLS non riuscita' };
    if (PLAIN_PORTS.has(port)) return { ...at, error: 'il servizio su questa porta non usa TLS' };
    const smtp = port === 25 || port === 587;
    const common = { ...at, ok: true, ...(smtp ? { starttls: 'smtp' } : {}), chainLen: 1, fingerprint: demoFingerprint(`${host}:${port}`) };
    if (gw && ip === gw.ip) {
      // Pannello del router o del firewall: certificato autofirmato del dispositivo, valido per anni.
      const life = 7300;
      const left = 4800 + (h % 900);
      return {
        ...common,
        tlsVersion: 'TLS 1.2',
        cipher: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        subject: domain ? 'firewall' : 'router.home',
        issuer: domain ? 'firewall' : 'router.home',
        ips: [gw.ip],
        ...(domain ? {} : { dnsNames: ['router.home'] }),
        ...datesFrom(now, left, life),
        daysLeft: left,
        lifetimeDays: life,
        keyType: 'RSA',
        keyBits: 2048,
        sigAlg: 'SHA256-RSA',
        selfSigned: true,
        nameMatch: true,
        trust: 'untrusted-root',
      };
    }
    const life = domain ? 397 : 3650;
    const left = 90 + (h % 260);
    const names = isIp ? { ips: [host] } : { dnsNames: [host] };
    return {
      ...common,
      tlsVersion: h % 3 === 0 ? 'TLS 1.2' : 'TLS 1.3',
      cipher: h % 3 === 0 ? 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384' : 'TLS_AES_128_GCM_SHA256',
      subject: host,
      issuer: domain ? 'CA Interna' : host,
      ...(domain ? { issuerOrg: domain } : {}),
      ...names,
      ...datesFrom(now, left, life),
      daysLeft: left,
      lifetimeDays: life,
      keyType: h % 2 ? 'ECDSA P-256' : 'RSA',
      keyBits: h % 2 ? 256 : 2048,
      // Firma coerente con la chiave: un autofirmato si firma con la propria, e la CA interna della demo usa lo stesso tipo.
      sigAlg: h % 2 ? 'ECDSA-SHA256' : 'SHA256-RSA',
      ...(domain ? { chainLen: 2, trust: 'trusted' as const } : { selfSigned: true, trust: 'untrusted-root' as const }),
      nameMatch: true,
    };
  });
  return { checkedAt: new Date(now).toISOString().replace(/\.\d{3}Z$/, 'Z'), results };
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
  // MB/s: [SEQ1M Q8T1 lettura, scrittura, SEQ1M Q1T1 lettura, scrittura,
  //        RND4K Q32T1 lettura, scrittura, RND4K Q1T1 lettura, scrittura]
  let v: number[];
  let fileMB = 1024;
  let note: string | undefined;
  if (usb) {
    v = [36.8, 8.1, 32.4, 7.5, 3.6, 0.05, 3.1, 0.04];
    fileMB = 112;
    note = 'Unità lenta: in 15 secondi il file di prova ha raggiunto 112 MB.';
  } else if (disk?.media === 'hdd') v = failing ? [45.1, 48.3, 38.2, 41.5, 0.62, 0.95, 0.31, 0.86] : [178, 168, 162, 151, 1.9, 1.8, 0.92, 1.7];
  else if (disk?.media === 'ssd')
    v = /nvme/i.test(disk.bus ?? '')
      ? full
        ? [2150, 720, 1640, 590, 380, 165, 41.8, 61.5]
        : [3480, 3050, 2870, 1410, 610, 420, 58.6, 152]
      : [560, 520, 512, 468, 395, 330, 31.2, 88];
  else v = [150, 110, 120, 96, 24, 9, 8.4, 4.1];
  const iops = (mbs: number) => Math.round((mbs * 1e6) / 4096);
  const prepMs = Math.min(15000, (fileMB * 1.048576 * 1000) / v[3]);
  return {
    startedAt: new Date().toISOString(),
    drive: drive.toUpperCase(),
    fileMB,
    seqQ8ReadMBs: v[0],
    seqQ8WriteMBs: v[1],
    seqReadMBs: v[2],
    seqWriteMBs: v[3],
    rndQ32ReadMBs: v[4],
    rndQ32ReadIops: iops(v[4]),
    rndQ32WriteMBs: v[5],
    rndQ32WriteIops: iops(v[5]),
    rndReadMBs: v[6],
    rndReadIops: iops(v[6]),
    rndWriteMBs: v[7],
    rndWriteIops: iops(v[7]),
    durationMs: Math.round(prepMs + 32000),
    note,
  };
}

/**
 * Test di velocità simulato per le demo: nessun traffico, nessun dato a
 * M-Lab. La casa è in Wi-Fi a 2,4 GHz su una linea FTTC con l'upload che fa
 * coda nel modem (bufferbloat alto); la clinica è in Wi-Fi su fibra (il Wi-Fi
 * fa da limite), con i ping bloccati dal firewall (sonde TCP) e un po' di
 * coda in upload.
 */
export function simulatedSpeed(scan: Scan, now = Date.now()): SpeedTest {
  const clinic = !!scan.agent.domain;
  const targets = scan.internet?.targets ?? [];
  const answered = targets.filter((t) => t.received > 0 && t.avgMs !== undefined);
  const tcp = answered.length > 0 && answered.every((t) => t.method === 'tcp');
  // Latenza a riposo: quella che la demo ha misurato verso 1.1.1.1, il server
  // delle sonde, così il test e la vista Internet dicono lo stesso numero e
  // la latenza sotto carico non scende mai sotto quella normale.
  const probe = answered.find((t) => t.target === '1.1.1.1') ?? answered[0];
  const idle = Math.round((probe ? (probe.avgMs as number) : clinic ? 13 : 24) * 10) / 10;
  const v = clinic
    ? { down: 138.6, up: 121.4, bd: 6.2, bdp: 11.8, bu: 41.5, bup: 63.0, retrans: 0.4, rtt: 7.8, site: 'mil05', machine: 'mlab1-mil05.mlab-oti.measurement-lab.org' }
    : { down: 61.8, up: 18.7, bd: 19.4, bdp: 31.2, bu: 142.6, bup: 188.4, retrans: 1.3, rtt: 21.6, site: 'mil07', machine: 'mlab3-mil07.mlab-oti.measurement-lab.org' };
  const r1 = (x: number) => Math.round(x * 10) / 10;
  const lat = (bloat: number, p95: number, sent: number, lost: number): SpeedLatency => ({
    sent,
    received: sent - lost,
    minMs: r1(idle + bloat * 0.4),
    medianMs: r1(idle + bloat),
    p95Ms: r1(idle + p95),
  });
  const every = tcp ? 2 : 4;
  return {
    startedAt: new Date(now).toISOString(),
    durationMs: 27400,
    provider: 'mlab-ndt7',
    server: { city: 'Milan', country: 'IT', site: v.site, machine: v.machine },
    probe: '1.1.1.1',
    probeMethod: tcp ? 'tcp' : 'icmp',
    idle: { sent: 5 * every, received: 5 * every, minMs: r1(idle * 0.9), medianMs: idle, p95Ms: r1(idle * 1.25) },
    download: {
      mbps: v.down,
      bytes: Math.round((v.down * 1e6 * 10) / 8),
      ms: 10000,
      source: 'client',
      minRttMs: v.rtt,
      rttMs: r1(v.rtt + v.bd * 0.3),
      retransPct: v.retrans,
      latency: lat(v.bd, v.bdp, 10 * every, 0),
      bloatMs: v.bd,
      bloatP95Ms: v.bdp,
    },
    upload: {
      mbps: v.up,
      bytes: Math.round((v.up * 1e6 * 10) / 8),
      ms: 10000,
      source: 'server',
      minRttMs: v.rtt,
      latency: lat(v.bu, v.bup, 10 * every, clinic ? 0 : 2),
      bloatMs: v.bu,
      bloatP95Ms: v.bup,
    },
    simulated: true,
  };
}
