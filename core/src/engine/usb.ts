import { more, num } from './fmt';
import type { Finding, Scan, Severity, UsbController, UsbDevice, UsbHub, UsbInfo, UsbPort } from './types';

// Albero dei dispositivi USB, come UsbTreeView: porte in errore (sovraccarico,
// corrente o banda insufficiente, dispositivo non riconosciuto) e
// dispositivi USB 3 che vanno a velocità USB 2. L'agente legge i dati che gli
// hub conservano dall'enumerazione (IOCTL di usbioctl.h), senza interrogare i
// dispositivi e senza numeri di serie. Gira anche in goja: niente Intl.
//
// Stati della porta: USB_CONNECTION_STATUS; velocità: USB_DEVICE_SPEED e
// USB_NODE_CONNECTION_INFORMATION_EX_V2_FLAGS (Microsoft Learn, lette il
// 9/11/2026). Le spiegazioni in italiano sono di Polaris.

/** Velocità effettiva: etichetta per chi legge e posizione in classifica. */
export const USB_SPEED: Record<string, { label: string; rank: number }> = {
  low: { label: 'USB 1 (1,5 Mbit/s)', rank: 0 },
  full: { label: 'USB 1 (12 Mbit/s)', rank: 1 },
  high: { label: 'USB 2 (480 Mbit/s)', rank: 2 },
  super: { label: 'USB 3 (5 Gbit/s)', rank: 3 },
  'super-plus': { label: 'USB 3 (10 Gbit/s o più)', rank: 4 },
};

/** Che cosa fa il dispositivo, dalle classi delle sue funzioni. */
export const USB_KIND: Record<string, string> = {
  storage: 'Memoria (disco, chiavetta, lettore di schede)',
  phone: 'Telefono o dispositivo portatile',
  printer: 'Stampante',
  network: 'Scheda di rete',
  camera: 'Webcam, fotocamera o scanner',
  audio: 'Audio (cuffie, microfono, casse)',
  bluetooth: 'Bluetooth',
  smartcard: 'Lettore di smart card o chiavetta di firma',
  input: 'Tastiera, mouse o altro comando',
  serial: 'Porta seriale',
  hub: 'Hub USB',
  other: 'Altro dispositivo',
};

/** Stati della porta: titolo breve, spiegazione e gravità. */
export const USB_STATUS: Record<string, [string, string, Severity]> = {
  'failed-enumeration': [
    'dispositivo non riconosciuto',
    'Windows non è riuscito a riconoscere il dispositivo collegato: di solito un cavo difettoso, una porta sporca o danneggiata, o un dispositivo guasto',
    'warn',
  ],
  'general-failure': ['collegamento non riuscito', 'il collegamento del dispositivo non è riuscito per un motivo che Windows non precisa', 'warn'],
  overcurrent: [
    'sovraccarico elettrico',
    'la porta ha rilevato un assorbimento di corrente eccessivo e si è spenta per protezione: un dispositivo guasto, un cavo in corto o un dispositivo che chiede più corrente di quella che la porta può dare',
    'warn',
  ],
  'not-enough-power': [
    'corrente insufficiente',
    'la porta non può dare al dispositivo la corrente che chiede: succede con dischi esterni e altri dispositivi collegati a un hub senza alimentatore',
    'warn',
  ],
  'not-enough-bandwidth': [
    'banda insufficiente',
    'sul controller non resta abbastanza banda per il dispositivo: succede con più webcam o schede audio sullo stesso controller',
    'warn',
  ],
  'nested-too-deeply': ['troppi hub in cascata', 'il dispositivo è collegato dietro troppi hub uno dentro l\'altro', 'warn'],
  'legacy-hub': ['hub non supportato', 'il dispositivo è collegato a un hub vecchio che Windows non supporta', 'info'],
  enumerating: ['riconoscimento in corso', 'Windows stava ancora riconoscendo il dispositivo durante l\'analisi', 'info'],
  reset: ['reimpostazione in corso', 'il dispositivo si stava reimpostando durante l\'analisi', 'info'],
  unknown: ['stato sconosciuto', 'Windows ha indicato uno stato della porta che Polaris non conosce', 'info'],
};

/** Produttori più comuni dal Vendor ID (elenco pubblico di USB-IF): solo per mostrare un nome leggibile. */
export const USB_VENDORS: Record<string, string> = {
  '03F0': 'HP', '0403': 'FTDI', '0424': 'Microchip', '045E': 'Microsoft', '046D': 'Logitech', '04A9': 'Canon', '04B8': 'Epson',
  '04E8': 'Samsung', '04F2': 'Chicony', '04F9': 'Brother', '058F': 'Alcor Micro', '05AC': 'Apple', '05E3': 'Genesys Logic',
  '067B': 'Prolific', '0781': 'SanDisk', '0930': 'Toshiba', '0951': 'Kingston', '0A5C': 'Broadcom', '0A5F': 'Zebra',
  '0B95': 'ASIX', '0BC2': 'Seagate', '0BDA': 'Realtek', '0C45': 'Microdia', '0CF3': 'Qualcomm Atheros', '0E0F': 'VMware',
  '0E8D': 'MediaTek', '1050': 'Yubico', '1058': 'Western Digital', '10C4': 'Silicon Labs', '12D1': 'Huawei', '152D': 'JMicron',
  '1532': 'Razer', '174C': 'ASMedia', '17EF': 'Lenovo', '18D1': 'Google', '1A86': 'QinHeng', '2109': 'VIA Labs', '2357': 'TP-Link',
  '2717': 'Xiaomi', '413C': 'Dell', '8086': 'Intel', '8087': 'Intel',
};

/** Tipo di controller dal driver. */
export const USB_CONTROLLER: Record<string, string> = {
  xhci: 'USB 3 (xHCI)',
  ehci: 'USB 2 (EHCI)',
  ohci: 'USB 1 (OHCI)',
  uhci: 'USB 1 (UHCI)',
  other: 'controller USB',
};

/** Nome da mostrare: produttore (se noto e non già nel nome) e prodotto. */
export function usbDeviceLabel(d: UsbDevice): string {
  const vendor = USB_VENDORS[(d.vid || '').toUpperCase()];
  const name = (d.name || '').trim();
  if (!name) return vendor ? `${USB_KIND[d.kind] ?? 'Dispositivo'} ${vendor}` : USB_KIND[d.kind] ?? 'Dispositivo USB';
  if (!vendor || name.toLowerCase().indexOf(vendor.toLowerCase()) >= 0) return name;
  return `${vendor} ${name}`;
}

export const usbSpeedText = (d: UsbDevice) => USB_SPEED[d.speed]?.label ?? 'velocità non nota';

/** Una porta con il suo contesto nell'albero. */
export interface UsbNode {
  port: UsbPort;
  controller: UsbController;
  /** hub che contiene la porta e quanti hub ci sono sopra (0: hub radice) */
  hub: UsbHub;
  depth: number;
  /** dispositivo hub che contiene la porta (assente per l'hub radice) */
  parent?: UsbDevice;
}

/** Tutte le porte lette, in profondità, con controller e hub. */
export function usbNodes(info?: UsbInfo): UsbNode[] {
  const out: UsbNode[] = [];
  const walk = (controller: UsbController, hub: UsbHub, depth: number, parent?: UsbDevice) => {
    if (depth > 8) return;
    for (const port of hub.ports ?? []) {
      out.push({ port, controller, hub, depth, parent });
      if (port.device?.hub) walk(controller, port.device.hub, depth + 1, port.device);
    }
  };
  for (const c of info?.controllers ?? []) if (c.hub) walk(c, c.hub, 0);
  return out;
}

/** Dispositivi collegati (hub esclusi). */
export const usbDevices = (info?: UsbInfo) => usbNodes(info).filter((n) => n.port.device && n.port.device.kind !== 'hub');

/** Porte in errore (uno stato diverso da "ok"). */
export const usbPortProblems = (info?: UsbInfo) => usbNodes(info).filter((n) => n.port.status !== 'ok');

/**
 * Dispositivo più lento di quello che sa fare: USB 3 che va a velocità USB 2
 * (o meno), oppure da 10 Gbit/s che va a 5. Gli hub sono esclusi: un hub USB 3
 * compare anche come hub USB 2, per come lo vede Windows.
 */
export function usbSlow(n: UsbNode): 'usb2' | 'gen1' | undefined {
  const d = n.port.device;
  if (!d || d.kind === 'hub') return undefined;
  const rank = USB_SPEED[d.speed]?.rank;
  if (rank === undefined) return undefined;
  if (d.canSuper && rank < USB_SPEED.super.rank) return 'usb2';
  if (d.canSuperPlus && d.speed === 'super') return 'gen1';
  return undefined;
}

/** Dove sta la porta, per chi la cerca. */
export function usbWhere(n: UsbNode): string {
  const tags = [n.port.typeC ? 'USB-C' : '', n.port.visible === false ? 'interna' : ''].filter(Boolean);
  const base = n.parent ? `porta ${n.port.index} dell'hub ${usbDeviceLabel(n.parent)}` : `porta ${n.port.index} del controller ${USB_CONTROLLER[n.controller.kind] ?? 'USB'}`;
  return tags.length ? `${base} (${tags.join(', ')})` : base;
}

/** Perché un dispositivo USB 3 va a velocità USB 2, per quanto si può dire. */
export function usbSlowReason(n: UsbNode): string {
  // Una porta USB 3 (anche la metà USB 2 di un hub USB 3, che ha una porta
  // compagna) collegata in USB 2: il limite è nel cavo o nel collegamento.
  if (n.port.companion || n.port.usb3) {
    return n.parent
      ? 'la porta dell\'hub è USB 3 ma il collegamento è avvenuto in USB 2: di solito la colpa è del cavo (un cavo solo USB 2, una prolunga, un cavo di sola ricarica) o dell\'hub collegato al PC con un cavo USB 2; prova il cavo originale, oppure collegalo direttamente al PC'
      : 'la porta è USB 3 ma il collegamento è avvenuto in USB 2: di solito la colpa è del cavo (un cavo solo USB 2, una prolunga, un cavo di sola ricarica) o di una porta frontale collegata male; prova il cavo originale e una porta sul retro';
  }
  if (n.parent && n.hub.kind === 'usb2') return 'è collegato dietro un hub USB 2, che lo limita: collegalo direttamente al PC o a un hub USB 3';
  if (n.port.usb3 === false) return 'è collegato a una porta USB 2: spostalo su una porta USB 3 (spesso blu, con il simbolo SS, oppure USB-C)';
  return 'una porta, un cavo o un hub USB 2 lo limitano: prova una porta USB 3 (spesso blu, con il simbolo SS) e il cavo originale';
}

const RANK: Record<Severity, number> = { unknown: 0, ok: 1, info: 2, warn: 3, crit: 4 };
type Add = (f: Omit<Finding, 'actions'> & { actions?: string[] }) => void;

/** Giudizi sull'albero USB. */
export function analyzeUsb(scan: Scan, add: Add) {
  const usb = scan.pc?.usb;
  if (!usb || usb.read === 'none') return;
  if (usb.read === 'error') {
    add({
      id: 'pc.usb.ports',
      metric: 'pc.usb.ports',
      category: 'pc',
      title: 'Porte USB',
      value: 'non lette',
      severity: 'unknown',
      verdict: 'Windows non ha risposto alla lettura dei controller USB: ripeti l\'analisi.',
    });
    return;
  }
  const devices = usbDevices(usb);
  const problems = usbPortProblems(usb);
  // Un dispositivo non riconosciuto compare anche in Gestione dispositivi
  // (codice 43, sul bus USB) e pesa già nella voce dei dispositivi: qui
  // resta un'informazione, per non contarlo due volte.
  const counted = !!scan.pc?.devices?.items.some((d) => (d.enumerator ?? '').toUpperCase() === 'USB' && d.problem === 43);
  const twice = (n: UsbNode) => counted && n.port.status === 'failed-enumeration';
  let sev: Severity = 'ok';
  for (const n of problems) {
    let s = (USB_STATUS[n.port.status] ?? USB_STATUS.unknown)[2];
    if (twice(n) && RANK[s] > RANK.info) s = 'info';
    if (RANK[s] > RANK[sev]) sev = s;
  }
  const list = problems
    .slice(0, 4)
    .map((n) => {
      const st = USB_STATUS[n.port.status] ?? USB_STATUS.unknown;
      return `${usbWhere(n)}${n.port.device?.name ? `, ${usbDeviceLabel(n.port.device)}` : ''}: ${st[0]}`;
    })
    .join('; ');
  const first = problems[0] ? USB_STATUS[problems[0].port.status] ?? USB_STATUS.unknown : undefined;
  let verdict = problems.length
    ? `Windows segnala ${list}${more(problems.length, 4)}. ${first![1][0].toUpperCase()}${first![1].slice(1)}.` +
      (problems.some((n) => n.port.status === 'overcurrent') ? ' Scollega subito il dispositivo da quella porta: lo spegnimento per sovraccarico protegge il PC.' : '')
    : `Nessuna porta USB segnala errori: ${num(devices.length, 'dispositivo collegato', 'dispositivi collegati')} su ${num(usb.controllers.length, 'controller', 'controller')}.`;
  if (problems.some(twice)) verdict += ' Il dispositivo non riconosciuto compare anche tra i dispositivi con problemi (codice 43), dove è già contato.';
  if (usb.partial) verdict += ' La lettura non è finita in tempo: l\'albero può essere incompleto.';
  add({
    id: 'pc.usb.ports',
    metric: 'pc.usb.ports',
    category: 'pc',
    title: 'Porte USB',
    value: problems.length ? num(problems.length, 'porta in errore', 'porte in errore') : `${num(devices.length, 'dispositivo', 'dispositivi')}, nessuna porta in errore`,
    numeric: problems.length,
    severity: sev,
    verdict,
    actions: problems.length ? ['usb-port-error'] : [],
  });

  const slow = devices.map((n) => ({ n, why: usbSlow(n) })).filter((x) => x.why);
  if (!slow.length) return;
  const usb2 = slow.filter((x) => x.why === 'usb2');
  const storageSlow = usb2.some((x) => x.n.port.device!.kind === 'storage');
  const shown = (usb2.length ? usb2 : slow).slice(0, 3);
  const s: Severity = storageSlow ? 'warn' : 'info';
  const head = shown
    .map((x) => {
      const d = x.n.port.device!;
      return `${usbDeviceLabel(d)} va a ${usbSpeedText(d)} ma saprebbe andare a ${d.canSuperPlus ? '10 Gbit/s' : '5 Gbit/s'}`;
    })
    .join('; ');
  const reason = usb2.length ? usbSlowReason(usb2[0].n) : 'la porta o il cavo arrivano a 5 Gbit/s: per i 10 Gbit/s servono una porta USB 3.2 Gen 2 (spesso USB-C) e un cavo adatto';
  add({
    id: 'pc.usb.speed',
    metric: 'pc.usb.speed',
    category: 'pc',
    title: 'Velocità dei dispositivi USB',
    value: num(slow.length, 'dispositivo più lento del possibile', 'dispositivi più lenti del possibile'),
    numeric: slow.length,
    severity: s,
    verdict:
      `${head}${more(slow.length, shown.length)}: ${reason}.` +
      (storageSlow ? ' Per un disco o una chiavetta vuol dire copie e backup molto più lenti: in USB 2 si arriva a circa 40 MB/s, in USB 3 un disco meccanico supera di solito i 100 MB/s e un SSD i 400 MB/s.' : ''),
    actions: ['usb-faster-port'],
  });
}
