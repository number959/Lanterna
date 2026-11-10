import type { InventoryHost } from './types';

// Riconoscimento del tipo di dispositivo dai segnali raccolti senza toccare
// i dispositivi oltre l'inventario autorizzato: ruolo nella rete (gateway,
// server DNS e DHCP), servizi annunciati da soli (mDNS, UPnP), ruoli NetBIOS,
// produttore dal prefisso del MAC (elenco pubblico IEEE), nome, TTL delle
// risposte al ping, MAC casuale, vicinanza al BSSID di una rete Wi-Fi.
// Ogni segnale dà punti a uno o più tipi; vince il tipo con più punti e la
// confidenza dipende dal punteggio. Le ragioni restano nel risultato: la
// mappa le mostra, perché un'ipotesi va dichiarata come tale.
// Gira anche in goja: niente Intl, niente lookbehind.

export type DeviceKind =
  | 'internet'
  | 'isp'
  | 'router'
  | 'firewall'
  | 'switch'
  | 'ap'
  | 'pc'
  | 'laptop'
  | 'server'
  | 'vm'
  | 'nas'
  | 'printer'
  | 'phone'
  | 'tablet'
  | 'voip'
  | 'camera'
  | 'tv'
  | 'iot'
  | 'medical'
  | 'unknown';

export type Confidence = 'alta' | 'media' | 'bassa';

export interface DeviceGuess {
  kind: DeviceKind;
  confidence: Confidence;
  /** Perché, dal segnale più forte. */
  reasons: string[];
}

export const KIND_LABEL: Record<DeviceKind, string> = {
  internet: 'Internet',
  isp: 'Rete dell\'operatore',
  router: 'Router',
  firewall: 'Firewall',
  switch: 'Switch',
  ap: 'Access point',
  pc: 'PC',
  laptop: 'PC portatile',
  server: 'Server',
  vm: 'Macchina virtuale',
  nas: 'NAS (archivio di rete)',
  printer: 'Stampante',
  phone: 'Telefono',
  tablet: 'Tablet',
  voip: 'Telefono VoIP',
  camera: 'Telecamera',
  tv: 'TV e multimedia',
  iot: 'Domotica e IoT',
  medical: 'Dispositivo medicale',
  unknown: 'Dispositivo sconosciuto',
};

/** Etichetta al plurale per i filtri e i conteggi. */
export const KIND_PLURAL: Record<DeviceKind, string> = {
  internet: 'Internet',
  isp: 'Operatore',
  router: 'Router',
  firewall: 'Firewall',
  switch: 'Switch',
  ap: 'Access point',
  pc: 'PC',
  laptop: 'Portatili',
  server: 'Server',
  vm: 'Macchine virtuali',
  nas: 'NAS',
  printer: 'Stampanti',
  phone: 'Telefoni',
  tablet: 'Tablet',
  voip: 'Telefoni VoIP',
  camera: 'Telecamere',
  tv: 'TV e multimedia',
  iot: 'Domotica e IoT',
  medical: 'Medicali',
  unknown: 'Sconosciuti',
};

/** Gruppo di appartenenza: infrastruttura di rete, server, postazioni, periferiche. */
export type KindGroup = 'rete' | 'server' | 'postazioni' | 'periferiche' | 'altro';

export const KIND_GROUP: Record<DeviceKind, KindGroup> = {
  internet: 'rete',
  isp: 'rete',
  router: 'rete',
  firewall: 'rete',
  switch: 'rete',
  ap: 'rete',
  server: 'server',
  vm: 'server',
  nas: 'server',
  pc: 'postazioni',
  laptop: 'postazioni',
  phone: 'postazioni',
  tablet: 'postazioni',
  voip: 'periferiche',
  printer: 'periferiche',
  camera: 'periferiche',
  tv: 'periferiche',
  iot: 'periferiche',
  medical: 'periferiche',
  unknown: 'altro',
};

/** Ordine nella mappa: prima l'infrastruttura, poi server, postazioni e periferiche. */
export const KIND_ORDER: DeviceKind[] = ['router', 'firewall', 'switch', 'ap', 'server', 'vm', 'nas', 'pc', 'laptop', 'tablet', 'phone', 'voip', 'printer', 'medical', 'camera', 'tv', 'iot', 'unknown', 'isp', 'internet'];

/** Contesto della rete che serve a interpretare i segnali di un dispositivo. */
export interface ClassifyContext {
  gatewayIp?: string;
  /** Il pannello del gateway dice di essere un firewall. */
  gatewayFirewall?: boolean;
  dnsServers?: string[];
  dhcpServer?: string;
  /** BSSID delle reti Wi-Fi visibili, per riconoscere gli access point cablati. */
  bssids?: string[];
  /** Ruoli dichiarati altrove (per esempio dai servizi critici verificati). */
  roles?: Record<string, string>;
  /** Capacità annunciate dal vicino LLDP/CDP con quel MAC o indirizzo. */
  neighborCaps?: Record<string, string[]>;
  /** Nomi dati dall'utente alle verifiche (segmentazione, servizi critici), per indirizzo. */
  labels?: Record<string, string>;
}

type Score = { kind: DeviceKind; pts: number; why: string };

// Produttori dal prefisso MAC: il tipo che rende probabile. Le regole sono
// prudenti: un produttore che fa anche altro dà pochi punti.
const VENDOR_RULES: { re: RegExp; kinds: [DeviceKind, number][]; why: string }[] = [
  { re: /^(brother|epson|seiko epson|kyocera|lexmark|xerox|ricoh|konica|sharp|zebra|oki|sindoh|pantum|olivetti|toshiba tec|fuji xerox|fujifilm business)/i, kinds: [['printer', 55]], why: 'produttore di stampanti' },
  { re: /^canon/i, kinds: [['printer', 45]], why: 'produttore di stampanti e fotocamere' },
  { re: /^(hikvision|dahua|axis|hanwha|uniview|reolink|vivotek|mobotix|avigilon|foscam|ezviz|amcrest|lorex|milesight|bosch security)/i, kinds: [['camera', 65]], why: 'produttore di telecamere di sorveglianza' },
  { re: /^(synology|qnap|asustor|buffalo|terramaster|drobo|netapp|ixsystems)/i, kinds: [['nas', 65]], why: 'produttore di NAS' },
  { re: /^(ubiquiti|aruba|ruckus|cambium|meraki|aerohive|engenius|mist systems|extreme networks)/i, kinds: [['ap', 35], ['switch', 25]], why: 'produttore di access point e switch' },
  { re: /^(cisco|juniper|hpe|arista|mikrotik|netgear|tp-link|d-link|zyxel|allied telesis|h3c|ruijie|edgecore|lancom|draytek|teltonika)/i, kinds: [['switch', 25], ['router', 20], ['ap', 15]], why: 'produttore di apparati di rete' },
  { re: /^(fortinet|palo alto|sophos|watchguard|check point|sonicwall|stormshield|barracuda)/i, kinds: [['firewall', 50]], why: 'produttore di firewall' },
  { re: /^(avm|technicolor|sagemcom|sercomm|zte|askey|arcadyan|huawei technologies|adb broadband|vantiva|dsl|zhone|calix)/i, kinds: [['router', 35]], why: 'produttore di router per la fibra e l\'ADSL' },
  { re: /^(polycom|poly|yealink|snom|grandstream|avaya|mitel|gigaset|fanvil|htek|spectralink|alcatel-lucent enterprise)/i, kinds: [['voip', 75]], why: 'produttore di telefoni VoIP' },
  {
    re: /^(ge healthcare|philips medical|mindray|dr[aä]ger|draeger|siemens healthineers|nihon kohden|spacelabs|baxter|b\. ?braun|fresenius|hamilton medical|masimo|welch allyn|hill-?rom|edan|schiller|carestream|agfa|esaote|biotronik|medtronic|zoll|natus|getinge|maquet|stryker|olympus medical|canon medical|radiometer|sysmex|roche diagnostics|abbott|beckman)/i,
    kinds: [['medical', 70]],
    why: 'produttore di apparecchiature medicali',
  },
  { re: /^(lantronix|moxa|digi international|perle)/i, kinds: [['iot', 45], ['medical', 15]], why: 'convertitore seriale-rete, spesso collegato a strumenti medicali o industriali' },
  { re: /^(espressif|shelly|allterco|tuya|itead|sonoff|signify|philips lighting|nest|ring|ecobee|tado|netatmo|yeelight|broadlink|lifx|wiz|meross|somfy|bticino|legrand|vimar|fibaro|homey|athom)/i, kinds: [['iot', 55]], why: 'produttore di dispositivi per la casa connessa' },
  { re: /^(sonos|bose|roku|lg electronics|tcl|hisense|vizio|sony interactive|nintendo|microsoft xbox|denon|yamaha|harman)/i, kinds: [['tv', 45]], why: 'produttore di TV, console o diffusori' },
  { re: /^(vmware)/i, kinds: [['vm', 75]], why: 'scheda di rete virtuale VMware' },
  { re: /^(pcs systemtechnik|oracle virtualbox|virtualbox|xensource|parallels|qemu)/i, kinds: [['vm', 70]], why: 'scheda di rete virtuale' },
  { re: /^(raspberry pi)/i, kinds: [['iot', 30], ['server', 20]], why: 'Raspberry Pi, usato per piccoli server e progetti' },
  { re: /^(apple)/i, kinds: [['phone', 22], ['laptop', 18], ['tablet', 10]], why: 'produttore di iPhone, iPad e Mac' },
  { re: /^(samsung|xiaomi|oneplus|oppo|vivo|realme|motorola|honor|huawei device|google|nothing technology|fairphone)/i, kinds: [['phone', 30], ['tv', 10]], why: 'produttore di telefoni' },
  { re: /^(dell|lenovo|hp|hewlett|asus|asustek|acer|msi|micro-star|gigabyte|intel|realtek|liteon|lite-on|azurewave|foxconn|hon hai|wistron|quanta|compal|pegatron|framework|fujitsu|toshiba|panasonic|getac)/i, kinds: [['pc', 30], ['laptop', 15]], why: 'produttore di PC o di schede di rete per PC' },
  { re: /^(supermicro|super micro)/i, kinds: [['server', 50]], why: 'produttore di server' },
];

// Nomi dati dagli amministratori o dai produttori (DNS o NetBIOS, prima parte).
const NAME_RULES: { re: RegExp; kind: DeviceKind; pts: number; why: string }[] = [
  { re: /^(npi[0-9a-f]{6}|brn|brw|epson|canon|kyocera|km[0-9a-f]{6}|xrx|lexmark|ricoh|shrp|zebra|prn)/i, kind: 'printer', pts: 60, why: 'nome tipico delle stampanti (per esempio NPI… per HP, BRN… per Brother)' },
  { re: /(printer|stampa|stampante|^print)/i, kind: 'printer', pts: 55, why: 'il nome indica una stampante' },
  { re: /^(ap|wap|uap|iap)([-_.0-9]|$)|(^|[-_.])ap[-_.0-9]|access-?point/i, kind: 'ap', pts: 55, why: 'il nome indica un access point' },
  { re: /^(sw|switch|core|stack|dist|acc)([-_.0-9]|$)/i, kind: 'switch', pts: 55, why: 'il nome indica uno switch' },
  { re: /^(fw|firewall|utm|fortigate|pfsense|opnsense)([-_.0-9]|$)/i, kind: 'firewall', pts: 55, why: 'il nome indica un firewall' },
  { re: /^(gw|gateway|router|rtr|edge|cpe)([-_.0-9]|$)/i, kind: 'router', pts: 50, why: 'il nome indica un router' },
  { re: /^(srv|server|dc|ad|sql|db|exch|mail|file|fs|app|web|pacs|ris|his|ehr|esx|hv|hyperv|proxmox|vcenter)([-_.0-9]|$)/i, kind: 'server', pts: 55, why: 'il nome indica un server' },
  { re: /^(nas|diskstation|ds\d{3,4}|ts-\d{3}|qnap|synology)/i, kind: 'nas', pts: 60, why: 'il nome indica un NAS' },
  { re: /^(laptop|nb|nbk|notebook|portatile)([-_.0-9]|$)/i, kind: 'laptop', pts: 50, why: 'il nome indica un portatile' },
  { re: /^(desktop|pc|ws|workstation|amb|ambulatorio|segreteria|reception|accettazione|ufficio|postazione)([-_.0-9]|$)/i, kind: 'pc', pts: 45, why: 'il nome indica una postazione' },
  { re: /(ipad|tablet|^tab[-_.])/i, kind: 'tablet', pts: 50, why: 'il nome indica un tablet' },
  { re: /(iphone|android|galaxy|pixel|redmi|oneplus|smartphone)/i, kind: 'phone', pts: 50, why: 'il nome indica un telefono' },
  { re: /(^cam|ipcam|camera|telecamera|nvr|dvr|videosorv)/i, kind: 'camera', pts: 55, why: 'il nome indica una telecamera o un videoregistratore' },
  { re: /(chromecast|firetv|fire-tv|roku|bravia|webos|tizen|appletv|apple-tv|smart-?tv|^tv[-_.])/i, kind: 'tv', pts: 55, why: 'il nome indica una TV o un dispositivo multimediale' },
  { re: /(voip|^sip[-_.]|yealink|polycom|snom|grandstream|^tel[-_.])/i, kind: 'voip', pts: 50, why: 'il nome indica un telefono VoIP' },
  { re: /(ecg|ekg|holter|spiro|ventil|infusion|infus|pompa|defib|ecografo|^rx[-_.]|^tac[-_.]|^rm[-_.]|lab-|analizz|laborator|dicom|modality|emogas)/i, kind: 'medical', pts: 50, why: 'il nome indica un\'apparecchiatura medicale o di laboratorio' },
  { re: /^(esp[-_]|shelly|tasmota|sonoff|tuya|hue|nest|echo|alexa|google-home|homepod)/i, kind: 'iot', pts: 55, why: 'il nome indica un dispositivo per la casa connessa' },
];

// Servizi DNS-SD annunciati via mDNS.
const SERVICE_RULES: { re: RegExp; kinds: [DeviceKind, number][]; why: string }[] = [
  { re: /^_(ipp|ipps|printer|pdl-datastream)\._tcp/i, kinds: [['printer', 85]], why: 'annuncia il servizio di stampa' },
  { re: /^_(scanner|uscan|uscans)\._tcp/i, kinds: [['printer', 60]], why: 'annuncia un servizio di scansione (multifunzione)' },
  { re: /^_googlecast\._tcp/i, kinds: [['tv', 70]], why: 'annuncia Google Cast (TV, Chromecast o diffusore)' },
  { re: /^_(airplay|raop)\._tcp/i, kinds: [['tv', 45], ['laptop', 10]], why: 'annuncia AirPlay' },
  { re: /^_(spotify-connect|sonos)\._tcp/i, kinds: [['tv', 45]], why: 'annuncia la riproduzione musicale in rete' },
  { re: /^_(hap|homekit|matter|matterc|hue|shelly|esphomelib)\._(tcp|udp)/i, kinds: [['iot', 70]], why: 'annuncia un servizio per la casa connessa' },
  { re: /^_(rtsp|onvif|axis-video)\._tcp/i, kinds: [['camera', 60]], why: 'annuncia un flusso video (RTSP)' },
  { re: /^_(apple-mobdev2|companion-link)\._tcp/i, kinds: [['phone', 40], ['tablet', 20]], why: 'annuncia i servizi dei dispositivi Apple portatili' },
  { re: /^_(smb|afpovertcp|nfs|webdav)\._tcp/i, kinds: [['nas', 30], ['server', 15], ['pc', 15]], why: 'condivide cartelle in rete' },
  { re: /^_workstation\._tcp/i, kinds: [['pc', 45]], why: 'si annuncia come postazione di lavoro' },
  { re: /^_(ssh|sftp-ssh)\._tcp/i, kinds: [['server', 20]], why: 'accetta collegamenti SSH' },
  { re: /^_sleep-proxy\._udp/i, kinds: [['tv', 30]], why: 'fa da proxy di sospensione Apple (Apple TV o HomePod)' },
];

// Tipi UPnP annunciati via SSDP.
const UPNP_RULES: { re: RegExp; kinds: [DeviceKind, number][]; why: string }[] = [
  { re: /InternetGatewayDevice|WANIPConnection|WANPPPConnection/i, kinds: [['router', 70]], why: 'si annuncia come router (UPnP Internet Gateway)' },
  { re: /wifialliance.*WFADevice/i, kinds: [['ap', 35], ['router', 25]], why: 'annuncia la configurazione Wi-Fi protetta (WPS)' },
  { re: /device:Printer|service:PrintBasic|service:PrintEnhanced/i, kinds: [['printer', 80]], why: 'si annuncia come stampante (UPnP)' },
  { re: /dial-multiscreen|device:MediaRenderer|service:AVTransport|RenderingControl|ZonePlayer/i, kinds: [['tv', 60]], why: 'si annuncia come riproduttore multimediale (UPnP o DIAL)' },
  { re: /device:MediaServer|service:ContentDirectory/i, kinds: [['nas', 35], ['tv', 15], ['pc', 10]], why: 'condivide contenuti multimediali (UPnP)' },
  { re: /device:(Basic|HVAC|Lighting|BinaryLight|DimmableLight)|SwitchPower|hue/i, kinds: [['iot', 45]], why: 'si annuncia come dispositivo domotico (UPnP)' },
  { re: /NetworkVideoTransmitter|onvif/i, kinds: [['camera', 65]], why: 'si annuncia come telecamera di rete' },
];

// Parole dei nomi dati dall'utente alle verifiche dei servizi ("PACS (DICOM)",
// "Pompe infusionali (VLAN 60)"): l'ordine conta, i server prima dei dispositivi.
const LABEL_RULES: { re: RegExp; kind: DeviceKind }[] = [
  { re: /(server|controller di dominio|ldap|active directory|\bdns\b|\bdhcp\b|pacs|cartella clinica|\bhis\b|\bris\b|\behr\b|hl7|database|gestionale|file server|posta|exchange|backup)/i, kind: 'server' },
  { re: /(pomp|infus|ecg|elettrocard|ventilat|monitor parametri|defibrill|ecograf|apparecchi|medical|dialisi|analizzator|laboratorio)/i, kind: 'medical' },
  { re: /(telecamer|camera|rtsp|nvr|videosorvegl)/i, kind: 'camera' },
  { re: /(stampant|printer)/i, kind: 'printer' },
  { re: /(switch)/i, kind: 'switch' },
  { re: /(access point|\bap\b|wi-?fi)/i, kind: 'ap' },
  { re: /(firewall)/i, kind: 'firewall' },
  { re: /(gateway|router)/i, kind: 'router' },
  { re: /(telefon|voip|centralino|\bsip\b)/i, kind: 'voip' },
  { re: /(\bnas\b|archivio)/i, kind: 'nas' },
];

/** Tipo suggerito dal nome che l'utente ha dato a una verifica, se ne contiene uno. */
export function labelKind(label?: string): DeviceKind | undefined {
  if (!label) return undefined;
  for (const r of LABEL_RULES) if (r.re.test(label)) return r.kind;
  return undefined;
}

/** Numero di VLAN scritto in un nome ("gw-vlan30", "Pompe infusionali (VLAN 60)"). */
export function vlanIn(text?: string): number | undefined {
  const m = /vlan[-_ .]?(\d{1,4})(?!\d)/i.exec(text ?? '');
  const n = m ? Number(m[1]) : NaN;
  return n >= 1 && n <= 4094 ? n : undefined;
}

/** Valore del MAC con il bit "amministrato localmente" azzerato, per confronti. */
function macValue(mac?: string): number | undefined {
  if (!mac) return undefined;
  const hex = mac.toLowerCase().replace(/[^0-9a-f]/g, '');
  if (hex.length !== 12) return undefined;
  const first = parseInt(hex.slice(0, 2), 16) & ~0x02;
  return first * Math.pow(2, 40) + parseInt(hex.slice(2), 16);
}

/** MAC vicino a uno dei BSSID: le radio degli access point hanno indirizzi derivati da quello della porta cablata. */
export function nearBssid(mac: string | undefined, bssids: string[] | undefined): string | undefined {
  const v = macValue(mac);
  if (v === undefined || !bssids) return undefined;
  for (const b of bssids) {
    const w = macValue(b);
    if (w !== undefined && w !== v && Math.abs(w - v) <= 64) return b;
  }
  return undefined;
}

/** Il primo componente del nome, senza il dominio. */
const shortName = (n?: string) => (n ? n.split('.')[0] : '');

const CONF: [number, Confidence][] = [
  [75, 'alta'],
  [40, 'media'],
  [0, 'bassa'],
];

/** Indovina il tipo di un dispositivo dell'inventario. */
export function classifyHost(h: InventoryHost, ctx: ClassifyContext = {}): DeviceGuess {
  const s: Score[] = [];
  const add = (kind: DeviceKind, pts: number, why: string) => s.push({ kind, pts, why });

  if (h.gateway || (ctx.gatewayIp && h.ip === ctx.gatewayIp)) {
    if (ctx.gatewayFirewall) add('firewall', 100, 'è il gateway della rete e il suo pannello si presenta come firewall');
    else add('router', 100, 'è il gateway: instrada il traffico verso le altre reti e verso Internet');
  }
  const caps = ctx.neighborCaps?.[h.ip] ?? (h.mac ? ctx.neighborCaps?.[h.mac.toLowerCase()] : undefined);
  if (caps) {
    if (caps.indexOf('router') >= 0) add('router', 90, 'lo switch lo annuncia come router (LLDP o CDP)');
    if (caps.indexOf('wlan-ap') >= 0) add('ap', 95, 'si annuncia come access point (LLDP)');
    if (caps.indexOf('bridge') >= 0 || caps.indexOf('switch') >= 0) add('switch', 85, 'si annuncia come switch (LLDP o CDP)');
    if (caps.indexOf('telephone') >= 0 || caps.indexOf('phone') >= 0) add('voip', 95, 'si annuncia come telefono (LLDP o CDP)');
  }
  const role = ctx.roles?.[h.ip];
  if (role) add(labelKind(role) ?? 'server', 50, `è ${role}`);
  const hint = ctx.labels?.[h.ip];
  const hk = labelKind(hint);
  if (hint && hk) add(hk, 45, `dal nome dato nella verifica: «${hint}»`);
  if (ctx.dnsServers && ctx.dnsServers.indexOf(h.ip) >= 0 && !h.gateway) add('server', 55, 'è il server DNS della rete');
  if (ctx.dhcpServer && ctx.dhcpServer === h.ip && !h.gateway) add('server', 45, 'è il server DHCP della rete');

  const near = nearBssid(h.mac, ctx.bssids);
  if (near) add('ap', 80, `il suo MAC è vicino a quello di una rete Wi-Fi trasmessa (${near}): è un access point`);

  for (const u of h.upnp ?? []) for (const r of UPNP_RULES) if (r.re.test(u)) for (const [k, p] of r.kinds) add(k, p, r.why);
  for (const sv of h.services ?? []) for (const r of SERVICE_RULES) if (r.re.test(sv)) for (const [k, p] of r.kinds) add(k, p, r.why);
  // AirPlay insieme alla condivisione di file o a SSH è un Mac, non una TV.
  if ((h.services ?? []).some((x) => /^_(airplay|raop)\./i.test(x)) && (h.services ?? []).some((x) => /^_(smb|afpovertcp|ssh|sftp-ssh|workstation)\./i.test(x))) {
    add('laptop', 40, 'annuncia AirPlay insieme alla condivisione di file: è probabilmente un Mac');
  }
  for (const r of h.roles ?? []) {
    if (r === 'domain-controller') add('server', 90, 'è un controller di dominio (NetBIOS)');
    else if (r === 'file-server') {
      add('pc', 25, 'condivide cartelle in rete (NetBIOS)');
      add('server', 20, 'condivide cartelle in rete (NetBIOS)');
    } else if (r === 'workstation') add('pc', 35, 'si annuncia come postazione Windows (NetBIOS)');
  }
  if (h.vendor) {
    for (const r of VENDOR_RULES) if (r.re.test(h.vendor)) for (const [k, p] of r.kinds) add(k, p, `${h.vendor}: ${r.why}`);
  }
  const mac = (h.mac ?? '').toLowerCase();
  if (/^00:15:5d/.test(mac)) add('vm', 75, 'scheda di rete virtuale di Hyper-V');
  if (/^52:54:00/.test(mac)) add('vm', 55, 'scheda di rete virtuale QEMU/KVM');
  const names = [shortName(h.name), h.netbios ?? ''].filter(Boolean);
  for (const n of names) for (const r of NAME_RULES) if (r.re.test(n)) add(r.kind, r.pts, r.why);
  if (h.ttl) {
    if (h.ttl > 128) {
      add('switch', 15, `TTL ${h.ttl}: tipico degli apparati di rete`);
      add('router', 10, `TTL ${h.ttl}: tipico degli apparati di rete`);
    } else if (h.ttl > 64) add('pc', 15, `TTL ${h.ttl}: tipico di Windows`);
  }
  if (h.randomMac && !/^52:54:00/.test(mac)) {
    add('phone', 25, 'MAC casuale: di solito un telefono o un portatile recente');
    add('laptop', 10, 'MAC casuale: di solito un telefono o un portatile recente');
  }
  if (h.upnp?.length && !s.length && h.server) add('unknown', 1, `si annuncia come «${h.server}»`);

  if (!s.length) return { kind: 'unknown', confidence: 'bassa', reasons: ['nessun segnale riconoscibile: il dispositivo risponde ma non si presenta'] };
  const tot: Partial<Record<DeviceKind, number>> = {};
  for (const x of s) tot[x.kind] = (tot[x.kind] ?? 0) + x.pts;
  let best: DeviceKind = 'unknown';
  let bestPts = -1;
  for (const k of KIND_ORDER) {
    const p = tot[k];
    if (p !== undefined && p > bestPts) {
      best = k;
      bestPts = p;
    }
  }
  const reasons: string[] = [];
  for (const x of s.filter((y) => y.kind === best).sort((a, b) => b.pts - a.pts)) if (reasons.indexOf(x.why) < 0) reasons.push(x.why);
  // Indizi contrari rilevanti: un'ipotesi debole va dichiarata.
  const conf = CONF.find(([min]) => bestPts >= min)![1];
  return { kind: best, confidence: conf, reasons: reasons.slice(0, 4) };
}
