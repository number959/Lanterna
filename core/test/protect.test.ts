import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { ACTIONS, analyze, documentParts, encText, isPortable, METRICS, printerProblems, printerText } from '../src/engine';
import type { Finding, Scan } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { guideById } from '../src/guides';
import { PrintersCard, ProtectionCard } from '../src/ui/protect';

// Cifratura, punti di ripristino, backup, account, accessi e stampanti.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const find = (s: Scan, id: string): Finding | undefined => analyze(s).findings.find((f) => f.id === id);

describe('cifratura del disco', () => {
  it('casa: cifrato ma mai attivato; clinica: protetto con chiave di ripristino', () => {
    const h = find(clone(demoScan), 'pc.encryption')!;
    expect(h.severity).toBe('warn');
    expect(h.value).toBe('C: cifrato, protezione mai attivata');
    expect(h.actions).toEqual(['activate-encryption']);
    const c = find(clone(clinicScan), 'pc.encryption')!;
    expect(c.severity).toBe('ok');
    expect(c.value).toBe('C: cifrato (XTS-AES 128), protezione attiva');
    expect(c.verdict).toContain('la custodisce di solito il reparto informatico');
  });

  it('sospesa, non cifrato su portatile e su fisso, senza chiave di ripristino, senza amministratore', () => {
    const s = clone(clinicScan);
    const os = s.pc!.encryption!.volumes![0];
    os.protection = 'off';
    os.suspendCount = 2;
    let f = find(s, 'pc.encryption')!;
    expect(f.severity).toBe('warn');
    expect(f.verdict).toContain('dopo 2 riavvii');
    expect(f.actions).toEqual(['resume-bitlocker']);
    os.conversion = 'decrypted';
    f = find(s, 'pc.encryption')!;
    expect(f.severity).toBe(isPortable(s.pc!) ? 'warn' : 'info');
    const h = clone(demoScan);
    h.pc!.encryption!.volumes![0].conversion = 'decrypted';
    expect(find(h, 'pc.encryption')!.severity).toBe('warn');
    const k = clone(clinicScan);
    k.pc!.encryption!.volumes![0].protectors = ['tpm'];
    f = find(k, 'pc.encryption')!;
    expect(f.severity).toBe('warn');
    expect(f.verdict).toContain('Manca però una chiave di ripristino');
    k.pc!.encryption = { read: 'denied' };
    expect(find(k, 'pc.encryption')!.severity).toBe('unknown');
    k.pc!.encryption = { read: 'absent' };
    expect(find(k, 'pc.encryption')).toBeUndefined();
    expect(encText({ letter: 'C:', kind: 'os', conversion: 'encrypting', percent: 42, protection: 'off', protectors: null })).toBe('cifratura in corso, 42%');
  });
});

describe('punti di ripristino e backup', () => {
  it('casa: nessun punto di ripristino, Documenti in OneDrive; clinica: tutto a posto', () => {
    const h = clone(demoScan);
    expect(find(h, 'pc.restore')!.severity).toBe('warn');
    const b = find(h, 'pc.backup')!;
    expect(b.severity).toBe('info');
    expect(b.verdict).toContain('La cartella Documenti è sincronizzata con OneDrive.');
    const c = clone(clinicScan);
    expect(find(c, 'pc.restore')!.value).toBe('4, l\'ultimo il 09/10/2026');
    expect(find(c, 'pc.backup')!.severity).toBe('ok');
  });

  it('backup non riuscito, nessun backup, criteri e Windows Server', () => {
    const s = clone(clinicScan);
    s.pc!.backup!.imageBackup!.lastFailure = '2026-10-14T01:00:00Z';
    let f = find(s, 'pc.backup')!;
    expect(f.severity).toBe('warn');
    expect(f.verdict).toContain('non è riuscito il 14 ottobre 2026');
    s.pc!.backup = { imageBackup: { read: 'ok', days: 90 } };
    f = find(s, 'pc.backup')!;
    expect(f.value).toBe('nessun backup trovato');
    expect(f.actions).toEqual(['backup-files']);
    s.pc!.backup = { restorePoints: { read: 'denied', count: 0, disabledByPolicy: true } };
    expect(find(s, 'pc.restore')!.value).toBe('spenti dai criteri');
    s.pc!.os!.server = true;
    expect(find(s, 'pc.restore')).toBeUndefined();
    expect(find(s, 'pc.backup')).toBeUndefined();
  });
});

describe('account e accessi', () => {
  it('casa: accesso automatico, account amministratore, nessun blocco; clinica: Desktop remoto con NLA', () => {
    const h = clone(demoScan);
    expect(find(h, 'pc.autologon')!.severity).toBe('warn');
    const a = find(h, 'pc.accounts')!;
    expect(a.severity).toBe('info');
    expect(a.actions).toEqual(['use-standard-account']);
    expect(find(h, 'pc.lock')!.severity).toBe('info');
    expect(find(h, 'pc.rdp')).toBeUndefined();
    const c = clone(clinicScan);
    expect(find(c, 'pc.rdp')!.severity).toBe('info');
    expect(find(c, 'pc.accounts')!.severity).toBe('ok');
    expect(find(c, 'pc.lock')!.value).toBe('dopo 10 minuti');
  });

  it('ospite e Administrator attivi, password non richiesta, molti amministratori; in dominio più prudente', () => {
    const s = clone(demoScan);
    const acc = s.pc!.accounts!;
    acc.local!.find((x) => x.kind === 'guest')!.enabled = true;
    acc.local!.find((x) => x.kind === 'builtin-admin')!.enabled = true;
    acc.local!.push({ rid: 1002, kind: 'user', enabled: true, passwordNotRequired: true });
    acc.admins = { members: 5, localEnabled: 4 };
    let f = find(s, 'pc.accounts')!;
    expect(f.severity).toBe('warn');
    expect(f.verdict).toContain('L\'account Guest (ospite) è attivo');
    expect(f.verdict).toContain('4 account locali sono amministratori');
    expect(f.actions).toContain('secure-local-accounts');
    s.agent.domain = 'studio.local';
    f = find(s, 'pc.accounts')!;
    expect(f.severity).toBe('info');
  });

  it('accesso automatico con password nel registro, Desktop remoto senza NLA, UAC spento o senza conferme', () => {
    const s = clone(clinicScan);
    s.pc!.access!.autologon = { enabled: true, passwordInRegistry: true };
    expect(find(s, 'pc.autologon')!.severity).toBe('crit');
    s.pc!.access!.rdp = { enabled: true, nla: false };
    expect(find(s, 'pc.rdp')!.severity).toBe('crit');
    s.pc!.access!.uac = { enabled: true, consentAdmin: 0, secureDesktop: true };
    expect(find(s, 'pc.uac')!.severity).toBe('warn');
    s.pc!.access!.uac = { enabled: false, consentAdmin: 5, secureDesktop: true };
    expect(find(s, 'pc.uac')!.severity).toBe('crit');
    s.pc!.access!.uac = { enabled: true, consentAdmin: 5, secureDesktop: false };
    expect(find(s, 'pc.uac')!.severity).toBe('info');
  });
});

describe('stampanti', () => {
  it('casa: stampante non in linea con lavori fermi; clinica: etichette senza carta', () => {
    const h = find(clone(demoScan), 'pc.printers')!;
    expect(h.severity).toBe('warn');
    expect(h.verdict).toContain('HP DeskJet 2700 series (predefinita): non in linea, 2 lavori fermi');
    expect(h.actions).toEqual(['printer-online', 'clear-print-queue']);
    const c = find(clone(clinicScan), 'pc.printers')!;
    expect(c.verdict).toContain('Zebra GK420d (etichette): carta esaurita');
    expect(c.verdict).toContain('Controlla carta, toner, sportelli e vassoi');
  });

  it('servizio fermo o disattivato; solo stampanti virtuali; testo dello stato', () => {
    const s = clone(clinicScan);
    s.pc!.printing!.spooler = { start: 'auto', running: false };
    let f = find(s, 'pc.printers')!;
    expect(f.value).toBe('servizio di stampa fermo');
    expect(f.actions).toEqual(['restart-spooler']);
    s.pc!.printing!.spooler = { start: 'disabled' };
    expect(find(s, 'pc.printers')!.value).toBe('servizio di stampa disattivato');
    s.pc!.printing = { spooler: { start: 'auto', running: true }, printers: [{ name: 'Microsoft Print to PDF', kind: 'virtual', jobs: 0 }] };
    expect(find(s, 'pc.printers')).toBeUndefined();
    expect(printerText({ name: 'x', kind: 'usb', jobs: 3 })).toBe('pronta, 3 lavori in coda');
    expect(printerProblems({ name: 'x', kind: 'usb', jobs: 0, flags: ['toner-low', 'paper-jam'] })).toEqual(['paper-jam']);
  });
});

describe('catalogo, guide, documento e schede', () => {
  it('voci, azioni e guide', () => {
    for (const id of ['pc.encryption', 'pc.restore', 'pc.backup', 'pc.accounts', 'pc.autologon', 'pc.rdp', 'pc.uac', 'pc.lock', 'pc.printers']) expect(METRICS[id], id).toBeTruthy();
    for (const id of guideById('protezione-dati-accessi')!.actions!.concat(guideById('stampanti')!.actions!)) expect(ACTIONS[id], id).toBeTruthy();
  });

  it('documento e schede senza nomi di account né chiavi', () => {
    const s = clone(clinicScan);
    const html = documentParts(s, analyze(s)).body;
    expect(html).toContain('<h2>Protezione dei dati e degli accessi</h2>');
    expect(html).toContain('<h2>Stampanti</h2>');
    expect(html).toContain('Zebra GK420d (etichette)');
    const a = analyze(s);
    const card = renderToStaticMarkup(createElement(ProtectionCard, { pc: s.pc!, findings: a.findings, live: true }));
    expect(card).toContain('identificativo della chiave di ripristino 7F3A21C9');
    expect(card).toContain('Apri la crittografia del dispositivo');
    expect(card).toContain('Administrator integrato disattivato');
    const pcard = renderToStaticMarkup(createElement(PrintersCard, { pc: s.pc!, live: false }));
    expect(pcard).toContain('Kyocera ECOSYS M2540dn (accettazione)');
    expect(pcard).toContain('una condivisa da altri computer');
    expect(pcard.indexOf('Microsoft Print to PDF')).toBeGreaterThan(pcard.indexOf('Zebra'));
    const none = clone(s.pc!);
    delete none.encryption;
    delete none.backup;
    delete none.accounts;
    delete none.access;
    delete none.printing;
    expect(renderToStaticMarkup(createElement(ProtectionCard, { pc: none, findings: [], live: false }))).toBe('');
    expect(renderToStaticMarkup(createElement(PrintersCard, { pc: none, live: false }))).toBe('');
  });
});
