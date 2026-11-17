import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { analyze, AUTORUN_CATEGORIES, autorunIssues } from '../src/engine';
import type { AutorunEntry, Scan } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { AUTORUN_TABS, AutorunsCard, entryDetails, entrySignature, entryState, microsoftTotal, tabCounts } from '../src/ui/autoruns';
import type { AutorunTab } from '../src/ui/autoruns';

// Sezione Avvio automatico della vista Computer: voci da controllare in
// cima, schede per categoria con i conteggi, voci di Microsoft solo contate,
// categorie lette in parte dichiarate, nessun pulsante che cambi qualcosa.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const card = (scan: Scan, opts: { live?: boolean; source?: 'agent' | 'demo' | 'file'; tab?: AutorunTab } = {}) =>
  renderToStaticMarkup(
    createElement(AutorunsCard, { scan, analysis: analyze(scan), live: !!opts.live, source: opts.source ?? 'demo', go: () => undefined, initialTab: opts.tab }),
  );
const entry = (patch: Partial<AutorunEntry>): AutorunEntry => ({ category: 'logon', name: 'Prova', enabled: true, ...patch });

describe('conteggi e testi delle voci', () => {
  it('conta per scheda le voci elencate, il totale, quelle di Microsoft, le voci da controllare e le categorie lette in parte', () => {
    const c = tabCounts(demoScan, autorunIssues(demoScan));
    expect(c.logon).toEqual({ listed: 6, total: 8, microsoft: 2, issues: 3, denied: [] });
    expect(c.tasks.denied).toEqual(['tasks']);
    expect(c.tasks.issues).toBe(2);
    expect(c.browser.listed).toBe(3);
    expect(c.other.total).toBe(17);
    expect(c.other.listed).toBe(0);
    expect(microsoftTotal(demoScan)).toBe(2 + 158 + 268 + 410 + 2 + 1 + 6 + 5 + 3);
    expect(AUTORUN_TABS.map((t) => t.id)).toEqual(['logon', 'tasks', 'services', 'drivers', 'wmi', 'browser', 'other']);
  });

  it('dettagli propri della categoria: trigger, esecuzione, avvio, account, browser, consumatore WMI', () => {
    const task = demoScan.pc!.autoruns!.entries.find((e) => e.name === 'Aggiornamento AcmeSoft')!;
    const d = entryDetails(task).join(' · ');
    expect(d).toContain('parte all\'accesso, ogni giorno');
    expect(d).toContain('gira come utente che ha effettuato l\'accesso');
    expect(d).toContain('attività nascosta');
    expect(d).toMatch(/ultima esecuzione .*, riuscita/);
    const svc = clinicScan.pc!.autoruns!.entries.find((e) => e.name === 'AcmeRefertiSvc')!;
    expect(entryDetails(svc)).toEqual(expect.arrayContaining(['avvio automatico', 'account LocalSystem', 'percorso con spazi senza virgolette']));
    expect(entryState(svc)).toEqual({ text: 'in esecuzione', on: true });
    const ext = demoScan.pc!.autoruns!.entries.find((e) => e.name === 'Acme Coupon Helper')!;
    expect(entryDetails(ext)).toEqual(expect.arrayContaining(['Chrome, profilo 1', 'imposta da criteri', 'può leggere e modificare tutti i siti']));
    const wmi = clinicScan.pc!.autoruns!.entries.find((e) => e.category === 'wmi')!;
    expect(entryDetails(wmi)).toEqual(['scrive nel registro eventi', 'collegata a un evento', 'spazio root\\subscription']);
    expect(entryState(entry({ enabled: false }))).toEqual({ text: 'disattivata', on: false });
  });

  it('booleani assenti nel JSON (omitempty) valgono falso: servizio fermo, sottoscrizione non collegata', () => {
    // Steam Client Service nella demo: avvio manuale, fermo, l'agente non scrive running.
    const steam = demoScan.pc!.autoruns!.entries.find((e) => e.name === 'Steam Client Service')!;
    expect(steam.running).toBeUndefined();
    expect(entryState(steam)).toEqual({ text: 'fermo', on: true });
    expect(card(demoScan, { tab: 'services' })).toContain('>fermo<');
    expect(entryState(entry({ category: 'drivers', start: 'boot' }))).toEqual({ text: 'fermo', on: true });
    expect(entryDetails(entry({ category: 'wmi', consumer: 'commandline' }))).toEqual(['esegue un comando', 'non collegata a un evento']);
  });

  it('tipi di voce in italiano, come li scrive l\'agente; account non letto mai «LocalSystem»', () => {
    const kinds: [string, string][] = [
      ['runonceex', 'chiave RunOnceEx'],
      ['policyrun', 'chiave Run dei criteri'],
      ['load', 'valore load di Windows'],
      ['lsa-auth', 'pacchetto di autenticazione (LSA)'],
      ['lsa-security', 'pacchetto di sicurezza (LSA)'],
      ['lsa-notify', 'notifica delle password (LSA)'],
    ];
    for (const [kind, text] of kinds) expect(entryDetails(entry({ kind, category: kind.startsWith('lsa') ? 'lsa' : 'logon' }))[0], kind).toBe(text);
    // Decisione 4: l'account non letto arriva vuoto («») o non arriva; mai «LocalSystem».
    for (const account of [undefined, '' as AutorunEntry['account']]) {
      const svc = entryDetails(entry({ category: 'services', start: 'auto', account }));
      expect(svc).toContain('account non letto');
      expect(svc.join(' ')).not.toContain('LocalSystem');
    }
    expect(entryDetails(entry({ category: 'drivers', start: 'boot' })).join(' ')).not.toContain('account');
  });

  it('file mancante: il tono è quello del giudizio sulla voce, non sempre un avviso', () => {
    const issues = autorunIssues(demoScan);
    const sync = demoScan.pc!.autoruns!.entries.find((e) => e.name === 'AcmeSyncHelper')!;
    const sev = issues.find((x) => x.entry === sync)!.severity;
    expect(sev).toBe('info');
    expect(entrySignature(sync, sev)).toEqual({ text: 'File mancante', tone: 'info' });
    expect(entrySignature(entry({ file: { path: 'C:\\x.exe', missing: true } }))?.tone).toBe('unknown');
    expect(card(demoScan)).toMatch(/<span class="c-info">(?:(?!<\/span><\/span>).)*File mancante/);
  });

  it('firma del file che conta: mancante, senza firma in AppData, comando interpretato, file eseguito da rundll32', () => {
    expect(entrySignature(entry({ file: { path: 'C:\\x.exe', missing: true } }))?.text).toBe('File mancante');
    expect(entrySignature(entry({ file: { path: '%USERPROFILE%\\AppData\\x.exe', folder: 'appData', signature: { status: 'unsigned' } } }))?.tone).toBe('warn');
    const ps = entrySignature(entry({ command: 'powershell.exe -Command x', file: { path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', folder: 'windows', signature: { status: 'valid', microsoft: true } } }));
    expect(ps?.text).toContain('la firma di Microsoft di questo programma di Windows non dice nulla');
    // explorer.exe, msiexec.exe e gli altri programmi dell'elenco non sono interpreti: il testo non li chiama così.
    const shellApp = entrySignature(entry({ command: 'explorer.exe shell:AppsFolder\\X!App', file: { path: 'C:\\Windows\\explorer.exe', folder: 'windows', signature: { status: 'valid', microsoft: true } } }));
    expect(shellApp).toMatchObject({ tone: 'info', text: 'Comando eseguito da explorer.exe: la firma di Microsoft di questo programma di Windows non dice nulla su ciò che esegue' });
    const rundll = entrySignature(
      entry({
        file: { path: 'C:\\Windows\\System32\\rundll32.exe', folder: 'windows', signature: { status: 'valid', microsoft: true } },
        target: { path: '%USERPROFILE%\\AppData\\Local\\x.dll', folder: 'appData', signature: { status: 'unsigned' } },
      }),
    );
    expect(rundll?.tone).toBe('warn');
    expect(entrySignature(entry({ category: 'browser' }))).toBeUndefined();
  });
});

describe('scheda Avvio automatico', () => {
  it('demo di casa: voci di Microsoft contate, voci da controllare in cima, categorie lette in parte, schede con i conteggi', () => {
    const html = card(demoScan);
    expect(html).toContain('Avvio automatico');
    expect(html).toContain('Le voci di Windows firmate da Microsoft non si elencano: sono 855');
    expect(html).toContain('aria-label="Voci da controllare"');
    expect(html.indexOf('AcmeShare')).toBeLessThan(html.indexOf('Categorie dell&#x27;avvio automatico'));
    expect(html).toContain('Acme Coupon Helper');
    expect(html).toContain('Aggiornamento AcmeSoft');
    // Le voci solo da conoscere si aprono a richiesta quando ce ne sono di più gravi.
    expect(html).toContain('Mostra anche le 4 voci da conoscere');
    expect(html).toContain('aria-expanded="false"');
    expect(html).not.toContain('Traduttore rapido');
    // Nella Clinica sono tutte da conoscere: si vedono subito.
    expect(card(clinicScan)).toContain('AcmeEndpointMonitor');
    expect(html).toContain('da verificare avviando Polaris come amministratore');
    expect(html).toContain('una categoria si legge solo in parte (attività pianificate)');
    expect((html.match(/role="tab"/g) ?? []).length).toBe(7);
    expect(html).toContain('role="tabpanel"');
    // Prima scheda con voci da controllare: Accesso.
    expect(html).toContain('aria-label="Accesso"');
    expect(html).toContain('8 voci in tutto: 2 di Windows firmate da Microsoft, non elencate; 6 elencate qui.');
    expect(html).toContain('HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run');
    expect(html).toContain('File mancante');
    expect(html).toContain('Passi nel piano d&#x27;azione');
    expect(html).not.toContain('Apri App di avvio');
  });

  it('le schede di ogni categoria mostrano i dettagli propri', () => {
    const tasks = card(demoScan, { tab: 'tasks' });
    expect(tasks).toContain('parte all&#x27;accesso, ogni giorno');
    expect(tasks).toContain('Senza i permessi di amministratore questa categoria si legge solo in parte');
    const browser = card(demoScan, { tab: 'browser' });
    expect(browser).toContain('Estensione');
    // Il totale dell'agente comprende i componenti interni del browser: si dice quanti sono.
    expect(browser).toContain('7 voci in tutto: 3 elencate qui; 4 componenti interni del browser, non elencati.');
    expect(browser).toContain('acmecouponhelperacmecouponhelperac');
    expect(browser).toContain('imposta da criteri');
    const other = card(clinicScan, { tab: 'other' });
    expect(other).toContain('Monitor e processori di stampa');
    expect(other).toContain('Acme Port Monitor');
    expect(other).toContain('Winlogon');
    const wmi = card(clinicScan, { tab: 'wmi' });
    expect(wmi).toContain('AcmeEndpointMonitor');
    expect(wmi).toContain('scrive nel registro eventi');
    const drivers = card(demoScan, { tab: 'drivers' });
    expect(drivers).toContain('acmewlan');
    expect(drivers).toContain('all&#x27;avvio del sistema');
  });

  it('con l\'agente offre solo di aprire App di avvio: nessun pulsante disattiva, cancella o rimuove', () => {
    const html = card(clinicScan, { live: true, source: 'agent' });
    expect(html).toContain('Apri App di avvio');
    for (const s of [html, card(demoScan, { tab: 'browser' })]) expect(s).not.toMatch(/>(?:[^<]*\b)?(Disattiva|Elimina|Rimuovi|Cancella|Termina)\b[^<]*<\/button>/);
    expect(html).toContain('Polaris legge soltanto: non disattiva e non cancella nessuna voce');
  });

  it('senza voci da controllare e con categorie lette in parte non dice «in regola»', () => {
    const s = clone(clinicScan);
    s.pc!.autoruns!.entries = [];
    s.pc!.autoruns!.denied = ['tasks', 'wmi'];
    const html = card(s);
    expect(html).toContain('le categorie lette solo in parte restano da verificare');
    expect(html).toContain('alcune categorie si leggono solo in parte (attività pianificate, sottoscrizioni WMI)');
    // Da amministratore non si chiede di ripetere da amministratore: le voci mancanti sono protette.
    s.pc!.autoruns!.elevated = true;
    const admin = card(s);
    expect(admin).toContain('Anche da amministratore alcune categorie si leggono solo in parte (attività pianificate, sottoscrizioni WMI)');
    expect(admin).toContain('le attività sono da guardare in Utilità di pianificazione');
    expect(admin).not.toMatch(/Senza i permessi di amministratore|avviando Polaris come amministratore/);
    const tasks = card(s, { tab: 'tasks' });
    expect(tasks).toContain('non si sono potute leggere nemmeno da amministratore (protette): da guardare in Utilità di pianificazione.');
    expect(tasks).not.toContain('Senza i permessi di amministratore');
    s.pc!.autoruns!.elevated = false;
    s.pc!.autoruns!.denied = [];
    expect(card(s)).toContain('Nessuna voce da controllare tra quelle lette.');
    const none = clone(demoScan);
    delete none.pc!.autoruns;
    expect(card(none)).toBe('');
  });

  it('nessun profilo utente o nome di profilo del browser nella scheda', () => {
    for (const s of [demoScan, clinicScan]) {
      for (const t of AUTORUN_TABS) expect(card(s, { tab: t.id })).not.toMatch(/C:\\Users\\/i);
      // Dei profili dei browser solo il numero, mai il nome.
      for (const e of s.pc!.autoruns!.entries) if (e.profile !== undefined) expect(typeof e.profile, e.name).toBe('number');
      expect(card(s, { tab: 'browser' })).not.toMatch(/profilo (?!\d)|Default|Profile \d/);
    }
  });

  it('i dati delle demo sono quelli che l\'agente può produrre', () => {
    for (const s of [demoScan, clinicScan]) {
      const ar = s.pc!.autoruns!;
      for (const c of AUTORUN_CATEGORIES) {
        const n = ar.counts?.[c];
        const listed = ar.entries.filter((e) => e.category === c).length;
        if (!n) {
          expect(listed, c).toBe(0);
          continue;
        }
        // Totale = voci di Microsoft non elencate + voci elencate (per le estensioni anche i componenti interni).
        if (c === 'browser') expect(n.total, c).toBeGreaterThanOrEqual(listed + (n.microsoft ?? 0));
        else expect(n.total, c).toBe((n.microsoft ?? 0) + listed);
      }
      // Le sottoscrizioni WMI non hanno un file firmato: non si contano mai come voci di Microsoft.
      expect(ar.counts?.wmi?.microsoft ?? 0).toBe(0);
      for (const e of ar.entries) {
        if (e.category === 'services') expect(e.scope, e.name).toBeUndefined();
        expect(e.location ?? '', e.name).not.toMatch(/%PROGRAMDATA%/i);
      }
      const procs = s.pc!.procs!;
      // Unreadable conta esattamente i processi non apribili, che l'agente segna con owner 'unknown'.
      expect(procs.unreadable).toBe(procs.items.filter((p) => p.access === 'none').length);
      for (const p of procs.items.filter((x) => x.access === 'none')) expect(p.owner, p.name).toBe('unknown');
      // Gli pseudo-processi del nucleo non hanno owner; i processi di Polaris si aprono e hanno il file.
      expect(procs.items.find((p) => p.pid === 4)!.owner).toBeUndefined();
      for (const p of procs.items.filter((x) => x.polaris)) expect(p.file?.path, p.name).toBeTruthy();
    }
  });
});
