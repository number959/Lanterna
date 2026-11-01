import { afterEach, describe, expect, it, vi } from 'vitest';
import { runScan } from '../src/ui/api';
import { base } from './fixtures';

// Avvio dell'analisi: come si legge il rifiuto dell'agente (409) quando
// l'analisi non può partire.

describe("avvio dell'analisi rifiutato dall'agente", () => {
  const old = base();
  let calls: string[] = [];

  /** Agente finto: risponde 409 con il corpo dato all'avvio; l'analisi precedente è `old`. */
  function agent(status: number, body: unknown) {
    calls = [];
    vi.stubGlobal('fetch', async (url: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET';
      calls.push(`${method} ${url}`);
      const json = (v: unknown, code = 200) => new Response(JSON.stringify(v), { status: code, headers: { 'Content-Type': 'application/json' } });
      if (url === 'api/scan' && method === 'POST') return typeof body === 'string' ? new Response(body, { status }) : json(body, status);
      if (url === 'api/progress') return json({ running: false, steps: [] });
      if (url === 'api/scan') return json(old);
      return new Response(null, { status: 404 });
    });
  }
  afterEach(() => vi.unstubAllGlobals());

  it("per un'altra attività in corso mostra il messaggio dell'agente, senza ricaricare l'analisi precedente", async () => {
    for (const error of [
      'misura del Wi-Fi in corso: attendi che finisca o interrompila',
      'test di velocità di Internet in corso: attendi che finisca o interrompilo',
      'test della CPU o del disco in corso: attendi che finisca o interrompilo',
    ]) {
      agent(409, { error });
      await expect(runScan(() => undefined)).rejects.toThrow(error);
      expect(calls).toEqual(['POST api/scan']);
    }
  });

  it("con un'analisi già in corso ne segue l'avanzamento (anche con un agente precedente senza il motivo)", async () => {
    for (const body of [{ error: 'analisi già in corso', busy: 'scan' }, { error: 'analisi già in corso' }]) {
      agent(409, body);
      const steps: unknown[] = [];
      await expect(runScan((p) => steps.push(p))).resolves.toEqual(old);
      expect(calls).toEqual(['POST api/scan', 'GET api/progress', 'GET api/scan']);
      expect(steps).toHaveLength(1);
    }
  });

  it('un 409 senza corpo leggibile non è scambiato per un\'analisi in corso', async () => {
    agent(409, 'conflitto');
    await expect(runScan(() => undefined)).rejects.toThrow('Avvio analisi: HTTP 409');
    expect(calls).toEqual(['POST api/scan']);
  });
});
