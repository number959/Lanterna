// Regole sui produttori dal MAC: il nome deve essere intero (revisione della 0.13.0).
import { expect, it } from 'vitest';
import { classifyHost } from '../src/engine';
it('riconosce i produttori solo a parola intera (HP non è HPE)', () => {
  const k = (vendor: string) => classifyHost({ ip: '10.0.0.9', mac: '00:11:22:33:44:55', vendor }, {}).kind;
  expect(k('HPE')).not.toBe('pc');
  expect(k('HP')).toBe('pc');
  expect(k('Ring')).toBe('iot');
  expect(k('RingCentral')).not.toBe('iot');
  expect(k('Hikvision')).toBe('camera');
  expect(k('Dräger')).toBe('medical');
  expect(k('B. Braun')).toBe('medical');
});

it('rifiuta le sottoreti con un prefisso non intero', async () => {
  const { parseCidr } = await import('../src/engine');
  expect(parseCidr('10.0.0.0/24')).toEqual({ net: 167772160, prefix: 24 });
  for (const bad of ['10.0.0.0/24.5', '10.0.0.0/', '10.0.0.0/33', '10.0.0.0/-1', '10.0.0.0/2e1']) expect(parseCidr(bad), bad).toBeUndefined();
});
