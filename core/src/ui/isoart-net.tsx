import type { DeviceKind } from '../engine';
import type { IsoArt } from './isoprims';

// Dispositivi di rete in prospettiva isometrica: firewall, switch, access point, NAS, macchine virtuali, telecamere, rete dell'operatore.
// Ogni disegno usa le primitive di isoprims.tsx (Box, face, rect, line, poly, disc, iso)
// e le classi di isoart.css; il punto (0, 0) è il centro dell'appoggio a terra.

export const NET_ART: Partial<Record<DeviceKind, IsoArt>> = {};
