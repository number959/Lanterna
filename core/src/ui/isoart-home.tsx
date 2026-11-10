import type { DeviceKind } from '../engine';
import type { IsoArt } from './isoprims';

// Postazioni e periferiche in prospettiva isometrica: PC, stampante, telefono, tablet, telefono VoIP, TV, domotica, dispositivi medicali, sconosciuti.
// Ogni disegno usa le primitive di isoprims.tsx (Box, face, rect, line, poly, disc, iso)
// e le classi di isoart.css; il punto (0, 0) è il centro dell'appoggio a terra.

export const HOME_ART: Partial<Record<DeviceKind, IsoArt>> = {};
