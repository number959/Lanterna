import type { ReachTarget } from '../engine';

// Canale tra la scheda "Reti e VLAN" e quella del test di segmentazione:
// le destinazioni proposte arrivano alla scheda del test se è montata,
// altrimenti aspettano che lo diventi.

type Listener = (targets: ReachTarget[]) => void;

const listeners = new Set<Listener>();
let pending: ReachTarget[] | null = null;

/** Propone destinazioni al test di segmentazione; restituisce subito. */
export function proposeReach(targets: ReachTarget[]) {
  if (!targets.length) return;
  if (listeners.size) listeners.forEach((f) => f(targets));
  else pending = [...(pending ?? []), ...targets];
}

/** La scheda del test si iscrive: riceve subito le proposte in attesa. */
export function onReachProposal(f: Listener): () => void {
  listeners.add(f);
  if (pending) {
    const p = pending;
    pending = null;
    f(p);
  }
  return () => {
    listeners.delete(f);
  };
}
