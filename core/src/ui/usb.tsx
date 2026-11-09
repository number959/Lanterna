import { AppWindow, Bluetooth, Cable, Camera, CreditCard, HardDrive, Headphones, Keyboard, Network, Printer, Smartphone, Split, Usb } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { m } from 'motion/react';
import { deviceProblemText, USB_CONTROLLER, USB_KIND, USB_STATUS, usbDeviceLabel, usbDevices, usbPortProblems, usbSlow, usbSpeedText } from '../engine';
import type { PcData, Severity, UsbController, UsbDevice, UsbHub, UsbPort } from '../engine';
import { openTool } from './api';
import { SevIcon, useToast } from './components';
import { rise } from './motion';

// Albero USB, come UsbTreeView: controller, hub e porte occupate con il
// dispositivo, la velocità a cui va davvero e gli errori della porta. Liste
// annidate (leggibili anche da uno screen reader), sempre aperte: di solito
// sono pochi dispositivi. Le porte vuote non sono elencate.

const KIND_ICON: Record<string, LucideIcon> = {
  storage: HardDrive,
  phone: Smartphone,
  printer: Printer,
  network: Network,
  camera: Camera,
  audio: Headphones,
  bluetooth: Bluetooth,
  smartcard: CreditCard,
  input: Keyboard,
  serial: Cable,
  hub: Split,
};

interface PortProps {
  port: UsbPort;
  hub: UsbHub;
  controller: UsbController;
  parent?: UsbDevice;
  depth: number;
}

/** Stato da mostrare accanto al dispositivo: errore della porta, problema del dispositivo o velocità ridotta. */
function portState(p: PortProps): { sev: Severity; text: string } | null {
  const st = p.port.status !== 'ok' ? USB_STATUS[p.port.status] ?? USB_STATUS.unknown : undefined;
  if (st) return { sev: st[2], text: st[0] };
  const d = p.port.device;
  if (d?.problem) return { sev: 'warn', text: deviceProblemText(d.problem).toLowerCase() };
  const slow = usbSlow(p);
  if (slow === 'usb2') return { sev: d?.kind === 'storage' ? 'warn' : 'info', text: `saprebbe andare a ${d?.canSuperPlus ? '10' : '5'} Gbit/s` };
  if (slow === 'gen1') return { sev: 'info', text: 'saprebbe andare a 10 Gbit/s' };
  return null;
}

function PortItem(p: PortProps) {
  const d = p.port.device;
  const Icon = (d && KIND_ICON[d.kind]) || Usb;
  const state = portState(p);
  const where = [`Porta ${p.port.index}`, p.port.typeC ? 'USB-C' : '', p.port.visible === false ? 'interna' : ''].filter(Boolean).join(' · ');
  const fast = d && (d.speed === 'super' || d.speed === 'super-plus');
  return (
    <li>
      <div className="usb-row">
        <span className="usb-port">{where}</span>
        <Icon size={16} aria-hidden className="usb-ic" />
        <span className="usb-name">
          <b>{d ? usbDeviceLabel(d) : 'Nessun dispositivo riconosciuto'}</b>
          {d && (
            <span className="faint">
              {USB_KIND[d.kind] ?? USB_KIND.other} · <span className="mono">{d.vid}:{d.pid}</span>
              {d.usb ? ` · dichiara USB ${d.usb}` : ''}
              {d.hub?.busPowered ? ' · senza alimentatore' : ''}
            </span>
          )}
        </span>
        {d && d.speed && <span className={`tag${fast ? ' accent' : ''}`}>{usbSpeedText(d)}</span>}
        {state && (
          <span className={`usb-state c-${state.sev}`}>
            <SevIcon sev={state.sev} size={14} /> {state.text}
          </span>
        )}
      </div>
      {d?.hub && d.hub.ports.length > 0 && <HubList hub={d.hub} controller={p.controller} parent={d} depth={p.depth + 1} />}
    </li>
  );
}

function HubList({ hub, controller, parent, depth }: { hub: UsbHub; controller: UsbController; parent?: UsbDevice; depth: number }) {
  return (
    <ul className="usb-ports">
      {hub.ports.map((port) => (
        <PortItem key={port.index} port={port} hub={hub} controller={controller} parent={parent} depth={depth} />
      ))}
    </ul>
  );
}

export function UsbCard({ pc, live }: { pc: PcData; live: boolean }) {
  const toast = useToast();
  const usb = pc.usb;
  if (!usb) return null;
  const devices = usbDevices(usb);
  const problems = usbPortProblems(usb);
  const open = () =>
    openTool('device-manager', 'app')
      .then(() => toast('Gestione dispositivi aperta', 'ok', 'open'))
      .catch((e) => toast(e instanceof Error ? e.message : String(e), 'error'));
  return (
    <m.section variants={rise} className="card usb-card">
      <div className="card-head">
        <h2 className="disk-title">
          <Usb size={19} aria-hidden /> Dispositivi USB
        </h2>
        <span className="sub">
          {usb.read === 'ok'
            ? `${devices.length} ${devices.length === 1 ? 'dispositivo' : 'dispositivi'} su ${usb.controllers.length} controller${problems.length ? `, ${problems.length} ${problems.length === 1 ? 'porta in errore' : 'porte in errore'}` : ''}`
            : usb.read === 'none'
              ? 'nessun controller USB'
              : 'non letti'}
        </span>
        <span className="spacer" />
        {live && (
          <button className="btn small" onClick={open}>
            <AppWindow size={15} aria-hidden /> Apri Gestione dispositivi
          </button>
        )}
      </div>
      {usb.read === 'none' ? (
        <p className="muted">Windows non vede controller USB: è normale in una macchina virtuale senza USB.</p>
      ) : usb.read === 'error' ? (
        <p className="muted">Windows non ha risposto alla lettura dei controller USB: ripeti l'analisi.</p>
      ) : (
        <ul className="usb-tree">
          {usb.controllers.map((c, i) => (
            <li key={i}>
              <div className="usb-ctrl">
                <b>{c.name}</b>
                <span className="tag">{USB_CONTROLLER[c.kind] ?? USB_CONTROLLER.other}</span>
                {c.hub && <span className="faint">{c.hub.portCount} porte</span>}
                {c.problem ? (
                  <span className="usb-state c-warn">
                    <SevIcon sev="warn" size={14} /> {deviceProblemText(c.problem).toLowerCase()}
                  </span>
                ) : null}
              </div>
              {c.hub && c.hub.ports.length > 0 ? (
                <HubList hub={c.hub} controller={c} depth={0} />
              ) : (
                <p className="faint usb-empty">Nessun dispositivo collegato.</p>
              )}
            </li>
          ))}
        </ul>
      )}
      <p className="faint card-foot">
        Polaris legge ciò che gli hub di Windows hanno registrato al collegamento, senza interrogare i dispositivi e senza numeri di serie; la velocità è quella a cui il
        dispositivo sta funzionando. Le porte vuote non sono elencate, e un hub USB 3 compare due volte (parte USB 2 e parte USB 3), come lo vede Windows.
      </p>
      {usb.partial && <p className="c-info">La lettura non è finita in tempo: l'albero può essere incompleto.</p>}
    </m.section>
  );
}
