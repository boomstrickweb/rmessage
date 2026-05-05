/**
 * nostr.js — Nostr relay WebSocket transport
 *
 * Handles:
 *  - WebSocket connections to Nostr relays
 *  - Subscribing to kind:4 (messages) and kind:25050 (signaling)
 *  - Publishing encrypted events
 *  - Relay status indicator updates
 *  - Offline queue flushing
 *
 * Exports: RELAYS, relConn, resubAll, nostrPub, setRp, iStat, flushOQ
 */

'use strict';

import { buildEv } from '../crypto/secp256k1.js';
import { kemE }    from '../crypto/mlkem.js';
import { aesEnc, yieldUI } from '../crypto/ratchet.js';
import { hex, rnd } from '../utils.js';
import { onEv }    from './events.js';

export const RELAYS = [
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.nostr.info',
];

export const WS   = {};
export const CONN = new Set();

// Relay name shortener: wss://relay.damus.io → damus.io
export const rn = u => u.split('/')[2].split('.').slice(-2).join('.');

export function setRp(url, st) {
  const el = document.getElementById('rp' + btoa(url).replace(/\W/g, ''));
  if (el) el.className = `rp ${st}`;
  if (st === 'ok' && window._OQ?.length) setTimeout(flushOQ, 300);
}

export function iStat() {} // simplified — relay pills updated via setRp

/**
 * Connect to a single Nostr relay. Auto-reconnects on close.
 */
export function relConn(url) {
  setRp(url, 'try');
  let ws;
  try { ws = new WebSocket(url); } catch { setRp(url, 'no'); return; }
  const t = setTimeout(() => { if (ws.readyState !== 1) { ws.close(); setRp(url, 'no'); } }, 9000);
  ws.onopen = () => {
    clearTimeout(t); WS[url] = ws; CONN.add(url); setRp(url, 'ok');
    ws.send(JSON.stringify(['REQ', hex(rnd(8)), { kinds: [4, 25050], '#p': [window._NK?.pub], limit: 50 }]));
    if (window._OQ?.length) setTimeout(flushOQ, 300);
  };
  ws.onmessage = async e => {
    try { const m = JSON.parse(e.data); if (m[0] === 'EVENT' && m[2]) await onEv(m[2]); } catch {}
  };
  ws.onclose = () => { CONN.delete(url); delete WS[url]; setRp(url, 'no'); setTimeout(() => relConn(url), 7000); };
  ws.onerror = () => clearTimeout(t);
}

/**
 * Resubscribe all connected relays (called after key load).
 */
export function resubAll() {
  Object.keys(WS).forEach(url => {
    const ws = WS[url];
    if (ws && ws.readyState === 1)
      ws.send(JSON.stringify(['REQ', hex(rnd(8)), { kinds: [4, 25050], '#p': [window._NK?.pub], limit: 50 }]));
  });
}

/**
 * Publish an encrypted event to all connected relays.
 * kind:4  → messages (Sealed Sender path)
 * kind:25050 → signaling (WebRTC offer/answer/ICE)
 */
export async function nostrPub(toPub, kyberPk, obj, kind = 4) {
  await yieldUI();
  const payload = kind === 25050 ? { ...obj, kyberPk: window._KKkeys?.pk } : obj;
  const { ct, K } = kemE(kyberPk);
  const { iv, ct: a } = await aesEnc(K, JSON.stringify(payload));
  const enc  = JSON.stringify({ v: 3, kem: ct, iv, ct: a });
  const tags = [['p', toPub], ['kyber', window._KKkeys?.pk]];
  const ev   = await buildEv(kind, enc, tags, window._NK?.priv, window._NK?.pub);
  let s = 0;
  Object.values(WS).forEach(ws => { if (ws.readyState === 1) { ws.send(JSON.stringify(['EVENT', ev])); s++; } });
  return s;
}

/**
 * Flush the offline message queue.
 */
export async function flushOQ() {
  if (!window._OQ?.length) return;
  const q = [...window._OQ]; window._OQ = []; window._saveOQ?.();
  for (const item of q) {
    const p = window._PEERS?.[item.to];
    if (p?.kyberPk) {
      try { await window._sendHybrid?.(item.to, p.kyberPk, item.op); }
      catch { window._OQ.push(item); }
    }
  }
  if (!window._OQ?.length) document.getElementById('obar').classList.remove('on');
}
