import { hex, rnd, fhex } from '../utils.js';
import { kemE, aesEnc } from '../crypto/mlkem.js';
import { buildEv } from '../crypto/secp256k1.js';

export const RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.nostr.info'];
export const WS = {};
export const CONN = new Set();

let _seenIds = new Map();
const REPLAY_WINDOW_MS = 5 * 60 * 1000;
const REPLAY_CACHE_TTL = 10 * 60 * 1000;
const REPLAY_CACHE_MAX = 2000;

export function iStat() {
  const el = document.getElementById('p2p-ind');
  if (el) el.classList.toggle('on', CONN.size > 0);
}

export function setRp(url, cls) {
  const id = 'rp' + btoa(url).replace(/\W/g, '');
  const el = document.getElementById(id);
  if (el) el.className = 'rp ' + cls;
}

export function relConn(url, onEvCallback) {
  setRp(url, 'try');
  let ws;
  try {
    ws = new WebSocket(url);
  } catch (e) {
    setRp(url, 'no');
    return;
  }
  const t = setTimeout(() => {
    if (ws.readyState !== 1) {
      ws.close();
      setRp(url, 'no');
    }
  }, 9000);

  ws.onopen = () => {
    clearTimeout(t);
    WS[url] = ws;
    CONN.add(url);
    setRp(url, 'ok');
    const G_ST = window;
    ws.send(JSON.stringify(['REQ', hex(rnd(8)), { kinds: [4, 25050], '#p': [G_ST._NK.pub], limit: 50 }]));
    iStat();
    if (window.flushOQ) window.flushOQ();
    resubAll();
  };

  ws.onmessage = async e => {
    try {
      const m = JSON.parse(e.data);
      if (m[0] === 'EVENT' && m[2]) await onEvCallback(m[2]);
    } catch { }
  };

  ws.onclose = () => {
    CONN.delete(url);
    delete WS[url];
    setRp(url, 'no');
    iStat();
    setTimeout(() => relConn(url, onEvCallback), 7000);
  };
  ws.onerror = () => clearTimeout(t);
}

export function resubAll() {
  const G_ST = window;
  Object.keys(WS).forEach(url => {
    const ws = WS[url];
    if (ws && ws.readyState === 1) {
      ws.send(JSON.stringify(['REQ', hex(rnd(8)), { kinds: [4, 25050], '#p': [G_ST._NK.pub], limit: 50 }]));
    }
  });
}

export async function nostrPub(toPub, kyberPk, obj, kind = 4) {
  const G_ST = window;
  const payload = kind === 25050 ? { ...obj, kyberPk: G_ST._KKkeys.pk } : obj;
  const { ct, K } = kemE(kyberPk);
  const { iv, ct: a } = await aesEnc(K, JSON.stringify(payload));
  const enc = JSON.stringify({ v: 3, kem: ct, iv, ct: a });
  const tags = [['p', toPub], ['kyber', G_ST._KKkeys.pk]];
  const ev = await buildEv(kind, enc, tags, G_ST._NK.priv, G_ST._NK.pub);
  let s = 0;
  Object.values(WS).forEach(ws => {
    if (ws.readyState === 1) {
      ws.send(JSON.stringify(['EVENT', ev]));
      s++;
    }
  });
  return s;
}

export function isReplay(ev) {
  const now = Date.now();
  const evTs = ev.created_at * 1000;
  if (Math.abs(now - evTs) > REPLAY_WINDOW_MS) return true;
  if (!ev.id || _seenIds.has(ev.id)) return true;
  if (_seenIds.size >= REPLAY_CACHE_MAX) {
    const firstKey = _seenIds.keys().next().value;
    _seenIds.delete(firstKey);
  }
  _seenIds.set(ev.id, now);
  return false;
}

setInterval(() => {
  const cutoff = Date.now() - REPLAY_CACHE_TTL;
  for (const [id, ts] of _seenIds) {
    if (ts < cutoff) _seenIds.delete(id);
  }
}, 60000);
