import { hex, rnd, cat, te } from '../utils.js';
import { kemE, aesEnc } from '../crypto/mlkem.js';
import { genNKP, buildEv } from '../crypto/secp256k1.js';
import { WS, CONN } from './nostr.js';

const G = window;
const _peerOnline = {};
const ONLINE_TTL = 90000;
const HB_INTERVAL = 30000;
let _hbTimer = null;

export function markOnline(peerPub) { _peerOnline[peerPub] = Date.now(); }
export function isOnline(peerPub) { return Date.now() - (_peerOnline[peerPub] || 0) < ONLINE_TTL; }
export function getOnlinePeers() { return Object.keys(G._PEERS || {}).filter(p => G._PEERS[p]?.kyberPk && isOnline(p) && p !== G._NK.pub); }

export async function sendHeartbeat() {
  if (!G._NK || !G._KKkeys || CONN.size === 0) return;
  const peers = Object.keys(G._PEERS).filter(p => G._PEERS[p]?.kyberPk);
  for (const p of peers) {
    try {
      const peer = G._PEERS[p];
      const { ct, K } = kemE(peer.kyberPk);
      const { iv, ct: a } = await aesEnc(K, JSON.stringify({ type: '__hb__', from: G._NK.pub, ts: Date.now() }));
      const enc = JSON.stringify({ v: 5, kem: ct, iv, ct: a });
      const ephNK = genNKP();
      const ev = await buildEv(4, enc, [['p', p]], ephNK.priv, ephNK.pub);
      Object.values(WS).forEach(ws => { if (ws.readyState === 1) ws.send(JSON.stringify(['EVENT', ev])); });
    } catch { }
  }
}

export function startHeartbeat() {
  if (_hbTimer) return;
  sendHeartbeat();
  _hbTimer = setInterval(sendHeartbeat, HB_INTERVAL);
}

export function stopHeartbeat() { clearInterval(_hbTimer); _hbTimer = null; }

export async function buildOnion(finalPayload, route) {
  let current = finalPayload;
  const dest = route[route.length - 1];
  const inner = { type: 'onion_final', payload: finalPayload, dest };
  current = inner;
  for (let i = route.length - 2; i >= 0; i--) {
    const hop = route[i];
    const peer = G._PEERS[hop];
    const { ct, K } = kemE(peer.kyberPk);
    const { iv, ct: a } = await aesEnc(K, JSON.stringify({ type: 'onion_relay', next: route[i + 1], ct: current }));
    current = JSON.stringify({ v: 6, kem: ct, iv, ct: a });
  }
  return current;
}

export async function sendOnion(destPub, finalEncPayload) {
  const online = getOnlinePeers();
  if (online.length < 1) throw new Error('No hops');
  const hop1 = online[Math.floor(Math.random() * online.length)];
  const route = [hop1, destPub];
  const onion = await buildOnion(finalEncPayload, route);
  const tags = [['p', hop1]];
  const ephNK = genNKP();
  const ev = await buildEv(4, onion, tags, ephNK.priv, ephNK.pub);
  Object.values(WS).forEach(ws => { if (ws.readyState === 1) ws.send(JSON.stringify(['EVENT', ev])); });
  return true;
}

export async function handleOnionRelay(layer) {
  const nextPub = layer.next;
  const ct = layer.ct;
  const tags = [['p', nextPub]];
  const ephNK = genNKP();
  const ev = await buildEv(4, ct, tags, ephNK.priv, ephNK.pub);
  Object.values(WS).forEach(ws => { if (ws.readyState === 1) ws.send(JSON.stringify(['EVENT', ev])); });
}
