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
      const { iv, ct: a } = await aesEnc(K, JSON.stringify({ from: G._NK.pub }));
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
  const dest = route[route.length - 1];
  const destPeer = G._PEERS[dest];
  const inner = { type: 'onion_final', payload: finalPayload, dest };
  const { ct: ct0, K: K0 } = kemE(destPeer.kyberPk);
  const { iv: iv0, ct: a0 } = await aesEnc(K0, JSON.stringify(inner));
  let current = JSON.stringify({ v: 6, kem: ct0, iv: iv0, ct: a0 });

  for (let i = route.length - 2; i >= 0; i--) {
    const nodePub = route[i];
    const nodePeer = G._PEERS[nodePub];
    const layer = { type: 'onion_relay', next: route[i + 1], ct: current };
    const { ct: cti, K: Ki } = kemE(nodePeer.kyberPk);
    const { iv: ivi, ct: ai } = await aesEnc(Ki, JSON.stringify(layer));
    current = JSON.stringify({ v: 6, kem: cti, iv: ivi, ct: ai });
  }
  return current;
}

export async function sendOnion(destPub, finalEncPayload) {
  const online = getOnlinePeers().filter(p => p !== destPub);
  let route;
  if (online.length >= 2) {
    const shuffled = online.sort(() => Math.random() - .5);
    route = [shuffled[0], shuffled[1], destPub];
  } else if (online.length === 1) {
    route = [online[0], destPub];
  } else return false;

  try {
    const onion = await buildOnion(finalEncPayload, route);
    const firstNode = route[0];
    const ephNK = genNKP();
    const ev = await buildEv(4, onion, [['p', firstNode]], ephNK.priv, ephNK.pub);
    Object.values(WS).forEach(ws => { if (ws.readyState === 1) ws.send(JSON.stringify(['EVENT', ev])); });
    return true;
  } catch (e) { console.warn('Onion send failed', e); return false; }
}

export async function handleOnionRelay(layer) {
  const nextPub = layer.next;
  const ct = layer.ct;
  const tags = [['p', nextPub]];
  const ephNK = genNKP();
  const ev = await buildEv(4, ct, tags, ephNK.priv, ephNK.pub);
  Object.values(WS).forEach(ws => { if (ws.readyState === 1) ws.send(JSON.stringify(['EVENT', ev])); });
}
