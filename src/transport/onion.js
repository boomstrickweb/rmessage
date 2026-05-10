/**
 * onion.js — Hybrid Onion Routing + Heartbeat
 *
 * Matches original single-file implementation exactly.
 * sendHybrid: tries onion routing (v:6, 2+ online peers), falls back to direct send.
 * Direct send uses real NK keypair (not ephemeral) — same as original.
 *
 * Exports: startHeartbeat, stopHeartbeat, sendHybrid, markOnline, isOnline
 */

'use strict';

import { kemE, kemKG }  from '../crypto/mlkem.js';
import { aesEnc }       from '../crypto/ratchet.js';
import { buildEv, genNKP } from '../crypto/secp256k1.js';
import { sendDummySealed, sendWithCoverSealed, stampDeniable } from './padding.js';
import { hex, rnd }     from '../utils.js';

const ONLINE_TTL  = 90000;  // 90s
const HB_INTERVAL = 30000;  // 30s

const _peerOnline = {};
let   _hbTimer    = null;

export function markOnline(peerPub) { _peerOnline[peerPub] = Date.now(); }
export function isOnline(peerPub)   { return Date.now() - (_peerOnline[peerPub] || 0) < ONLINE_TTL; }

function getOnlinePeers() {
  return Object.keys(window._PEERS || {})
    .filter(p => window._PEERS[p]?.kyberPk && isOnline(p) && p !== window._NK?.pub);
}

// ── Heartbeat (v:5 — simple AES-KEM, ephemeral keypair, matches original) ──

export async function sendHeartbeat() {
  const NK = window._NK, KK = window._KKkeys, CONN = window._CONN;
  if (!NK || !KK || !CONN?.size) return;
  const peers = Object.keys(window._PEERS || {}).filter(p => window._PEERS[p]?.kyberPk);
  for (const p of peers) {
    try {
      const peer   = window._PEERS[p];
      const { ct, K } = kemE(peer.kyberPk);
      const { iv, ct: a } = await aesEnc(K, JSON.stringify({ type: '__hb__', from: NK.pub, ts: Date.now() }));
      const enc    = JSON.stringify({ v: 5, kem: ct, iv, ct: a });
      const ephNK  = genNKP();
      const ev     = await buildEv(4, enc, [['p', p]], ephNK.priv, ephNK.pub);
      Object.values(window._WS || {}).forEach(ws => {
        if (ws.readyState === 1) ws.send(JSON.stringify(['EVENT', ev]));
      });
    } catch {}
  }
}

export function startHeartbeat() {
  if (_hbTimer) return;
  sendHeartbeat();
  _hbTimer = setInterval(sendHeartbeat, HB_INTERVAL);
}

export function stopHeartbeat() { clearInterval(_hbTimer); _hbTimer = null; }

// ── Onion layer encryption (v:6) ──

async function encryptLayer(kyberPk, content) {
  const { ct, K } = kemE(kyberPk);
  const { iv, ct: a } = await aesEnc(K, JSON.stringify(content));
  return JSON.stringify({ v: 6, kem: ct, iv, ct: a });
}

async function buildOnion(destPub, finalEncPayload, route) {
  // route = [node1, node2, ..., destPub] (destPub already last)
  const destPeer = window._PEERS?.[destPub];
  if (!destPeer?.kyberPk) throw new Error('No key for dest');

  // Innermost: destination gets final payload
  let current = await encryptLayer(destPeer.kyberPk, { type: 'onion_final', payload: finalEncPayload, dest: destPub });

  // Wrap relay layers in reverse
  for (let i = route.length - 2; i >= 0; i--) {
    const nodePeer = window._PEERS?.[route[i]];
    if (!nodePeer?.kyberPk) throw new Error('No key for node ' + route[i]);
    current = await encryptLayer(nodePeer.kyberPk, { type: 'onion_relay', next: route[i + 1], ct: current });
  }
  return current;
}

// ── sendHybrid — matches original exactly ──

export async function sendHybrid(destPub, destKyberPk, obj) {
  const NK = window._NK, KK = window._KKkeys;
  if (!NK || !KK || !destKyberPk) throw new Error('Not ready');

  // Stamp deniable auth
  try { await stampDeniable(obj, destPub); } catch {}

  // Build sealed inner payload
  const innerObj = { ...obj, _sender: { nostr: NK.pub, kyber: KK.pk } };

  // Encrypt with padding → v:4 envelope (matches original pqEncPadded output)
  const { padPlain } = await import('../crypto/ratchet.js');
  const { ct, K }    = kemE(destKyberPk);
  const { iv, ct: a } = await aesEnc(K, padPlain(JSON.stringify(innerObj)));
  const finalEnc = JSON.stringify({ v: 4, kem: ct, iv, ct: a });

  // Try onion routing with 2+ online peers
  const online = getOnlinePeers().filter(p => p !== destPub && window._PEERS[p]?.kyberPk);
  let sentViaOnion = false;

  if (online.length >= 1) {
    // Try onion routing: 2-hop if 2+ peers, 1-hop fallback
    const shuffled = online.sort(() => Math.random() - 0.5);
    const route = online.length >= 2
      ? [shuffled[0], shuffled[1], destPub]
      : [shuffled[0], destPub];
    try {
      const onion    = await buildOnion(destPub, finalEnc, route);
      // Onion first hop uses ephemeral keypair (sealed sender — matches original)
      const ephNK    = genNKP();
      const tags     = [['p', route[0]]];
      const ev       = await buildEv(4, onion, tags, ephNK.priv, ephNK.pub);
      let n = 0;
      Object.values(window._WS || {}).forEach(ws => {
        if (ws.readyState === 1) { ws.send(JSON.stringify(['EVENT', ev])); n++; }
      });
      if (n > 0) sentViaOnion = true;
    } catch (e) {
      console.warn('Onion failed, falling back to direct:', e);
    }
  }

  // Direct send — ephemeral keypair (sealed sender, matches original exactly)
  if (!sentViaOnion) {
    const ephNK = genNKP();
    const tags  = [['p', destPub]];
    const ev    = await buildEv(4, finalEnc, tags, ephNK.priv, ephNK.pub);
    let n = 0;
    Object.values(window._WS || {}).forEach(ws => {
      if (ws.readyState === 1) { ws.send(JSON.stringify(['EVENT', ev])); n++; }
    });
    if (n === 0) throw new Error('relay_offline');
  }

  // Non-blocking cover traffic to other peers
  const others = Object.keys(window._PEERS || {}).filter(p => p !== destPub && window._PEERS[p]?.kyberPk);
  others.forEach(p => setTimeout(() => sendDummySealed(p).catch(() => {}), 50 + Math.random() * 250));
}
