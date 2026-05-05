/**
 * onion.js — Hybrid Onion Routing (mini-Tor over Nostr)
 *
 * When 2+ peers are online:
 *   Origin → Node1 → Node2 → Destination
 * Each node peels one encryption layer and sees only prev/next hop.
 * Relay sees: random pubkeys, uniform ciphertext size.
 * Falls back to direct sealed-sender if no online peers available.
 *
 * Online detection: peers send heartbeat pings every 30s.
 * A peer is considered online if last ping was <90s ago.
 *
 * Exports: startHeartbeat, stopHeartbeat, sendHybrid, markOnline, isOnline
 */

'use strict';

import { kemE, kemKG }     from '../crypto/mlkem.js';
import { aesEnc, aesDec, pqEncPadded } from '../crypto/ratchet.js';
import { buildEv }         from '../crypto/secp256k1.js';
import { genNKP }          from '../crypto/secp256k1.js';
import { nostrPub }        from './nostr.js';
import { sendWithCoverSealed } from './padding.js';
import { hex, fhex, rnd } from '../utils.js';

const ONLINE_TTL    = 90000;  // 90 seconds
const HB_INTERVAL   = 30000;  // heartbeat every 30s

const _peerOnline = {};
let _hbTimer = null;

export function markOnline(peerPub) { _peerOnline[peerPub] = Date.now(); }
export function isOnline(peerPub)   { return Date.now() - (_peerOnline[peerPub] || 0) < ONLINE_TTL; }

function getOnlinePeers() {
  return Object.keys(window._PEERS || {})
    .filter(p => window._PEERS[p]?.kyberPk && isOnline(p) && p !== window._NK?.pub);
}

// ── Heartbeat ──

export async function sendHeartbeat() {
  const NK = window._NK, KKkeys = window._KKkeys, CONN = window._CONN;
  if (!NK || !KKkeys || !CONN?.size) return;
  const peers = Object.keys(window._PEERS || {}).filter(p => window._PEERS[p]?.kyberPk);
  for (const p of peers) {
    try {
      const peer = window._PEERS[p];
      const { ct, K } = kemE(peer.kyberPk);
      const { iv, ct: a } = await aesEnc(K, JSON.stringify({ type: '__hb__', from: NK.pub, ts: Date.now() }));
      const enc   = JSON.stringify({ v: 5, kem: ct, iv, ct: a });
      const ephNK = genNKP();
      const ev    = await buildEv(4, enc, [['p', p]], ephNK.priv, ephNK.pub);
      Object.values(window._WS || {}).forEach(ws => { if (ws.readyState === 1) ws.send(JSON.stringify(['EVENT', ev])); });
    } catch {}
  }
}

export function startHeartbeat() {
  if (_hbTimer) return;
  sendHeartbeat();
  _hbTimer = setInterval(sendHeartbeat, HB_INTERVAL);
}

export function stopHeartbeat() { clearInterval(_hbTimer); _hbTimer = null; }

// ── Onion encryption ──

/**
 * Build an onion-encrypted payload for a multi-hop route.
 * @param {object} finalPayload - the actual message op (already serialized)
 * @param {string[]} route      - [node1Pub, node2Pub, ..., destPub]
 */
async function buildOnion(finalPayload, route) {
  // Innermost layer: the final payload encrypted for destination
  const dest      = route[route.length - 1];
  const destPeer  = window._PEERS?.[dest];
  if (!destPeer?.kyberPk) throw new Error('No kyberPk for destination');

  let layer = await pqEncPadded(destPeer.kyberPk, JSON.stringify({ type: 'onion_final', payload: finalPayload }));

  // Wrap in reverse order for intermediate hops
  for (let i = route.length - 2; i >= 0; i--) {
    const nodePub  = route[i];
    const nodePeer = window._PEERS?.[nodePub];
    if (!nodePeer?.kyberPk) throw new Error('No kyberPk for node ' + nodePub);
    const nextHop  = route[i + 1];
    layer = await pqEncPadded(nodePeer.kyberPk, JSON.stringify({ type: 'onion_relay', next: nextHop, ct: layer }));
  }
  return layer;
}

/**
 * Send via onion routing if enough online peers are available.
 * Falls back to direct sealed-sender otherwise.
 */
export async function sendHybrid(toPub, kyberPk, obj) {
  const online = getOnlinePeers().filter(p => p !== toPub);

  if (online.length >= 2) {
    // Pick 2 random relay nodes
    const shuffled = online.sort(() => Math.random() - 0.5);
    const route    = [shuffled[0], shuffled[1], toPub];
    try {
      const onion = await buildOnion(JSON.stringify(obj), route);
      // Send onion to first hop (node1) via sealed sender
      const firstHopPeer = window._PEERS?.[route[0]];
      if (firstHopPeer?.kyberPk) {
        await sendWithCoverSealed(route[0], firstHopPeer.kyberPk, {
          id: hex(rnd(16)), type: '__onion__', ct: onion,
          from: window._NK?.pub, to: route[0], lam: 0, vc: {}, ts: Date.now(),
        });
        // Update onion indicator
        document.getElementById('obar').classList.remove('on');
        return;
      }
    } catch (e) {
      console.warn('Onion routing failed, falling back to direct:', e);
    }
  }

  // Fallback: direct sealed sender
  await sendWithCoverSealed(toPub, kyberPk, obj);
}
