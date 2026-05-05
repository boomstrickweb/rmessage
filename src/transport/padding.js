/**
 * padding.js — Traffic Padding + Sealed Sender + Deniable Authentication
 *
 * Traffic Padding:
 *   Sends dummy events to all known peers at random intervals (5–14s).
 *   Dummy events are indistinguishable from real ones at the relay level.
 *
 * Sealed Sender:
 *   Real events use a throwaway ephemeral Nostr keypair.
 *   Relay sees: anonymous pubkey → recipient tag.
 *   Real sender identity is encrypted inside the payload.
 *
 * Deniable Authentication:
 *   HMAC-SHA256 tag derived from the Double Ratchet epoch shared secret.
 *   Both sender and receiver can compute this tag, so neither can
 *   prove authorship to a third party (Signal-style deniability).
 *
 * Exports: startPadding, stopPadding, sendWithCoverSealed, sendDummySealed,
 *          stampDeniable, verifyDeniable
 */

'use strict';

import { buildEv }         from '../crypto/secp256k1.js';
import { genNKP }          from '../crypto/secp256k1.js';
import { pqEncPadded }     from '../crypto/ratchet.js';
import { hex, rnd, te }    from '../utils.js';

const PAD_MIN_MS = 5000;
const PAD_MAX_MS = 14000;
let _padTimer = null;

// ── HMAC-SHA256 ──

async function hmac256(keyBytes, data) {
  const k   = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const inp = typeof data === 'string' ? te(data) : data;
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, inp));
}

async function getDeniableKey(peerPub) {
  try {
    const st = JSON.parse(localStorage.getItem('rl6_dr_' + peerPub));
    if (!st?.rootKey) return null;
    const { hkdf1 } = await import('../crypto/ratchet.js');
    return hkdf1(
      (await import('../utils.js')).fhex(st.rootKey),
      new Uint8Array(32),
      'RELAY_DENIABLE_AUTH'
    );
  } catch { return null; }
}

/**
 * Stamp a deniable HMAC auth tag on an outgoing message object.
 */
export async function stampDeniable(obj, peerPub) {
  try {
    const dk = await getDeniableKey(peerPub);
    if (!dk) return obj;
    const input = te(obj.id + (obj.ts || Date.now()));
    const tag   = await hmac256(dk, input);
    obj._da     = hex(tag).slice(0, 32);
  } catch {}
  return obj;
}

/**
 * Verify a deniable HMAC auth tag on an incoming message.
 * Returns true (valid), false (tampered), or null (no tag — backward compat).
 */
export async function verifyDeniable(obj, peerPub) {
  if (!obj._da) return null;
  try {
    const dk = await getDeniableKey(peerPub);
    if (!dk) return null;
    const input       = te(obj.id + (obj.ts || 0));
    const expected    = await hmac256(dk, input);
    const expectedHex = hex(expected).slice(0, 32);
    if (expectedHex.length !== obj._da.length) return false;
    let diff = 0;
    for (let i = 0; i < expectedHex.length; i++) diff |= expectedHex.charCodeAt(i) ^ obj._da.charCodeAt(i);
    return diff === 0;
  } catch { return null; }
}

// ── Sealed Sender ──

async function sealedSend(toPub, encContent, tags) {
  const ephNK = genNKP();
  const ev    = await buildEv(4, encContent, tags, ephNK.priv, ephNK.pub);
  Object.values(window._WS || {}).forEach(ws => { if (ws.readyState === 1) ws.send(JSON.stringify(['EVENT', ev])); });
}

export async function sendDummySealed(toPub) {
  const peer = window._PEERS?.[toPub];
  if (!peer?.kyberPk) return;
  const dummy = {
    id: hex(rnd(16)), type: '__pad__', from: window._NK?.pub, to: toPub,
    lam: 0, vc: {}, payload: {}, ts: Date.now(),
    _sender: { nostr: window._NK?.pub, kyber: window._KKkeys?.pk },
  };
  await stampDeniable(dummy, toPub);
  try {
    const enc  = await pqEncPadded(peer.kyberPk, JSON.stringify(dummy));
    const tags = [['p', toPub]];
    await sealedSend(toPub, enc, tags);
  } catch {}
}

/**
 * Send a real message with cover traffic (sealed sender + dummy events to all other peers).
 */
export async function sendWithCoverSealed(realToPub, realKyberPk, obj) {
  await stampDeniable(obj, realToPub);
  const innerObj = { ...obj, _sender: { nostr: window._NK?.pub, kyber: window._KKkeys?.pk } };
  const enc      = await pqEncPadded(realKyberPk, JSON.stringify(innerObj));
  const tags     = [['p', realToPub]];
  await sealedSend(realToPub, enc, tags);
  const others = Object.keys(window._PEERS || {}).filter(p => p !== realToPub && window._PEERS[p]?.kyberPk);
  others.forEach((p, i) => setTimeout(() => sendDummySealed(p), 50 + Math.random() * 250));
}

// ── Traffic padding loop ──

export function startPadding() {
  if (_padTimer) return;
  const fire = async () => {
    const peers = Object.keys(window._PEERS || {}).filter(p => window._PEERS[p]?.kyberPk);
    const CONN  = window._CONN;
    if (peers.length && CONN?.size > 0) {
      const count  = 1 + Math.floor(Math.random() * Math.min(2, peers.length));
      const picked = peers.sort(() => Math.random() - 0.5).slice(0, count);
      for (const p of picked) await sendDummySealed(p);
    }
    _padTimer = setTimeout(fire, PAD_MIN_MS + Math.random() * (PAD_MAX_MS - PAD_MIN_MS));
  };
  _padTimer = setTimeout(fire, PAD_MIN_MS + Math.random() * (PAD_MAX_MS - PAD_MIN_MS));
}

export function stopPadding() { clearTimeout(_padTimer); _padTimer = null; }
