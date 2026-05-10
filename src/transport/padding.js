/**
 * padding.js — Traffic Padding + Deniable Authentication
 *
 * Matches original single-file implementation exactly.
 * sendDummySealed: dummy events via real NK keypair (not ephemeral)
 * stampDeniable / verifyDeniable: HMAC-SHA256 deniable auth tags
 *
 * Exports: startPadding, stopPadding, sendDummySealed,
 *          stampDeniable, verifyDeniable
 */

'use strict';

import { buildEv }      from '../crypto/secp256k1.js';
import { kemE }         from '../crypto/mlkem.js';
import { aesEnc }       from '../crypto/ratchet.js';
import { hex, rnd, te } from '../utils.js';

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
    const { fhex }  = await import('../utils.js');
    return hkdf1(fhex(st.rootKey), new Uint8Array(32), 'RELAY_DENIABLE_AUTH');
  } catch { return null; }
}

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

// ── Dummy send (matches original sendDummy — uses real NK keypair) ──

export async function sendDummySealed(toPub) {
  const peer = window._PEERS?.[toPub];
  const NK   = window._NK;
  const KK   = window._KKkeys;
  if (!peer?.kyberPk || !NK || !KK) return;
  try {
    const dummy = {
      id: hex(rnd(16)), type: '__pad__', from: NK.pub,
      to: toPub, lam: 0, vc: {}, payload: {}, ts: Date.now(),
      _sender: { nostr: NK.pub, kyber: KK.pk },
    };
    // pqEncPadded: ML-KEM-768 + AES-GCM + padPlain → v:4
    const { padPlain } = await import('../crypto/ratchet.js');
    const { ct, K }    = kemE(peer.kyberPk);
    const { iv, ct: a } = await aesEnc(K, padPlain(JSON.stringify(dummy)));
    const enc  = JSON.stringify({ v: 4, kem: ct, iv, ct: a });
    const tags = [['p', toPub], ['kyber', KK.pk]];
    const ev   = await buildEv(4, enc, tags, NK.priv, NK.pub);
    Object.values(window._WS || {}).forEach(ws => {
      if (ws.readyState === 1) ws.send(JSON.stringify(['EVENT', ev]));
    });
  } catch {}
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

// ── sendWithCoverSealed (used by onion.js for compatibility) ──
// Matches original sendWithCover: uses real NK keypair, not ephemeral

export async function sendWithCoverSealed(realToPub, realKyberPk, obj) {
  const NK = window._NK, KK = window._KKkeys;
  if (!NK || !KK) return;
  try {
    const innerObj = { ...obj, _sender: { nostr: NK.pub, kyber: KK.pk } };
    await stampDeniable(innerObj, realToPub);
    const { padPlain } = await import('../crypto/ratchet.js');
    const { ct, K }    = kemE(realKyberPk);
    const { iv, ct: a } = await aesEnc(K, padPlain(JSON.stringify(innerObj)));
    const enc  = JSON.stringify({ v: 4, kem: ct, iv, ct: a });
    const tags = [['p', realToPub], ['kyber', KK.pk]];
    const ev   = await buildEv(4, enc, tags, NK.priv, NK.pub);
    Object.values(window._WS || {}).forEach(ws => {
      if (ws.readyState === 1) ws.send(JSON.stringify(['EVENT', ev]));
    });
    // Cover traffic
    const others = Object.keys(window._PEERS || {}).filter(p => p !== realToPub && window._PEERS[p]?.kyberPk);
    others.forEach(p => setTimeout(() => sendDummySealed(p).catch(() => {}), 50 + Math.random() * 250));
  } catch (e) { throw e; }
}
