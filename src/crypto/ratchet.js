/**
 * ratchet.js — Double Ratchet + HKDF
 *
 * Provides forward secrecy for text messages over Nostr.
 * Each message uses a unique message key derived from the ratchet chain.
 * Ratchet steps use fresh ML-KEM ephemeral keypairs.
 *
 * Exports: drInit, drInitRecv, drEncrypt, drDecrypt, pqEncStr, pqDecStr,
 *          pqEncBin, pqDecBin, pqEncPadded, aesEnc, aesDec, hkdf1, hkdf2,
 *          yieldUI
 */

'use strict';

import { kemKG, kemE, kemD } from './mlkem.js';
import { hex, fhex, rnd, te, td, cat } from '../utils.js';

// ── HKDF helpers (WebCrypto) ──

export async function hkdf1(ikm, salt, info) {
  const base = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: te(info) }, base, 256
  );
  return new Uint8Array(bits);
}

export async function hkdf2(ikm, salt, info1, info2) {
  const k1 = await hkdf1(ikm, salt, info1);
  const k2 = await hkdf1(ikm, salt, info1 + info2);
  return [k1, k2];
}

// ── AES-256-GCM ──

export async function aesEnc(K, plain) {
  const key = await crypto.subtle.importKey('raw', K, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv  = rnd(12);
  const inp = plain instanceof Uint8Array ? plain : te(typeof plain === 'string' ? plain : JSON.stringify(plain));
  const ct  = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, inp));
  return { iv: hex(iv), ct: hex(ct) };
}

export async function aesDec(K, ivH, ctH) {
  const key = await crypto.subtle.importKey('raw', K, { name: 'AES-GCM' }, false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fhex(ivH) }, key, fhex(ctH)));
}

// ── UI yield — prevents ML-KEM from blocking the thread ──
// MessageChannel is ~5x faster than setTimeout(0) for this purpose

export function yieldUI() {
  return new Promise(r => { const ch = new MessageChannel(); ch.port1.onmessage = r; ch.port2.postMessage(0); });
}

// ── Double Ratchet state storage ──

const DR_PREFIX = 'rl6_dr_';
const drKey = peerPub => DR_PREFIX + peerPub;

function drLoad(peerPub) {
  try { return JSON.parse(localStorage.getItem(drKey(peerPub))); } catch { return null; }
}

function drSave(peerPub, st) {
  try { localStorage.setItem(drKey(peerPub), JSON.stringify(st)); } catch {}
}

// ── DR init (sender side) ──

export async function drInit(peerPub, peerKyberPk) {
  const eph = kemKG();
  const { ct: initCt, K: initK } = kemE(peerKyberPk);
  const [rootKey, sendChainKey] = await hkdf2(initK, new Uint8Array(32), 'RELAY_DR_ROOT', '_INIT');
  const st = {
    initialized: true,
    rootKey: hex(rootKey),
    sendChainKey: hex(sendChainKey),
    recvChainKey: null,
    sendN: 0, recvN: 0,
    initCt,
    myEphPk: eph.pk, myEphSk: eph.sk,
    myRatchetCt: null, peerEphPk: null,
    ratchetN: 0,
  };
  drSave(peerPub, st);
  return st;
}

// ── DR init (receiver side) ──

export async function drInitRecv(peerPub, myKyberSk, initCt) {
  const initK = kemD(initCt, myKyberSk);
  const [rootKey, recvChainKey] = await hkdf2(initK, new Uint8Array(32), 'RELAY_DR_ROOT', '_INIT');
  const eph = kemKG();
  const st = {
    initialized: true,
    rootKey: hex(rootKey),
    sendChainKey: null,
    recvChainKey: hex(recvChainKey),
    sendN: 0, recvN: 0,
    initCt: null,
    myEphPk: eph.pk, myEphSk: eph.sk,
    myRatchetCt: null, peerEphPk: null,
    ratchetN: 0,
  };
  drSave(peerPub, st);
  return st;
}

async function drAdvanceChain(chainKeyHex) {
  const ck     = fhex(chainKeyHex);
  const mk     = await hkdf1(ck, new Uint8Array(32), 'RELAY_DR_MSG_KEY');
  const nextCk = await hkdf1(ck, new Uint8Array(32), 'RELAY_DR_CHAIN_ADV');
  return { mk, nextCk };
}

// ── Encrypt with Double Ratchet ──

export async function drEncrypt(peerPub, plaintext, peerKyberPk) {
  let st = drLoad(peerPub);
  if (!st || !st.initialized) {
    st = await drInit(peerPub, peerKyberPk);
  }
  if (!st.sendChainKey) {
    const targetPk = st.peerEphPk || peerKyberPk;
    const { ct: ratchetCt, K: ratchetK } = kemE(targetPk);
    const [newRoot, newSendChain] = await hkdf2(fhex(st.rootKey), ratchetK, 'RELAY_DR_ROOT', '_RATCHET');
    st.rootKey      = hex(newRoot);
    st.sendChainKey = hex(newSendChain);
    st.myRatchetCt  = ratchetCt;
    st.ratchetN     = (st.ratchetN || 0) + 1;
  }
  const { mk, nextCk } = await drAdvanceChain(st.sendChainKey);
  st.sendChainKey = hex(nextCk);
  const n = st.sendN++;
  const aesKey = await crypto.subtle.importKey('raw', mk, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv  = rnd(12);
  const inp = plaintext instanceof Uint8Array ? plaintext : te(typeof plaintext === 'string' ? plaintext : JSON.stringify(plaintext));
  const ct  = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, inp));
  const result = { v: 4, n, iv: hex(iv), ct: hex(ct) };
  if (st.initCt)      { result.initCt = st.initCt; st.initCt = null; }
  if (st.myRatchetCt) { result.ratchetCt = st.myRatchetCt; st.myRatchetCt = null; }
  result.ephPk = st.myEphPk;
  drSave(peerPub, st);
  return JSON.stringify(result);
}

// ── Decrypt with Double Ratchet ──

export async function drDecrypt(peerPub, payload, myKyberSk) {
  const { v, n, initCt, ratchetCt, ephPk, iv, ct } = JSON.parse(payload);
  if (v !== 4) throw new Error('DR version mismatch');
  let st = drLoad(peerPub);
  if (!st || !st.initialized) {
    if (!initCt) throw new Error('DR: no initCt for first message');
    st = await drInitRecv(peerPub, myKyberSk, initCt);
  }
  if (ephPk) st.peerEphPk = ephPk;
  if (ratchetCt) {
    const ratchetK = kemD(ratchetCt, st.myEphSk);
    const [newRoot, newRecvChain] = await hkdf2(fhex(st.rootKey), ratchetK, 'RELAY_DR_ROOT', '_RATCHET');
    st.rootKey      = hex(newRoot);
    st.recvChainKey = hex(newRecvChain);
    const newEph    = kemKG();
    st.myEphPk      = newEph.pk; st.myEphSk = newEph.sk;
    st.myRatchetCt  = null;
    st.sendChainKey = null;
  }
  if (!st.recvChainKey) throw new Error('DR: no recv chain');
  const { mk, nextCk } = await drAdvanceChain(st.recvChainKey);
  st.recvChainKey = hex(nextCk);
  st.recvN++;
  const aesKey = await crypto.subtle.importKey('raw', mk, { name: 'AES-GCM' }, false, ['decrypt']);
  const plain  = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fhex(iv) }, aesKey, fhex(ct)));
  drSave(peerPub, st);
  return plain;
}

// ── Traffic padding helpers ──

const PAD_BLOCK = 512;

export function padPlain(str) {
  const b      = te(str);
  const target = Math.ceil((b.length + 2) / PAD_BLOCK) * PAD_BLOCK;
  const padLen = target - b.length - 2;
  const out    = new Uint8Array(2 + b.length + padLen);
  new DataView(out.buffer).setUint16(0, b.length);
  out.set(b, 2); out.set(rnd(padLen), 2 + b.length);
  return out;
}

export function unpadPlain(bytes) {
  const realLen = new DataView(bytes.buffer, bytes.byteOffset, 2).getUint16(0);
  return td(bytes.slice(2, 2 + realLen));
}

// ── High-level encryption helpers ──

export async function pqEncStr(pkH, str, peerPub, peerKyberPk) {
  if (peerPub) {
    const drPayload = await drEncrypt(peerPub, str, peerKyberPk);
    const { ct, K } = kemE(pkH);
    const { iv, ct: a } = await aesEnc(K, drPayload);
    return JSON.stringify({ v: 4, kem: ct, iv, ct: a });
  }
  const { ct, K } = kemE(pkH);
  const { iv, ct: a } = await aesEnc(K, str);
  return JSON.stringify({ v: 3, kem: ct, iv, ct: a });
}

export async function pqDecStr(skH, payload) {
  const parsed = JSON.parse(payload);
  const raw    = await aesDec(kemD(parsed.kem, skH), parsed.iv, parsed.ct);
  return td(raw);
}

async function _hkdfKey(raw) {
  const base = await crypto.subtle.importKey('raw', raw, { name: 'HKDF' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new Uint8Array(0) },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

export async function pqEncBin(pkH, bytes) {
  await yieldUI();
  const { ct, K } = kemE(pkH);
  const key = await _hkdfKey(K);
  const iv  = rnd(12);
  const inp = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, inp);
  return { kem: ct, iv: hex(iv), ct: hex(new Uint8Array(enc)) };
}

export async function pqDecBin(skH, kem, iv, ct) {
  await yieldUI();
  const K   = kemD(kem, skH);
  const key = await _hkdfKey(K);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fhex(iv) }, key, fhex(ct)));
}

export async function pqEncPadded(pkH, str) {
  const padded = padPlain(typeof str === 'string' ? str : JSON.stringify(str));
  const { ct, K } = kemE(pkH);
  const { iv, ct: a } = await aesEnc(K, padded);
  return JSON.stringify({ v: 4, kem: ct, iv, ct: a });
}
