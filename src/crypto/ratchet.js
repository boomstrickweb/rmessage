import { te, hex, fhex } from '../utils.js';
import { kemKG, kemE, kemD } from './mlkem.js';

// HKDF-SHA256: derive keys from input key material
export async function hkdf2(ikm, salt, info1, info2) {
  const base = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: te(info1 + info2) }, base, 512);
  return [new Uint8Array(bits, 0, 32), new Uint8Array(bits, 32, 32)];
}

export async function hkdf1(ikm, salt, info) {
  const base = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: te(info) }, base, 256);
  return new Uint8Array(bits);
}

// HMAC-SHA256
export async function hmac256(keyBytes, data) {
  const k = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const inp = typeof data === 'string' ? te(data) : data;
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, inp));
}

// Deniable Auth
async function getDeniableKey(peerPub) {
  const st = drLoad(peerPub);
  if (!st?.rootKey) return null;
  return hkdf1(fhex(st.rootKey), new Uint8Array(32), 'RELAY_DENIABLE_AUTH');
}

export async function stampDeniable(obj, peerPub) {
  try {
    const dk = await getDeniableKey(peerPub);
    if (!dk) return obj;
    const input = te(obj.id + (obj.ts || Date.now()));
    const tag = await hmac256(dk, input);
    obj._da = hex(tag).slice(0, 32);
  } catch { }
  return obj;
}

export async function verifyDeniable(obj, peerPub) {
  if (!obj._da) return null;
  try {
    const dk = await getDeniableKey(peerPub);
    if (!dk) return null;
    const input = te(obj.id + (obj.ts || 0));
    const expected = await hmac256(dk, input);
    const expectedHex = hex(expected).slice(0, 32);
    if (expectedHex.length !== obj._da.length) return false;
    let diff = 0;
    for (let i = 0; i < expectedHex.length; i++)
      diff |= expectedHex.charCodeAt(i) ^ obj._da.charCodeAt(i);
    return diff === 0;
  } catch { return null; }
}

function drKey(peerPub) { return 'rl6_dr_' + peerPub; }

export function drLoad(peerPub) {
  try { const d = JSON.parse(localStorage.getItem(drKey(peerPub))); if (d) return d; } catch { }
  return null;
}

export function drSave(peerPub, st) {
  try { localStorage.setItem(drKey(peerPub), JSON.stringify(st)); } catch { }
}

export async function drInit(peerPub, peerKyberPk) {
  const eph = kemKG();
  const { ct: initCt, K: initK } = kemE(peerKyberPk);
  const salt = new Uint8Array(32);
  const [rootKey, sendChainKey] = await hkdf2(initK, salt, 'RELAY_DR_ROOT', '_INIT');
  const st = {
    rootKey: hex(rootKey),
    sendChainKey: hex(sendChainKey),
    recvChainKey: null,
    sendN: 0, recvN: 0,
    peerKyberPk,
    myEphPk: eph.pk, myEphSk: eph.sk,
    initCt,
    initialized: true
  };
  drSave(peerPub, st);
  return st;
}

export async function drInitRecv(peerPub, peerKyberPk, initCt) {
  const initK = kemD(initCt, window._KKkeys.sk);
  const salt = new Uint8Array(32);
  const [rootKey, recvChainKey] = await hkdf2(initK, salt, 'RELAY_DR_ROOT', '_INIT');
  const eph = kemKG();
  const st = {
    rootKey: hex(rootKey),
    sendChainKey: null,
    recvChainKey: hex(recvChainKey),
    sendN: 0, recvN: 0,
    peerKyberPk,
    myEphPk: eph.pk, myEphSk: eph.sk,
    initialized: true
  };
  drSave(peerPub, st);
  return st;
}

async function drAdvanceChain(chainKeyHex) {
  const ck = fhex(chainKeyHex);
  const mk = await hkdf1(ck, new Uint8Array(32), 'RELAY_DR_MSG_KEY');
  const nextCk = await hkdf1(ck, new Uint8Array(32), 'RELAY_DR_CHAIN_ADV');
  return { mk, nextCk };
}

export async function drEncrypt(peerPub, plaintext) {
  let st = drLoad(peerPub);
  const peer = window._PEERS[peerPub];
  if (!st || !st.initialized) st = await drInit(peerPub, peer.kyberPk);
  if (!st.sendChainKey) {
    const targetPk = st.peerEphPk || peer.kyberPk;
    const { ct: ratchetCt, K: ratchetK } = kemE(targetPk);
    const [newRoot, newSendChain] = await hkdf2(fhex(st.rootKey), ratchetK, 'RELAY_DR_ROOT', '_RATCHET');
    st.rootKey = hex(newRoot); st.sendChainKey = hex(newSendChain);
    st.myRatchetCt = ratchetCt;
  }
  const { mk, nextCk } = await drAdvanceChain(st.sendChainKey);
  st.sendChainKey = hex(nextCk);
  const n = st.sendN++;
  const aesKey = await crypto.subtle.importKey('raw', mk, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = rnd(12);
  const inp = plaintext instanceof Uint8Array ? plaintext : te(typeof plaintext === 'string' ? plaintext : JSON.stringify(plaintext));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, inp));
  const result = { v: 4, n, iv: hex(iv), ct: hex(ct) };
  if (st.initCt) { result.initCt = st.initCt; st.initCt = null; }
  if (st.myRatchetCt) { result.ratchetCt = st.myRatchetCt; st.myRatchetCt = null; }
  result.ephPk = st.myEphPk;
  drSave(peerPub, st);
  return JSON.stringify(result);
}

export async function drDecrypt(peerPub, payload) {
  const { v, n, initCt, ratchetCt, ephPk, iv, ct } = JSON.parse(payload);
  if (v !== 4) throw new Error('DR version mismatch');
  let st = drLoad(peerPub);
  const peer = window._PEERS[peerPub];
  if (!st || !st.initialized) {
    if (!initCt) throw new Error('DR: no initCt');
    st = await drInitRecv(peerPub, peer.kyberPk, initCt);
  }
  if (ephPk) st.peerEphPk = ephPk;
  if (ratchetCt) {
    const ratchetK = kemD(ratchetCt, st.myEphSk);
    const [newRoot, newRecvChain] = await hkdf2(fhex(st.rootKey), ratchetK, 'RELAY_DR_ROOT', '_RATCHET');
    st.rootKey = hex(newRoot); st.recvChainKey = hex(newRecvChain);
    const newEph = kemKG();
    st.myEphPk = newEph.pk; st.myEphSk = newEph.sk;
    st.sendChainKey = null;
  }
  if (!st.recvChainKey) throw new Error('DR: no recv chain');
  const { mk, nextCk } = await drAdvanceChain(st.recvChainKey);
  st.recvChainKey = hex(nextCk); st.recvN++;
  const aesKey = await crypto.subtle.importKey('raw', mk, { name: 'AES-GCM' }, false, ['decrypt']);
  const plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fhex(iv) }, aesKey, fhex(ct)));
  drSave(peerPub, st);
  return plain;
}
