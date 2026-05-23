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

export async function drInitRecv(peerPub, peerKyberPk, initCt, mySk) {
  const initK = kemD(initCt, mySk);
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
