import { rnd, hex, fhex, cat, te } from '../utils.js';
import { SHAKE128, SHAKE256, SHA3_256, SHA3_512 } from './sha3.js';

const KQ = 3329, KN = 256, KK = 3, ET1 = 2, ET2 = 2, DU = 10, DV = 4;
const km = a => { a = a % KQ; return a < 0 ? a + KQ : a; };
const kpw = (b, e) => { let r = 1; b = km(b); while (e > 0) { if (e & 1) r = km(r * b); b = km(b * b); e >>= 1; } return r; };
const kbrv = x => { let r = 0; for (let i = 0; i < 7; i++) { r = (r << 1) | (x & 1); x >>= 1; } return r; };
const KZ = new Int32Array(128); for (let i = 0; i < 128; i++) KZ[i] = kpw(17, kbrv(i));

const knt = f => {
  const a = Int32Array.from(f); let i = 1;
  for (let l = 128; l >= 2; l >>= 1) for (let s = 0; s < KN; s += 2 * l) {
    const z = KZ[i++]; for (let j = s; j < s + l; j++) {
      const t = km(z * a[j + l]); a[j + l] = km(a[j] - t); a[j] = km(a[j] + t);
    }
  } return a;
};
const kit = f => {
  const a = Int32Array.from(f); let i = 127;
  for (let l = 2; l <= 128; l <<= 1) for (let s = 0; s < KN; s += 2 * l) {
    const z = KZ[i--]; for (let j = s; j < s + l; j++) {
      const t = a[j]; a[j] = km(t + a[j + l]); a[j + l] = km(z * km(a[j + l] - t));
    }
  } const iv = kpw(128, KQ - 2); for (let j = 0; j < KN; j++) a[j] = km(a[j] * iv); return a;
};

const kbm = (a, b) => {
  const c = new Int32Array(KN);
  for (let i = 0; i < 128; i++) {
    const g = kpw(17, 2 * kbrv(i) + 1);
    c[2 * i] = km(km(a[2 * i] * b[2 * i]) + km(km(a[2 * i + 1] * b[2 * i + 1]) * g));
    c[2 * i + 1] = km(km(a[2 * i] * b[2 * i + 1]) + km(a[2 * i + 1] * b[2 * i]));
  } return c;
};

const kpa = (a, b) => { const c = new Int32Array(KN); for (let i = 0; i < KN; i++) c[i] = km(a[i] + b[i]); return c; };
const kps = (a, b) => { const c = new Int32Array(KN); for (let i = 0; i < KN; i++) c[i] = km(a[i] - b[i]); return c; };
const kcp = (p, d) => { const c = new Int32Array(KN); for (let i = 0; i < KN; i++) c[i] = Math.round(p[i] * (1 << d) / KQ) & ((1 << d) - 1); return c; };
const kdp = (p, d) => { const c = new Int32Array(KN); for (let i = 0; i < KN; i++) c[i] = Math.round(p[i] * KQ / (1 << d)); return c; };

function kenc(p, d) {
  const o = new Uint8Array(KN * d / 8);
  for (let i = 0; i < KN; i++) {
    const v = p[i] & ((1 << d) - 1);
    for (let b = 0; b < d; b++) { const pos = i * d + b; if (v & (1 << b)) o[pos >> 3] |= 1 << (pos & 7); }
  } return o;
}

function kdec(bytes, d) {
  const p = new Int32Array(KN);
  for (let i = 0; i < KN; i++) {
    let v = 0; for (let b = 0; b < d; b++) { const pos = i * d + b; v |= ((bytes[pos >> 3] >> (pos & 7)) & 1) << b; }
    p[i] = v;
  } return p;
}

const kH = d => SHA3_256(d);
const kG = d => { const h = SHA3_512(d); return [h.slice(0, 32), h.slice(32)]; };
const kPRF = (s, b, l) => SHAKE256(cat(s, new Uint8Array([b])), l);
const kXOF = (rho, i, j, l) => SHAKE128(cat(rho, new Uint8Array([i, j])), l);

function kSU(b) {
  const p = new Int32Array(KN); let j = 0, pos = 0;
  while (j < KN && pos + 2 < b.length) {
    const d1 = b[pos] | ((b[pos + 1] & 0xF) << 8); const d2 = (b[pos + 1] >> 4) | (b[pos + 2] << 4); pos += 3;
    if (d1 < KQ) p[j++] = d1; if (j < KN && d2 < KQ) p[j++] = d2;
  } return p;
}

function kCBD(eta, b) {
  const p = new Int32Array(KN);
  for (let i = 0; i < KN; i++) {
    let a = 0, bb = 0;
    for (let j = 0; j < eta; j++) { const idx = 2 * eta * i + j; a += (b[idx >> 3] >> (idx & 7)) & 1; }
    for (let j = 0; j < eta; j++) { const idx = 2 * eta * i + eta + j; bb += (b[idx >> 3] >> (idx & 7)) & 1; }
    p[i] = km(a - bb);
  } return p;
}

function kGA(rho, tr) {
  const A = [];
  for (let i = 0; i < KK; i++) {
    A[i] = [];
    for (let j = 0; j < KK; j++) { const bi = tr ? j : i, bj = tr ? i : j; A[i][j] = kSU(kXOF(rho, bi, bj, 672)); }
  } return A;
}

export function kemKG() {
  const d = rnd(32), z = rnd(32); const [rho, sigma] = kG(d); const A = kGA(rho, false);
  const sh = [], eh = [];
  for (let i = 0; i < KK; i++) sh[i] = knt(kCBD(ET1, kPRF(sigma, i, 64 * ET1)));
  for (let i = 0; i < KK; i++) eh[i] = knt(kCBD(ET1, kPRF(sigma, KK + i, 64 * ET1)));
  const th = [];
  for (let i = 0; i < KK; i++) {
    let s = new Int32Array(KN); for (let j = 0; j < KK; j++) s = kpa(s, kbm(A[i][j], sh[j]));
    th[i] = kpa(s, eh[i]);
  }
  const pk = new Uint8Array(KK * 384 + 32); for (let i = 0; i < KK; i++) pk.set(kenc(th[i], 12), i * 384); pk.set(rho, KK * 384);
  const hpk = kH(pk);
  const sk = new Uint8Array(KK * 384 + pk.length + 32 + 32);
  for (let i = 0; i < KK; i++) sk.set(kenc(sh[i], 12), i * 384);
  sk.set(pk, KK * 384); sk.set(hpk, KK * 384 + pk.length); sk.set(z, KK * 384 + pk.length + 32);
  return { pk: hex(pk), sk: hex(sk) };
}

export function kemE(pkH) {
  const pk = fhex(pkH), m = rnd(32), hpk = kH(pk); const [Kss, r] = kG(cat(m, hpk));
  const th = []; for (let i = 0; i < KK; i++) th[i] = kdec(pk.slice(i * 384, (i + 1) * 384), 12);
  const rho = pk.slice(KK * 384, KK * 384 + 32); const A = kGA(rho, true);
  const rh = [], e1 = [];
  for (let i = 0; i < KK; i++) rh[i] = knt(kCBD(ET1, kPRF(r, i, 64 * ET1)));
  for (let i = 0; i < KK; i++) e1[i] = kCBD(ET2, kPRF(r, KK + i, 64 * ET2));
  const e2 = kCBD(ET2, kPRF(r, 2 * KK, 64 * ET2));
  const u = [];
  for (let i = 0; i < KK; i++) {
    let s = new Int32Array(KN); for (let j = 0; j < KK; j++) s = kpa(s, kbm(A[i][j], rh[j]));
    u[i] = kpa(kit(s), e1[i]);
  }
  let vs = new Int32Array(KN); for (let i = 0; i < KK; i++) vs = kpa(vs, kbm(th[i], rh[i]));
  const mu = new Int32Array(KN); for (let i = 0; i < KN; i++) mu[i] = ((m[i >> 3] >> (i & 7)) & 1) * Math.round(KQ / 2);
  const v = kpa(kpa(kit(vs), e2), mu);
  const ct = new Uint8Array(KK * KN * DU / 8 + KN * DV / 8);
  for (let i = 0; i < KK; i++) ct.set(kenc(kcp(u[i], DU), DU), i * KN * DU / 8);
  ct.set(kenc(kcp(v, DV), DV), KK * KN * DU / 8);
  return { ct: hex(ct), K: Kss };
}

export function kemD(ctH, skH) {
  const ct = fhex(ctH), sk = fhex(skH);
  const sh = []; for (let i = 0; i < KK; i++) sh[i] = kdec(sk.slice(i * 384, (i + 1) * 384), 12);
  const u = []; for (let i = 0; i < KK; i++) u[i] = kdp(kdec(ct.slice(i * KN * DU / 8, (i + 1) * KN * DU / 8), DU), DU);
  const v = kdp(kdec(ct.slice(KK * KN * DU / 8, KK * KN * DU / 8 + KN * DV / 8), DV), DV);
  let inner = new Int32Array(KN); for (let i = 0; i < KK; i++) inner = kpa(inner, kbm(sh[i], knt(u[i])));
  const w = kps(v, kit(inner));
  const mp = new Uint8Array(32); for (let i = 0; i < KN; i++) { if (Math.round(w[i] * 2 / KQ) & 1) mp[i >> 3] |= 1 << (i & 7); }
  const pk_ = sk.slice(KK * 384, KK * 384 + KK * 384 + 32);
  const [Kss] = kG(cat(mp, kH(pk_)));
  return Kss;
}

export async function aesEnc(k, data) {
  const key = await crypto.subtle.importKey('raw', k, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = rnd(12); const inp = typeof data === 'string' ? te(data) : (data instanceof Uint8Array ? data : new Uint8Array(data));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, inp);
  return { iv: hex(iv), ct: hex(new Uint8Array(ct)) };
}

export async function aesDec(k, ivH, ctH) {
  const key = await crypto.subtle.importKey('raw', k, { name: 'AES-GCM' }, false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fhex(ivH) }, key, fhex(ctH)));
}

// Standalone AES-GCM for files (hybrid)
export async function aesEncGCM(k, data) {
  const key = await crypto.subtle.importKey('raw', k, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = rnd(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { iv: hex(iv), ct: hex(new Uint8Array(ct)) };
}

export async function aesDecGCM(k, ivH, ctH) {
  const key = await crypto.subtle.importKey('raw', k, { name: 'AES-GCM' }, false, ['decrypt']);
  const ct = fhex(ctH);
  const iv = fhex(ivH);
  const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new Uint8Array(dec);
}

// MessageChannel yield — 5x faster than setTimeout(0), frees UI
export function yieldUI() { return new Promise(r => { const ch = new MessageChannel(); ch.port1.onmessage = r; ch.port2.postMessage(0); }); }

export async function pqEncBin(pkH, bytes) {
  await yieldUI();
  const { ct, K } = kemE(pkH);
  const key = await _hkdfKey(K);
  const iv = rnd(12);
  const inp = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, inp);
  return { kem: ct, iv: hex(iv), ct: hex(new Uint8Array(enc)) };
}

export async function pqDecBin(skH, kem, iv, ct) {
  await yieldUI();
  const K = kemD(kem, skH);
  const key = await _hkdfKey(K);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fhex(iv) }, key, fhex(ct)));
}

async function _hkdfKey(raw) {
  const base = await crypto.subtle.importKey('raw', raw, { name: 'HKDF' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new Uint8Array(0) }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
