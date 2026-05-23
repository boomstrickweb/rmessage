import { rnd, hex, fhex, cat, te, td } from '../utils.js';
import { SHAKE128, SHAKE256, SHA3_256, SHA3_512 } from './sha3.js';

// ML-DSA-44 parameters (Dilithium-2, FIPS 204)
const MLDSAQ = 8380417, MLDSAN = 256, MLDSAL = 4, MLDSAK = 4;
const MLDSA_ETA = 2, MLDSA_TAU = 39, MLDSA_BETA = 78;
const MLDSA_GAMMA1 = 1 << 17, MLDSA_GAMMA2 = 95232;

const dmod = a => { a = a % MLDSAQ; return a < 0 ? a + MLDSAQ : a; };
const dpow = (b, e) => { let r = 1; b = dmod(b); while (e > 0) { if (e & 1) r = dmod(r * b); b = dmod(b * b); e >>= 1; } return r; };
const dbrv = x => { let r = 0; for (let i = 0; i < 7; i++) { r = (r << 1) | (x & 1); x >>= 1; } return r; };
const DZ = new Int32Array(256); for (let i = 0; i < 256; i++) DZ[i] = dpow(1753, dbrv(i));

const dntt = f => {
  const a = Int32Array.from(f); let i = 1;
  for (let l = 128; l >= 2; l >>= 1) for (let s = 0; s < MLDSAN; s += 2 * l) {
    const z = DZ[i++]; for (let j = s; j < s + l; j++) {
      const t = dmod(z * a[j + l]); a[j + l] = dmod(a[j] - t); a[j] = dmod(a[j] + t);
    }
  } return a;
};
const dintt = f => {
  const a = Int32Array.from(f); let i = 255;
  for (let l = 2; l <= 128; l <<= 1) for (let s = 0; s < MLDSAN; s += 2 * l) {
    const z = DZ[i--]; for (let j = s; j < s + l; j++) {
      const t = a[j]; a[j] = dmod(t + a[j + l]); a[j + l] = dmod(z * dmod(a[j + l] - t));
    }
  } const iv = dpow(256, MLDSAQ - 2); for (let j = 0; j < MLDSAN; j++) a[j] = dmod(a[j] * iv); return a;
};

const dmul = (a, b) => { const c = new Int32Array(MLDSAN); for (let i = 0; i < MLDSAN; i++) c[i] = dmod(a[i] * b[i]); return c; };
const dadd = (a, b) => { const c = new Int32Array(MLDSAN); for (let i = 0; i < MLDSAN; i++) c[i] = dmod(a[i] + b[i]); return c; };
const dsub = (a, b) => { const c = new Int32Array(MLDSAN); for (let i = 0; i < MLDSAN; i++) c[i] = dmod(a[i] - b[i]); return c; };

function denc10(p) {
  const o = new Uint8Array(320);
  for (let i = 0; i < MLDSAN; i++) {
    const v = dmod(p[i]); for (let b = 0; b < 10; b++) { const pos = i * 10 + b; if (v & (1 << b)) o[pos >> 3] |= 1 << (pos & 7); }
  } return o;
}
function ddec10(b) {
  const p = new Int32Array(MLDSAN);
  for (let i = 0; i < MLDSAN; i++) {
    let v = 0; for (let j = 0; j < 10; j++) { const pos = i * 10 + j; v |= ((b[pos >> 3] >> (pos & 7)) & 1) << j; }
    p[i] = v;
  } return p;
}

function dexpand(rho, i, j) {
  return dntt(Array.from({ length: MLDSAN }, (_, k) => {
    const bytes = SHAKE128(cat(rho, new Uint8Array([j, i])), 272);
    const d1 = bytes[k * 3] | (bytes[k * 3 + 1] & 0xF) << 8; return d1 < MLDSAQ ? d1 : 0;
  }).reduce((a, v, k) => { a[k] = v; return a; }, new Int32Array(MLDSAN)));
}

function dcbd(eta, b) {
  const p = new Int32Array(MLDSAN);
  for (let i = 0; i < MLDSAN; i++) {
    let a2 = 0, b2 = 0;
    for (let j = 0; j < eta; j++) { const idx = 2 * eta * i + j; a2 += (b[idx >> 3] >> (idx & 7)) & 1; }
    for (let j = 0; j < eta; j++) { const idx = 2 * eta * i + eta + j; b2 += (b[idx >> 3] >> (idx & 7)) & 1; }
    p[i] = dmod(a2 - b2);
  } return p;
}

function dinf(p) {
  let m = 0; for (const v of p) { const a = Math.abs(v > MLDSAQ / 2 ? v - MLDSAQ : v); if (a > m) m = a; }
  return m;
}
function dhighlow(r) {
  const m = dmod(r); const r1 = Math.round(m / MLDSA_GAMMA2 / 2);
  const r0 = dmod(m - r1 * MLDSA_GAMMA2 * 2); return [r1, r0];
}

export function mldsaKG() {
  const seed = rnd(32); const _h512 = SHA3_512(cat(seed, new Uint8Array([MLDSAK, MLDSAL])));
  const rho = _h512.slice(0, 32), rhop = _h512.slice(32, 64);
  const A = Array.from({ length: MLDSAK }, (_, i) => Array.from({ length: MLDSAL }, (_, j) => dexpand(rho, i, j)));
  const s1 = Array.from({ length: MLDSAL }, (_, i) => dntt(dcbd(MLDSA_ETA, SHAKE256(cat(rhop, new Uint8Array([i])), 64 * MLDSA_ETA))));
  const s2 = Array.from({ length: MLDSAK }, (_, i) => dntt(dcbd(MLDSA_ETA, SHAKE256(cat(rhop, new Uint8Array([MLDSAL + i])), 64 * MLDSA_ETA))));
  const t = Array.from({ length: MLDSAK }, (_, i) => { let r = new Int32Array(MLDSAN); for (let j = 0; j < MLDSAL; j++) r = dadd(r, dmul(A[i][j], s1[j])); return dadd(dintt(r), dintt(s2[i])); });
  const pk = new Uint8Array(32 + MLDSAK * 320); pk.set(rho);
  for (let i = 0; i < MLDSAK; i++) pk.set(denc10(t[i]), 32 + i * 320);
  const skBytes = new Uint8Array(32 + 32 + 32 + MLDSAL * 128 + MLDSAK * 128);
  skBytes.set(rho); skBytes.set(rhop, 32); skBytes.set(SHA3_256(pk), 64);
  for (let i = 0; i < MLDSAL; i++) { const e = new Uint8Array(128); const ss = dintt(s1[i]); for (let j = 0; j < MLDSAN; j++) { const v = ss[j] < 0 ? ss[j] + MLDSAQ : ss[j]; e[j >> 1] |= (v & 0xF) << ((j & 1) * 4); } skBytes.set(e, 96 + i * 128); }
  for (let i = 0; i < MLDSAK; i++) { const e = new Uint8Array(128); const ss = dintt(s2[i]); for (let j = 0; j < MLDSAN; j++) { const v = ss[j] < 0 ? ss[j] + MLDSAQ : ss[j]; e[j >> 1] |= (v & 0xF) << ((j & 1) * 4); } skBytes.set(e, 96 + MLDSAL * 128 + i * 128); }
  return { pk: hex(pk), sk: hex(skBytes) };
}

export async function mldsaSign(skH, msg) {
  const sk = fhex(skH); const rho = sk.slice(0, 32); const rhop = sk.slice(32, 64);
  const A = Array.from({ length: MLDSAK }, (_, i) => Array.from({ length: MLDSAL }, (_, j) => dexpand(rho, i, j)));
  const s1 = Array.from({ length: MLDSAL }, (_, i) => { const e = sk.slice(96 + i * 128, 96 + (i + 1) * 128); const p = new Int32Array(MLDSAN); for (let j = 0; j < MLDSAN; j++) p[j] = dmod(((e[j >> 1] >> ((j & 1) * 4)) & 0xF) - (MLDSA_ETA > 2 ? 4 : 2)); return dntt(p); });
  const s2 = Array.from({ length: MLDSAK }, (_, i) => { const e = sk.slice(96 + MLDSAL * 128 + i * 128, 96 + MLDSAL * 128 + (i + 1) * 128); const p = new Int32Array(MLDSAN); for (let j = 0; j < MLDSAN; j++) p[j] = dmod(((e[j >> 1] >> ((j & 1) * 4)) & 0xF) - (MLDSA_ETA > 2 ? 4 : 2)); return dntt(p); });
  const mu = SHAKE256(cat(sk.slice(64, 96), typeof msg === 'string' ? te(msg) : msg), 64);
  let kappa = 0;
  while (kappa < 256) {
    const y = Array.from({ length: MLDSAL }, (_, i) => { const r = SHAKE256(cat(rhop, new Uint8Array([kappa >> 8, kappa & 0xFF, i])), MLDSAN * 4); const p = new Int32Array(MLDSAN); for (let j = 0; j < MLDSAN; j++) { const v = (r[j * 4] | (r[j * 4 + 1] << 8) | (r[j * 4 + 2] << 16)) % (2 * MLDSA_GAMMA1); p[j] = dmod(v - MLDSA_GAMMA1); } return dntt(p); });
    const Ay = Array.from({ length: MLDSAK }, (_, i) => { let r = new Int32Array(MLDSAN); for (let j = 0; j < MLDSAL; j++) r = dadd(r, dmul(A[i][j], y[j])); return dintt(r); });
    const w1 = Ay.map(p => p.map(v => dhighlow(v)[0]));
    const w1b = new Uint8Array(MLDSAK * MLDSAN / 2);
    for (let i = 0; i < MLDSAK; i++) for (let j = 0; j < MLDSAN; j++) w1b[(i * MLDSAN + j) >> 1] |= (w1[i][j] & 0xF) << ((j & 1) * 4);
    const cHash = SHAKE256(cat(mu, w1b), 32);
    const cPoly = new Int32Array(MLDSAN); let pos = 0;
    for (let i = MLDSAN - 1; i >= MLDSAN - MLDSA_TAU; i--) { let j = cHash[pos++] % (i + 1); cPoly[i] = cPoly[j]; cPoly[j] = 1; }
    const cNTT = dntt(cPoly);
    const z = y.map((yi, i) => dintt(dadd(yi, dmul(cNTT, s1[i]))));
    const r0 = Ay.map((Ayi, i) => { const cs2 = dintt(dmul(cNTT, s2[i])); return dsub(Ayi, cs2).map(v => dhighlow(v)[1]); });
    if (z.some(zi => dinf(zi) >= MLDSA_GAMMA1 - MLDSA_BETA) || r0.some(ri => dinf(ri) >= MLDSA_GAMMA2 - MLDSA_BETA)) { kappa++; continue; }
    const sig = new Uint8Array(32 + MLDSAL * MLDSAN * 4 / 8 + MLDSAK);
    sig.set(cHash);
    let off = 32; for (const zi of z) { for (let j = 0; j < MLDSAN; j += 2) { const v1 = zi[j] + MLDSA_GAMMA1; const v2 = zi[j + 1] + MLDSA_GAMMA1; sig[off++] = (v1 >> 9) & 0xFF; sig[off++] = (v1 >> 1) & 0xFF; sig[off++] = ((v1 & 1) << 7) | ((v2 >> 11) & 0x7F); sig[off++] = (v2 >> 3) & 0xFF; sig[off++] = (v2 & 7) << 5; } }
    return hex(sig);
  }
  throw new Error('ML-DSA sign failed');
}

export async function mldsaVerify(pkH, msg, sigH) {
  try {
    const pk = fhex(pkH); const sig = fhex(sigH); const rho = pk.slice(0, 32);
    const A = Array.from({ length: MLDSAK }, (_, i) => Array.from({ length: MLDSAL }, (_, j) => dexpand(rho, i, j)));
    const t = Array.from({ length: MLDSAK }, (_, i) => dntt(ddec10(pk.slice(32 + i * 320, 32 + (i + 1) * 320))));
    const cHash = sig.slice(0, 32);
    const cPoly = new Int32Array(MLDSAN); let pos = 0;
    for (let i = MLDSAN - 1; i >= MLDSAN - MLDSA_TAU; i--) { let j = cHash[pos++] % (i + 1); cPoly[i] = cPoly[j]; cPoly[j] = 1; }
    const cNTT = dntt(cPoly);
    const z = Array.from({ length: MLDSAL }, (_, i) => { const p = new Int32Array(MLDSAN); let off = 32 + i * MLDSAN * 4 / 8; for (let j = 0; j < MLDSAN; j += 2) { const b0 = sig[off], b1 = sig[off + 1], b2 = sig[off + 2], b3 = sig[off + 3], b4 = sig[off + 4]; p[j] = (b0 << 9) | (b1 << 1) | (b2 >> 7) - MLDSA_GAMMA1; p[j + 1] = ((b2 & 0x7F) << 11) | (b3 << 3) | (b4 >> 5) - MLDSA_GAMMA1; off += 5; } return dntt(p); });
    if (z.some(zi => dinf(zi) >= MLDSA_GAMMA1 - MLDSA_BETA)) return false;
    const w = Array.from({ length: MLDSAK }, (_, i) => { let r = new Int32Array(MLDSAN); for (let j = 0; j < MLDSAL; j++) r = dadd(r, dmul(A[i][j], z[j])); return dintt(dsub(r, dmul(cNTT, t[i]))); });
    const mu = SHAKE256(cat(SHA3_256(pk), typeof msg === 'string' ? te(msg) : msg), 64);
    const w1b = new Uint8Array(MLDSAK * MLDSAN / 2);
    for (let i = 0; i < MLDSAK; i++) { const wi = w[i].map(v => dhighlow(v)[0]); for (let j = 0; j < MLDSAN; j++) w1b[(i * MLDSAN + j) >> 1] |= (wi[j] & 0xF) << ((j & 1) * 4); }
    const cCheck = SHAKE256(cat(mu, w1b), 32);
    return cCheck.every((v, i) => v === cHash[i]);
  } catch { return false; }
}
