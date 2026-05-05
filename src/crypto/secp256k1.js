/**
 * secp256k1.js — secp256k1 elliptic curve + Schnorr BIP340
 *
 * Used for Nostr event signing (protocol requirement).
 * All message authentication uses ML-DSA (post-quantum) instead.
 *
 * Exports: genNKP, schnorrSign, buildEv
 */

'use strict';

import { hex, fhex, rnd, te } from '../utils.js';

const _SP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const _SN = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const _sm = (a, m = _SP) => ((a % m) + m) % m;
const _spw = (b, e, m = _SP) => {
  let r = 1n; b = _sm(b, m);
  while (e > 0n) { if (e & 1n) r = _sm(r * b, m); e >>= 1n; b = _sm(b * b, m); }
  return r;
};

class _SPt {
  constructor(x, y) { this.x = x; this.y = y; }
  static Z = new _SPt(0n, 0n);
  isZ() { return this.x === 0n && this.y === 0n; }
  add(o) {
    if (this.isZ()) return o;
    if (o.isZ()) return this;
    if (this.x === o.x) {
      if (this.y !== o.y) return _SPt.Z;
      const l = _sm(3n * this.x * this.x * _spw(2n * this.y, _SP - 2n));
      const x = _sm(l * l - 2n * this.x);
      return new _SPt(x, _sm(l * (this.x - x) - this.y));
    }
    const l = _sm((o.y - this.y) * _spw(o.x - this.x, _SP - 2n));
    const x = _sm(l * l - this.x - o.x);
    return new _SPt(x, _sm(l * (this.x - x) - this.y));
  }
  mul(n) {
    let r = _SPt.Z, p = new _SPt(this.x, this.y);
    n = _sm(n, _SN);
    while (n > 0n) { if (n & 1n) r = r.add(p); p = p.add(p); n >>= 1n; }
    return r;
  }
}

const _SG = new _SPt(
  0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n,
  0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n
);

const _bi  = b => BigInt('0x' + (hex(b) || '0'));
const _bb  = (n, l = 32) => fhex(n.toString(16).padStart(l * 2, '0'));
const cat  = (...a) => { const r = new Uint8Array(a.reduce((s, x) => s + x.length, 0)); let o = 0; a.forEach(x => { r.set(x, o); o += x.length; }); return r; };

async function wsha256(d) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', typeof d === 'string' ? te(d) : d));
}

/**
 * Generate a new Nostr keypair { priv, pub }.
 */
export function genNKP() {
  let p;
  do { p = _bi(rnd(32)); } while (p === 0n || p >= _SN);
  const priv = p.toString(16).padStart(64, '0');
  return { priv, pub: _SG.mul(p).x.toString(16).padStart(64, '0') };
}

/**
 * Sign a 32-byte hash with Schnorr BIP340.
 */
export async function schnorrSign(h, priv) {
  const p = _sm(BigInt('0x' + priv), _SN);
  const P = _SG.mul(p);
  const pp = P.y % 2n === 0n ? p : _SN - p;
  const Px = _bb(P.x);
  const aux = rnd(32);
  const t0 = await wsha256('BIP0340/aux');
  const ta = await wsha256(cat(t0, t0, aux));
  const tB = _bb(pp ^ _bi(ta));
  const t1 = await wsha256('BIP0340/nonce');
  const kh = await wsha256(cat(t1, t1, tB, Px, h));
  let k = _sm(_bi(kh), _SN);
  if (k === 0n) throw new Error('k=0');
  const R = _SG.mul(k);
  if (R.y % 2n !== 0n) k = _SN - k;
  const Rx = _bb(R.x);
  const t2 = await wsha256('BIP0340/challenge');
  const eH = await wsha256(cat(t2, t2, Rx, Px, h));
  return hex(cat(Rx, _bb(_sm(k + _sm(_bi(eH), _SN) * pp, _SN))));
}

/**
 * Build and sign a Nostr event.
 */
export async function buildEv(kind, content, tags, priv, pub) {
  const ev = { pubkey: pub, created_at: Math.floor(Date.now() / 1000), kind, tags, content };
  const id = await wsha256(JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]));
  ev.id  = hex(id);
  ev.sig = await schnorrSign(id, priv);
  return ev;
}
