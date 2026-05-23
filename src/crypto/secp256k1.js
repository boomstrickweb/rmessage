import { _bi, _bb, _sm, _spw, _SP, _SN, _SG } from './sha3.js'; // Assuming shared BigInt/Curve constants are there or defined locally
import { rnd, hex, cat, fhex, wsha256 } from '../utils.js';

// We'll define the curve here to avoid import issues if sha3.js is not yet populated
const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const sm = (a, m = P) => ((a % m) + m) % m;
const spw = (b, e, m = P) => {
  let r = 1n; b = sm(b, m);
  while (e > 0n) { if (e & 1n) r = sm(r * b, m); e >>= 1n; b = sm(b * b, m); }
  return r;
};

class SPt {
  constructor(x, y) { this.x = x; this.y = y; }
  static Z = new SPt(0n, 0n);
  isZ() { return this.x === 0n && this.y === 0n; }
  add(o) {
    if (this.isZ()) return o; if (o.isZ()) return this;
    if (this.x === o.x) {
      if (this.y !== o.y) return SPt.Z;
      const l = sm(3n * this.x * this.x * spw(2n * this.y, P - 2n));
      const x = sm(l * l - 2n * this.x);
      return new SPt(x, sm(l * (this.x - x) - this.y));
    }
    const l = sm((o.y - this.y) * spw(o.x - this.x, P - 2n));
    const x = sm(l * l - this.x - o.x);
    return new SPt(x, sm(l * (this.x - x) - this.y));
  }
  mul(n) {
    let r = SPt.Z, p = new SPt(this.x, this.y); n = sm(n, N);
    while (n > 0n) { if (n & 1n) r = r.add(p); p = p.add(p); n >>= 1n; }
    return r;
  }
}

const G_PT = new SPt(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n);

const bi = b => BigInt('0x' + (hex(b) || '0'));
const bb = (n, l = 32) => fhex(n.toString(16).padStart(l * 2, '0'));

export function genNKP() {
  let p; do { p = bi(rnd(32)); } while (p === 0n || p >= N);
  const priv = p.toString(16).padStart(64, '0');
  return { priv, pub: G_PT.mul(p).x.toString(16).padStart(64, '0') };
}

export async function schnorrSign(h, priv) {
  const p = sm(BigInt('0x' + priv), N);
  const P_PT = G_PT.mul(p);
  const pp = P_PT.y % 2n === 0n ? p : N - p;
  const Px = bb(P_PT.x);
  const aux = rnd(32);
  const t0 = await wsha256('BIP0340/aux');
  const ta = await wsha256(cat(t0, t0, aux));
  const tB = bb(pp ^ bi(ta));
  const t1 = await wsha256('BIP0340/nonce');
  const kh = await wsha256(cat(t1, t1, tB, Px, h));
  let k = sm(bi(kh), N); if (k === 0n) throw new Error('k=0');
  const R = G_PT.mul(k);
  if (R.y % 2n !== 0n) k = N - k;
  const Rx = bb(R.x);
  const t2 = await wsha256('BIP0340/challenge');
  const eH = await wsha256(cat(t2, t2, Rx, Px, h));
  return hex(cat(Rx, bb(sm(k + sm(bi(eH), N) * pp, N))));
}

export async function buildEv(kind, content, tags, priv, pub) {
  const ev = { pubkey: pub, created_at: Math.floor(Date.now() / 1000), kind, tags, content };
  const id = await wsha256(JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]));
  ev.id = hex(id);
  ev.sig = await schnorrSign(id, priv);
  return ev;
}
