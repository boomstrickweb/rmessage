import { hex, rnd, te, td } from '../utils.js';
import { kemE, aesEnc } from '../crypto/mlkem.js';
import { genNKP, buildEv } from '../crypto/secp256k1.js';
import { WS, CONN } from './nostr.js';

const G = window;
const PAD_BLOCK = 512;
const PAD_MIN_MS = 5000;
const PAD_MAX_MS = 14000;
let _padTimer = null;

export function padPlain(str) {
  const b = te(str);
  const target = Math.ceil((b.length + 2) / PAD_BLOCK) * PAD_BLOCK;
  const padLen = target - b.length - 2;
  const out = new Uint8Array(2 + b.length + padLen);
  new DataView(out.buffer).setUint16(0, b.length);
  out.set(b, 2); out.set(rnd(padLen), 2 + b.length);
  return out;
}

export function unpadPlain(bytes) {
  const realLen = new DataView(bytes.buffer, bytes.byteOffset, 2).getUint16(0);
  return td(bytes.slice(2, 2 + realLen));
}

export async function pqEncPadded(pkH, str) {
  const padded = padPlain(typeof str === 'string' ? str : JSON.stringify(str));
  const { ct, K } = kemE(pkH);
  const { iv, ct: a } = await aesEnc(K, padded);
  return JSON.stringify({ v: 4, kem: ct, iv, ct: a });
}

export async function sendDummySealed(toPub) {
  const peer = G._PEERS[toPub]; if (!peer?.kyberPk) return;
  const dummy = { id: hex(rnd(16)), type: '__pad__', from: G._NK.pub, to: toPub, lam: 0, vc: {}, payload: {}, ts: Date.now() };
  try {
    const enc = await pqEncPadded(peer.kyberPk, JSON.stringify(dummy));
    const ephNK = genNKP();
    const ev = await buildEv(4, enc, [['p', toPub]], ephNK.priv, ephNK.pub);
    Object.values(WS).forEach(ws => { if (ws.readyState === 1) ws.send(JSON.stringify(['EVENT', ev])); });
  } catch { }
}

export function startPadding() {
  if (_padTimer) return;
  const fire = async () => {
    const peers = Object.keys(G._PEERS).filter(p => G._PEERS[p]?.kyberPk);
    if (peers.length && CONN.size > 0) {
      const count = 1 + Math.floor(Math.random() * Math.min(2, peers.length));
      const picked = peers.sort(() => Math.random() - .5).slice(0, count);
      for (const p of picked) await sendDummySealed(p);
    }
    _padTimer = setTimeout(fire, PAD_MIN_MS + Math.random() * (PAD_MAX_MS - PAD_MIN_MS));
  };
  _padTimer = setTimeout(fire, PAD_MIN_MS + Math.random() * (PAD_MAX_MS - PAD_MIN_MS));
}

export function stopPadding() { clearTimeout(_padTimer); _padTimer = null; }
