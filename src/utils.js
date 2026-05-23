import { SHA3_256 } from './crypto/sha3.js';
export const G = typeof window !== 'undefined' ? window : {};

// ── Utility functions ──

export const te = s => new TextEncoder().encode(s);
export const td = b => new TextDecoder().decode(b);
export const hex = b => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
export const fhex = s => new Uint8Array((s.length % 2 ? '0' + s : s).match(/../g).map(x => parseInt(x, 16)));
export const rnd = n => crypto.getRandomValues(new Uint8Array(n));
export const cat = (...a) => {
  const r = new Uint8Array(a.reduce((s, x) => s + x.length, 0));
  let o = 0;
  a.forEach(x => { r.set(x, o); o += x.length; });
  return r;
};

/** Returns a shortened version of a URL (domain and TLD) */
export function rn(u) {
  try {
    return u.split('/')[2].split('.').slice(-2).join('.');
  } catch {
    return u;
  }
}

/** Formats a timestamp into HH:MM */
export function ft(ts) {
  const d = new Date(ts);
  return d.getHours().toString().padStart(2, '0') + ':' + d.getMinutes().toString().padStart(2, '0');
}

/** Resizes a textarea based on its content */
export function rsz(el) {
  el.style.height = 'auto';
  el.style.height = (el.scrollHeight) + 'px';
}

/** Computes a SHA-256 hash */
export async function wsha256(d) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', typeof d === 'string' ? te(d) : d));
}

/** Computes a hex fingerprint for a given peer ID */
export async function computeFP(peerPub) {
  const G = window;
  const peer = G._PEERS[peerPub]; if (!peer?.kyberPk) return null;
  // Canonical order: always myNostr < peerNostr lexicographically
  // so both sides get same result regardless of who computes
  const [a, b] = G._NK.pub < peerPub
    ? [G._NK.pub + G._KKkeys.pk, peerPub + peer.kyberPk]
    : [peerPub + peer.kyberPk, G._NK.pub + G._KKkeys.pk];
  const raw = te(a + '|' + b);
  const hash = SHA3_256(raw); // 32 bytes
  return hash;
}

/** Converts a fingerprint buffer to emojis (12 emojis) */
export function fpToEmojis(hash) {
  const FP_EMOJIS = ['🔥','🌊','⚡','🌙','🦋','🐉','🌺','🎯','🔮','🌈','🦅','🐬','🌸','⭐','🎪','🦊','🌴','🎭','🔱','🦁','🌋','🐙','🎨','🏔','🦄','🌊','🎸','🦜','🌙','🔮','🎯','🦋','⚡','🌺','🐉','🔥','🎪','🦅','🐬','🌸','🎭','🔱','🦁','🌋','🐙','🎨','🏔','🦄','🎸','🦜','🍄','🦩','🎲','🌿','🔭','🦚','🎠','🌠','🦋','🔑','🌊','⚗️','🦈','🎡'];
  return Array.from({ length: 12 }, (_, i) => FP_EMOJIS[hash[i] % FP_EMOJIS.length]);
}

/** Converts a fingerprint buffer to hex */
export function fpToHex(hash) {
  const h = hex(hash);
  return h.match(/.{1,8}/g).join(' ');
}

/** Escapes HTML characters and replaces newlines with <br> */
export function esc(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\n/g, '<br>');
}
