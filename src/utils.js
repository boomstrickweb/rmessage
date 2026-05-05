/**
 * utils.js — Shared byte/encoding utilities
 *
 * Exports: rnd, hex, fhex, te, td, cat
 */

'use strict';

export const rnd  = n => crypto.getRandomValues(new Uint8Array(n));
export const hex  = b => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
export const fhex = s => new Uint8Array((s.length % 2 ? '0' + s : s).match(/../g).map(x => parseInt(x, 16)));
export const te   = s => new TextEncoder().encode(s);
export const td   = b => new TextDecoder().decode(b);
export const cat  = (...a) => {
  const r = new Uint8Array(a.reduce((s, x) => s + x.length, 0));
  let o = 0; a.forEach(x => { r.set(x, o); o += x.length; });
  return r;
};
