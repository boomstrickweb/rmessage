/**
 * crdt.js — CRDT message store + IndexedDB media storage
 *
 * CRDT:
 *   Conflict-free replicated data type for message ordering.
 *   Uses Lamport timestamps + vector clocks.
 *   Raw media bytes (_bytes) are stored in IndexedDB separately
 *   to keep localStorage entries small.
 *
 * IndexedDB:
 *   Stores raw media bytes keyed by op ID.
 *   Survives page refresh; cleared on Emergency Wipe.
 *
 * Exports: CRDT, idbSave, idbLoad, idbDelete
 */

'use strict';

import { hex, rnd } from '../utils.js';

// ── IndexedDB ──

let _idb = null;

function getIDB() {
  if (_idb) return Promise.resolve(_idb);
  return new Promise((res, rej) => {
    const req = indexedDB.open('relay_media', 1);
    req.onupgradeneeded = e => { e.target.result.createObjectStore('media', { keyPath: 'id' }); };
    req.onsuccess = e => { _idb = e.target.result; res(_idb); };
    req.onerror   = () => rej(req.error);
  });
}

export async function idbSave(id, bytes, mime) {
  try { const db = await getIDB(); const tx = db.transaction('media', 'readwrite'); tx.objectStore('media').put({ id, bytes, mime }); } catch {}
}

export async function idbLoad(id) {
  try {
    const db = await getIDB();
    return new Promise(res => {
      const req = db.transaction('media', 'readonly').objectStore('media').get(id);
      req.onsuccess = () => res(req.result || null);
      req.onerror   = () => res(null);
    });
  } catch { return null; }
}

export async function idbDelete(id) {
  try { const db = await getIDB(); const tx = db.transaction('media', 'readwrite'); tx.objectStore('media').delete(id); } catch {}
}

// ── CRDT ──

export class CRDT {
  constructor(id) { this.id = id; this.lam = 0; this.vc = { [id]: 0 }; this.ops = []; this.mc = 0; }

  add(type, payload, to) {
    this.lam++; this.vc[this.id] = this.lam;
    const op = { id: hex(rnd(16)), from: this.id, to, lam: this.lam, vc: { ...this.vc }, type, payload, ts: Date.now() };
    this.ops.push(op); this._save(); return op;
  }

  merge(op) {
    if (this.ops.find(o => o.id === op.id)) return false;
    this.lam = Math.max(this.lam, op.lam) + 1;
    Object.keys(op.vc || {}).forEach(k => this.vc[k] = Math.max(this.vc[k] || 0, op.vc[k] || 0));
    this.ops.push(op);
    this.ops.sort((a, b) => a.lam !== b.lam ? a.lam - b.lam : a.from.localeCompare(b.from));
    this.mc++; this._save(); return true;
  }

  chat(a, b) { return this.ops.filter(o => (o.from === a && o.to === b) || (o.from === b && o.to === a)); }

  _save() {
    try {
      const ops = this.ops.map(o => {
        const s = { ...o, payload: { ...o.payload } };
        // Store raw bytes in IDB; remove from CRDT to keep localStorage lean
        if (s.payload._bytes) { idbSave(o.id, s.payload._bytes, s.payload.mimeType); delete s.payload._bytes; }
        delete s.payload._prog;
        return s;
      });
      localStorage.setItem('rl5_crdt', JSON.stringify({ lam: String(this.lam), vc: this.vc, ops, mc: this.mc }));
    } catch {}
  }

  static load(id) {
    const c = new CRDT(id);
    try {
      const d = JSON.parse(localStorage.getItem('rl5_crdt'));
      if (d) { c.lam = Number(d.lam) || 0; c.vc = d.vc || { [id]: 0 }; c.ops = d.ops || []; c.mc = d.mc || 0; }
    } catch {}
    return c;
  }
}
