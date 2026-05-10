/**
 * settings.js — Settings panel, peer management, fingerprint verification,
 *               Key Transparency audit log, Emergency Wipe, Disappearing Messages
 *
 * Exports: openSettings, closeSettings, addPeer, delPeer, openFP, closeFP,
 *          verifyFP, openKT, closeKT, toggleDisappearing, setDisappearing,
 *          emergencyWipe, exportKeys, importKeys
 */

'use strict';

import { genNKP }          from '../crypto/secp256k1.js';
import { kemKG }           from '../crypto/mlkem.js';
import { SHA3_256 }        from '../crypto/sha3.js';
import { mldsaSign }       from '../crypto/mldsa.js';
import { saveEncryptedSKs, changePin, bioSupported, bioEnroll } from '../storage/pin.js';
import { renderContacts, renderPeers, ktRender } from './render.js';
import { idbDelete }       from '../storage/crdt.js';
import { hex, te }         from '../utils.js';

// ── Helpers ──

const COLS = ['#e8ff00', '#00aaff', '#00ff88', '#ff5588', '#ff9900', '#cc44ff'];
const randCol = () => COLS[Math.floor(Math.random() * COLS.length)];

function kh(pk) {
  try { return hex(SHA3_256(te(pk || ''))).slice(0, 32); } catch { return '?'; }
}

// ── Settings panel ──

export function openSettings() {
  buildSettings();
  document.getElementById('settings').classList.add('show');
}

export function closeSettings() {
  document.getElementById('settings').classList.remove('show');
}

function buildSettings() {
  const NK     = window._NK;
  const KKkeys = window._KKkeys;

  // My Keys card — uses the actual IDs in index.html
  const nostrEl  = document.getElementById('myNostr');
  const kyberEl  = document.getElementById('myKyber');
  const topKey   = document.getElementById('topKey');
  if (nostrEl) nostrEl.textContent = NK?.pub  ? NK.pub  : '—';
  if (kyberEl) kyberEl.textContent = KKkeys?.pk ? KKkeys.pk.slice(0, 64) + '...' + KKkeys.pk.slice(-16) : '—';
  if (topKey)  topKey.textContent  = NK?.pub  ? NK.pub.slice(0, 10) + '...' : 'key...';

  // Disappearing messages
  const curDis = parseInt(localStorage.getItem('rl6_disappear') || '0');
  const disEl = document.getElementById('disSelect');
  if (disEl) disEl.value = curDis.toString();

  renderPeers();
}

// ── Add peer ──
// Reads from peerInp textarea (JSON: {nostr, kyber}) — matches the HTML in index.html

export function addPeer() {
  const inp = document.getElementById('peerInp');
  let b;
  try { b = JSON.parse(inp.value.trim()); }
  catch { alert('Invalid JSON format.\nExample: {"nostr":"ab12...","kyber":"04ab..."}'); return; }
  const nk = (b.nostr || b.nostrPub || '').toLowerCase().replace(/[^a-f0-9]/g, '');
  if (!nk || nk.length !== 64) { alert('Nostr key must be 64 hex characters.'); return; }
  if (!b.kyber && !b.kyberPk) { alert('ML-KEM key missing (kyber field).'); return; }
  const kpub = b.kyber || b.kyberPk;
  if (kpub.length < 100) { alert('ML-KEM key is too short.'); return; }
  if (nk === window._NK?.pub) { alert('This is your own key!'); return; }
  const peers = window._PEERS;
  const COLS_LOCAL = ['#e8ff00','#00aaff','#00ff88','#ff5588','#ff9900','#cc44ff'];
  if (!peers[nk]) {
    peers[nk] = { name: nk.slice(0, 10), kyberPk: kpub, color: COLS_LOCAL[Object.keys(peers).length % COLS_LOCAL.length], lastRead: 0 };
    ktRecord(nk, null, kpub, 'key_first');
  } else {
    if (peers[nk].kyberPk && peers[nk].kyberPk !== kpub) {
      const warn = `⚠ Key change detected for ${peers[nk].name}!\n\nOld: ${peers[nk].kyberPk.slice(0, 24)}\nNew: ${kpub.slice(0, 24)}\n\nAccept new key?`;
      if (!confirm(warn)) return;
      ktRecord(nk, peers[nk].kyberPk, kpub, 'key_changed');
    }
    peers[nk].kyberPk = kpub;
  }
  savePeers();
  inp.value = '';
  renderPeers(); renderContacts();
}

export function delPeer(npub) {
  if (!confirm('Delete this peer and their message history?')) return;
  const chat = window._C?.chat(window._NK?.pub, npub) || [];
  chat.forEach(m => idbDelete(m.id));
  window._C.ops = window._C.ops.filter(o => !(o.from === npub || o.to === npub));
  window._C._save();
  delete window._PEERS[npub]; savePeers();
  renderPeers(); renderContacts();
  if (window._AP === npub) window._goContacts?.();
}

function savePeers() {
  localStorage.setItem('rl5_peers', JSON.stringify(window._PEERS));
}

// ── Fingerprint verification ──
// openFP, closeFP, confirmVerify are implemented in app.js (need SHA3_256 + emoji logic)
// These exports are kept for compatibility but delegate to window.openFP / window.closeFP

export function openFP(npub) {
  if (window.openFP) window.openFP(npub);
}

export function closeFP() {
  if (window.closeFP) window.closeFP();
}

export function verifyFP() {
  if (window.confirmVerify) window.confirmVerify();
}

// ── Key Transparency log ──

export function ktRecord(peer, oldPk, newPk, event) {
  // Support both (peer, newPk, event) and (peer, oldPk, newPk, event) signatures
  if (typeof newPk === 'string' && ['key_first','key_changed','key_ok'].includes(event)) {
    // called as (peer, oldPk, newPk, event)
  } else if (['key_first','key_changed','key_ok'].includes(newPk)) {
    // called as (peer, newPk, event) — oldPk is actually newPk
    event = newPk; newPk = oldPk; oldPk = null;
  }
  if (!window._ktLog) window._ktLog = [];
  const hash = newPk ? kh(newPk).slice(0, 16) : '—';
  window._ktLog.push({ peer, newHash: hash, event, ts: Date.now() });
  window._ktLog = window._ktLog.slice(-200);
  try { localStorage.setItem('rl6_kt', JSON.stringify(window._ktLog)); } catch {}
  ktRender();
}

export function openKT() {
  ktRender();
  document.getElementById('ktModal').classList.add('show');
}

export function closeKT() { document.getElementById('ktModal').classList.remove('show'); }

// ── Disappearing messages ──

export function setDisappearing(val) {
  const ms = parseInt(val);
  if (ms > 0) localStorage.setItem('rl6_disappear', String(ms));
  else localStorage.removeItem('rl6_disappear');
  window._disappearMs = ms > 0 ? ms : 0;
}

export function runDisappearing() {
  const ms = window._disappearMs || 0; if (!ms) return;
  const now = Date.now();
  const C   = window._C;
  const before = C.ops.length;
  C.ops = C.ops.filter(o => (now - o.ts) < ms);
  if (C.ops.length !== before) { C._save(); renderContacts(); if (window._AP) window._renderMsgs?.(); }
}

// ── Emergency Wipe ──

export function emergencyWipe() {
  // Wipe all keys, messages, DR state, peers, settings
  localStorage.clear();
  sessionStorage.clear();
  try {
    indexedDB.deleteDatabase('relay_media');
  } catch {}
  // Replace with blank page — do not reload (browser cache)
  document.documentElement.innerHTML = `
    <html><head><title>RELAY</title></head><body style="background:#0a0a0a;color:#e8002a;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
    <div style="text-align:center"><div style="font-size:48px">⊘</div><div style="margin-top:16px;font-size:18px">RELAY — Emergency Wipe Complete</div><div style="margin-top:8px;color:#666;font-size:12px">All keys and data destroyed.</div></div></body></html>`;
}

// ── Key export / import ──

export function exportKeys() {
  const NK = window._NK, KKkeys = window._KKkeys;
  if (!NK || !KKkeys) { alert('No keys loaded.'); return; }
  const bundle = {
    v: 1,
    nostr: { pub: NK.pub, priv: NK.priv },
    kyber: { pk: KKkeys.pk, sk: KKkeys.sk },
    peers: window._PEERS,
  };
  const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = 'relay-keys-' + Date.now() + '.json';
  a.click();
}

export async function importKeys(file) {
  try {
    const text   = await file.text();
    const bundle = JSON.parse(text);
    if (bundle.v !== 1 || !bundle.nostr?.priv || !bundle.kyber?.sk) throw new Error('Invalid key file');
    if (!confirm('Import keys? Current keys and messages will be replaced.')) return;
    window._NK     = bundle.nostr;
    window._KKkeys = bundle.kyber;
    if (bundle.peers) { window._PEERS = bundle.peers; savePeers(); }
    const pin = prompt('Set a new PIN (6 digits) to protect imported keys:');
    if (pin?.length === 6 && /^\d{6}$/.test(pin)) {
      await saveEncryptedSKs(pin, bundle.nostr.priv, bundle.kyber.sk);
    }
    alert('Keys imported ✓ Reloading...');
    location.reload();
  } catch (e) { alert('Import failed: ' + e.message); }
}

// ── My fingerprint for sharing ──

export function copyShareBundle() {
  const NK = window._NK, KKkeys = window._KKkeys;
  if (!NK || !KKkeys) return;
  const bundle = JSON.stringify({ nostrPub: NK.pub, kyberPk: KKkeys.pk, v: 1 });
  navigator.clipboard.writeText(bundle).then(() => alert('Contact bundle copied ✓')).catch(() => alert(bundle));
}
