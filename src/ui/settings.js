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

  // Identity display
  document.getElementById('myNpub').textContent  = NK?.pub   ? NK.pub.slice(0, 32)  + '...' : '—';
  document.getElementById('myKpub').textContent  = KKkeys?.pk ? KKkeys.pk.slice(0, 32) + '...' : '—';
  document.getElementById('myFP').textContent    = NK?.pub   ? kh(NK.pub + (KKkeys?.pk || '')).match(/.{4}/g).join(' ') : '—';

  // Stats
  const total = window._C?.ops?.length || 0;
  const peers = Object.keys(window._PEERS || {}).length;
  document.getElementById('statMsgs').textContent  = total;
  document.getElementById('statPeers').textContent = peers;
  document.getElementById('statVer').textContent   = 'ML-KEM-768 · ML-DSA-44 · DR';

  // Disappearing messages
  const curDis = parseInt(localStorage.getItem('rl6_disappear') || '0');
  document.getElementById('disSelect').value = curDis.toString();

  renderPeers();
}

// ── Add peer ──

export function addPeer() {
  const nb = document.getElementById('addNpub');
  const cb = document.getElementById('addKpub');
  const nn = document.getElementById('addName');
  const npub = nb.value.trim(), kpub = cb.value.trim(), name = nn.value.trim();
  if (!npub || !kpub || !name) { alert('Fill in all fields.'); return; }
  if (!/^[0-9a-f]{64}$/i.test(npub)) { alert('Nostr pub must be 64 hex chars.'); return; }
  if (!/^[0-9a-f]{768,}$/i.test(kpub)) { alert('ML-KEM pub key is too short.'); return; }
  const peers = window._PEERS;
  if (!peers[npub]) {
    peers[npub] = { name, kyberPk: kpub, color: randCol(), lastRead: 0 };
    ktRecord(npub, kpub, 'key_first');
  } else {
    if (peers[npub].kyberPk && peers[npub].kyberPk !== kpub) {
      const warn = `⚠ Key change detected for ${peers[npub].name}!\n\nOld: ${peers[npub].kyberPk.slice(0, 24)}\nNew: ${kpub.slice(0, 24)}\n\nAccept new key?`;
      if (!confirm(warn)) return;
      ktRecord(npub, kpub, 'key_changed');
    }
    peers[npub].kyberPk = kpub;
    if (name) peers[npub].name = name;
  }
  savePeers();
  nb.value = ''; cb.value = ''; nn.value = '';
  renderPeers(); renderContacts();
  alert(`Peer "${name}" added ✓`);
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

export function openFP(npub) {
  const peer = window._PEERS?.[npub]; if (!peer) return;
  const fp = kh(npub + (peer.kyberPk || '')).match(/.{4}/g).join(' ');
  document.getElementById('fpName').textContent   = peer.name;
  document.getElementById('fpPub').textContent    = npub;
  document.getElementById('fpKpub').textContent   = (peer.kyberPk || '—').slice(0, 48) + '...';
  document.getElementById('fpHash').textContent   = fp;
  document.getElementById('fpStatus').textContent = peer.fpVerified ? '✓ Verified' : '⚠ Not verified — confirm with peer out-of-band';
  document.getElementById('fpStatus').style.color = peer.fpVerified ? 'var(--grn)' : 'var(--red)';
  document.getElementById('fpModal').dataset.npub = npub;
  document.getElementById('fpModal').classList.add('show');
}

export function closeFP() { document.getElementById('fpModal').classList.remove('show'); }

export function verifyFP() {
  const npub = document.getElementById('fpModal').dataset.npub;
  if (!npub || !window._PEERS?.[npub]) return;
  window._PEERS[npub].fpVerified = true; savePeers();
  document.getElementById('fpStatus').textContent = '✓ Verified';
  document.getElementById('fpStatus').style.color = 'var(--grn)';
  renderPeers(); renderContacts();
}

// ── Key Transparency log ──

export function ktRecord(peer, newPk, event) {
  if (!window._ktLog) window._ktLog = [];
  window._ktLog.push({ peer, newHash: kh(newPk).slice(0, 16), event, ts: Date.now() });
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
