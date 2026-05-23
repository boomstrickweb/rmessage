import { G, te, td, hex, fhex, rnd, cat, esc, rn, ft, rsz, wsha256, computeFP, fpToEmojis, fpToHex } from './utils.js';
import { genNKP, schnorrSign, buildEv } from './crypto/secp256k1.js';
import { kemKG, kemE, kemD, aesEnc, aesDec } from './crypto/mlkem.js';
import { mldsaKG, mldsaSign, mldsaVerify } from './crypto/mldsa.js';
import { drLoad, drSave, drInit, drInitRecv, hkdf2, hkdf1 } from './crypto/ratchet.js';
import { CRDT, idbSave, idbLoad, idbDelete } from './storage/crdt.js';
import { hasEncryptedSKs, loadEncryptedSKs, saveEncryptedSKs, awaitPin, showPinScreen, pinKey, pinDel, tryBiometric, bioSupported, bioEnroll, bioUnlock } from './storage/pin.js';
import { RELAYS, WS, CONN, relConn, resubAll, nostrPub, isReplay, iStat, setRp } from './transport/nostr.js';
import { renderContacts, renderMsgs, renderPeers, showBadge } from './ui/render.js';
import { addPeer, delPeer } from './ui/settings.js';
import { onEv } from './transport/events.js';

// Global state initialization
G._PEERS = {};
G._NK = null;
G._KKkeys = null;
G._C = null;
G._OQ = [];
G.AP = null; // Active Peer
G.MLDSAkeys = null;

const TTL_LABELS = { 0: 'Off', 3600: '1h', 86400: '24h', 604800: '7d' };

// ── Application Boot ──

async function boot() {
  setLM('Initializing...');
  document.getElementById('loading').style.display = 'flex';

  let nkPriv, kkSk;

  if (hasEncryptedSKs()) {
    const sessionPin = sessionStorage.getItem('rl6_session_pin');
    if (sessionPin) {
      try {
        const r = await loadEncryptedSKs(sessionPin);
        nkPriv = r.nkPriv; kkSk = r.kkSk;
      } catch { sessionStorage.removeItem('rl6_session_pin'); }
    }
    if (!nkPriv) {
      document.getElementById('loading').style.display = 'none';
      const r = await awaitPin('unlock');
      nkPriv = r.nkPriv; kkSk = r.kkSk;
      document.getElementById('loading').style.display = 'flex';
    }
  } else {
    setLM('Generating keys...');
    const tmpNK = genNKP();
    setLM('ML-KEM-768 (FIPS 203)...');
    const tmpKK = kemKG();
    localStorage.setItem('rl5_nkey_pub', tmpNK.pub);
    localStorage.setItem('rl5_kkey_pub', tmpKK.pk);
    
    document.getElementById('loading').style.display = 'none';
    await awaitPin('setup');
    const pin = sessionStorage.getItem('rl6_session_pin');
    document.getElementById('loading').style.display = 'flex';
    setLM('Encrypting keys...');
    await saveEncryptedSKs(pin, tmpNK.priv, tmpKK.sk);
    localStorage.setItem('rl5_nkey', JSON.stringify({ pub: tmpNK.pub }));
    localStorage.setItem('rl5_kkey', JSON.stringify({ pk: tmpKK.pk }));
    nkPriv = tmpNK.priv; kkSk = tmpKK.sk;
    if (await bioSupported()) {
      setTimeout(() => offerBioEnroll(pin), 500);
    }
  }

  setLM('Loading assets...');
  const nkPub = JSON.parse(localStorage.getItem('rl5_nkey') || '{}').pub || localStorage.getItem('rl5_nkey_pub');
  const kkPub = JSON.parse(localStorage.getItem('rl5_kkey') || '{}').pk || localStorage.getItem('rl5_kkey_pub');
  G._NK = { priv: nkPriv, pub: nkPub };
  G._KKkeys = { pk: kkPub, sk: kkSk };

  try { G._PEERS = JSON.parse(localStorage.getItem('rl5_peers')) || {}; } catch { G._PEERS = {}; }
  try { G._OQ = JSON.parse(localStorage.getItem('rl6_oq')) || []; } catch { G._OQ = []; }
  try { const dk = JSON.parse(localStorage.getItem('rl6_mldsa_key')); if (dk?.pk && dk?.sk) G.MLDSAkeys = dk; } catch { }

  G._C = CRDT.load(G._NK.pub);
  document.getElementById('myNostr').textContent = G._NK.pub;
  document.getElementById('myKyber').textContent = G._KKkeys.pk.slice(0, 64) + '...' + G._KKkeys.pk.slice(-16);
  document.getElementById('topKey').textContent = G._NK.pub.slice(0, 10) + '...';
  document.getElementById('rpills').innerHTML = RELAYS.map(u => `<div class="rp" id="rp${btoa(u).replace(/\W/g, '')}"><div class="rdot"></div>${rn(u)}</div>`).join('');
  
  renderContacts();
  document.getElementById('loading').style.display = 'none';
  RELAYS.forEach(url => relConn(url, onEv));

  if (!G.MLDSAkeys) {
    setTimeout(async () => {
      try { G.MLDSAkeys = mldsaKG(); localStorage.setItem('rl6_mldsa_key', JSON.stringify(G.MLDSAkeys)); } catch { }
    }, 100);
  }
}

function setLM(m) { document.getElementById('lmsg').textContent = m; }

async function offerBioEnroll(pin) {
  if (!confirm('Enable Biometrics (Face ID / Touch ID)?')) return;
  const ok = await bioEnroll(pin);
  if (ok) alert('Biometrics enabled ✓');
}

// ── Global UI Exposure ──

G.openChat = (pub) => {
  G.AP = pub; const p = G._PEERS[pub]; if (!p) return;
  p.lastRead = Date.now(); localStorage.setItem('rl5_peers', JSON.stringify(G._PEERS));
  document.getElementById('chatName').textContent = p.name;
  document.getElementById('chatName').style.color = p.color;
  document.getElementById('chatKey').textContent = pub;
  document.getElementById('sbtn').disabled = false;
  sl('scChat', 'act'); sl('scC', 'hl'); sl('scCall', 'hr'); sl('scS', 'hr'); na('nbC');
  updateFPBtn(pub);
  updateTTLBtn();
  renderContacts(); renderMsgs();
};

G.goContacts = () => { sl('scC', 'act'); sl('scChat', 'hr'); sl('scCall', 'hr'); sl('scS', 'hr'); na('nbC'); };
G.goSettings = () => { sl('scS', 'act'); sl('scC', 'hl'); sl('scChat', 'hr'); sl('scCall', 'hr'); na('nbS'); renderPeers(); };

G.sendTxt = async () => {
  const inp = document.getElementById('minp'); const txt = inp.value.trim(); if (!txt || !G.AP) return;
  const peer = G._PEERS[G.AP];
  if (!peer?.kyberPk) { alert('Peer key missing. Add via Settings.'); return; }
  document.getElementById('sbtn').disabled = true;
  const op = G._C.add('text', { text: txt }, G.AP); renderMsgs();
  inp.value = ''; inp.style.height = 'auto';
  try {
    const s = await nostrPub(G.AP, peer.kyberPk, op);
    if (!s) { G._OQ.push({ to: G.AP, op }); saveOQ(); document.getElementById('obar').classList.add('on'); }
  } catch { G._OQ.push({ to: G.AP, op }); saveOQ(); document.getElementById('obar').classList.add('on'); }
  document.getElementById('sbtn').disabled = false; inp.focus();
};

document.getElementById('minp').addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey && window.innerWidth > 600) {
    e.preventDefault();
    G.sendTxt();
  }
});

function saveOQ() { localStorage.setItem('rl6_oq', JSON.stringify(G._OQ)); }

G.addPeer = addPeer;
G.delPeer = delPeer;
G.rsz = rsz;

G.onFile = (e) => {
  const f = e.target.files[0]; if (!f || !G.AP) return;
  e.target.value = '';
  // Simplified media send for now (just local show)
  const mt = f.type.startsWith('image') ? 'image' : f.type.startsWith('audio') ? 'voice' : 'file';
  const tid = hex(rnd(16));
  f.arrayBuffer().then(ab => {
    const data = new Uint8Array(ab);
    const op = G._C.add(mt, { _bytes: data, name: f.name, size: f.size, mimeType: f.type, _prog: 1 }, G.AP);
    op.id = tid; idbSave(tid, data, f.type); renderMsgs();
  });
};

G.openImg = (url) => { document.getElementById('imgVImg').src = url; document.getElementById('imgV').classList.add('show'); };
G.closeImg = () => { document.getElementById('imgV').classList.remove('show'); };

G.copyBundle = async () => {
  const bundle = JSON.stringify({ nostr: G._NK.pub, kyber: G._KKkeys.pk });
  const btn = document.getElementById('copyBtn');
  try { await navigator.clipboard.writeText(bundle); }
  catch {
    const ta = document.createElement('textarea'); ta.value = bundle;
    ta.style.cssText = 'position:fixed;opacity:0;top:0;left:0';
    document.body.appendChild(ta); ta.select(); document.execCommand('copy');
    document.body.removeChild(ta);
  }
  btn.textContent = '✓ Copied!'; btn.classList.add('copy-ok');
  setTimeout(() => { btn.textContent = '📋 \u00a0Copy Key Bundle (JSON)'; btn.classList.remove('copy-ok'); }, 2000);
};

// ── Fingerprint UI ──

let _fpCurrentPeer = null;
G.openFP = async (peerPub) => {
  if (!peerPub || !G._PEERS[peerPub]) return;
  _fpCurrentPeer = peerPub;
  const peer = G._PEERS[peerPub];
  const hash = await computeFP(peerPub); if (!hash) return;
  const emojis = fpToEmojis(hash);
  const hexStr = fpToHex(hash);
  const verified = peer.fpVerified === hexStr;

  document.getElementById('fpEmojis').innerHTML = emojis.map(e => `<div class="fp-em">${e}</div>`).join('');
  document.getElementById('fpHex').textContent = hexStr;
  const statusEl = document.getElementById('fpStatus');
  if (verified) {
    statusEl.innerHTML = `<div class="fp-ok">✓ Verified. Connection is secure.</div>`;
    document.getElementById('fpVerifyBtn').textContent = '✓ Verified';
    document.getElementById('fpVerifyBtn').style.background = 'var(--b2)';
  } else {
    statusEl.innerHTML = `<div class="fp-warn">⚠ Not verified. Compare with peer!</div>`;
    document.getElementById('fpVerifyBtn').textContent = '✓ Verify';
    document.getElementById('fpVerifyBtn').style.background = 'var(--grn)';
  }
  document.getElementById('fpSubtitle').innerHTML = `Compare these emojis with <b>${peer.name}</b>.`;
  document.getElementById('fpModal').classList.add('show');
};

G.closeFP = () => { document.getElementById('fpModal').classList.remove('show'); _fpCurrentPeer = null; };
G.confirmVerify = async () => {
  if (!_fpCurrentPeer) return;
  const peer = G._PEERS[_fpCurrentPeer];
  const hash = await computeFP(_fpCurrentPeer);
  peer.fpVerified = fpToHex(hash);
  localStorage.setItem('rl5_peers', JSON.stringify(G._PEERS));
  updateFPBtn(_fpCurrentPeer);
  G.closeFP(); renderContacts();
};

function updateFPBtn(peerPub) {
  const btn = document.getElementById('fpBtn'); if (!btn) return;
  const peer = G._PEERS[peerPub];
  if (peer.fpVerified) { btn.className = 'fp-btn verified'; btn.textContent = '✓'; }
  else { btn.className = 'fp-btn unverified'; btn.textContent = '⚠'; }
}

// ── TTL UI ──

G.openTTL = () => {
  const ttl = parseInt(localStorage.getItem('rl6_ttl_' + G.AP) || '0');
  ['0', '3600', '86400', '604800'].forEach(v => {
    const el = document.getElementById('ttlSel' + v);
    if (el) el.textContent = (v === String(ttl / 1000)) ? '✓' : '—';
  });
  document.getElementById('ttlModal').classList.add('show');
};
G.closeTTL = () => document.getElementById('ttlModal').classList.remove('show');
G.setTTL = (sec) => {
  localStorage.setItem('rl6_ttl_' + G.AP, String(sec * 1000));
  updateTTLBtn(); G.closeTTL();
};
function updateTTLBtn() {
  const btn = document.getElementById('ttlBtn'); if (!btn) return;
  const ttl = parseInt(localStorage.getItem('rl6_ttl_' + G.AP) || '0');
  btn.className = ttl > 0 ? 'ttl-btn on' : 'ttl-btn';
  const bar = document.getElementById('dmBar');
  if (ttl > 0) { bar.classList.add('on'); bar.textContent = '⏱ Messages vanish after ' + TTL_LABELS[ttl / 1000]; }
  else { bar.classList.remove('on'); }
}

// ── Event Helpers ──

function sl(id, cls) { const el = document.getElementById(id); if (el) el.className = 'screen ' + cls; }
function na(id) { document.querySelectorAll('.nb').forEach(b => b.classList.remove('act')); const el = document.getElementById(id); if (el) el.classList.add('act'); }

// ── PIN Global Exposure ──
G.pinKey_ = pinKey;
G.pinDel_ = pinDel;
G.tryBiometric_ = tryBiometric;

// Global functions for inline HTML event handlers
window.onFile = (e) => G.onFile(e);
window.openImg = (u) => G.openImg(u);
window.closeImg = () => G.closeImg();
window.sendTxt = () => G.sendTxt();
window.openChat = (p) => G.openChat(p);
window.goContacts = () => G.goContacts();
window.goSettings = () => G.goSettings();
window.openFP = (p) => G.openFP(p);
window.closeFP = () => G.closeFP();
window.confirmVerify = () => G.confirmVerify();
window.copyBundle = () => G.copyBundle();
window.addPeer = () => G.addPeer();
window.delPeer = (k) => G.delPeer(k);
window.rsz = (e) => G.rsz(e);
window.pinKey = (n) => G.pinKey_(n);
window.pinDel = () => G.pinDel_();
window.tryBiometric = () => G.tryBiometric_();
window.openTTL = () => G.openTTL();
window.closeTTL = () => G.closeTTL();
window.setTTL = (s) => G.setTTL(s);
window.clearData = () => {
  if (!confirm('Clear all data? PIN and all keys will be deleted!')) return;
  localStorage.clear(); sessionStorage.clear(); location.reload();
};

// ── Start ──
document.addEventListener('DOMContentLoaded', boot);
