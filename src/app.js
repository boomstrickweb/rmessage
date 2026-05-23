/**
 * app.js — Application entry point
 *
 * Boot sequence:
 *  1. Generate / load Nostr keypair + ML-KEM-768 keypair
 *  2. PIN unlock (decrypt stored keys) or first-run PIN setup
 *  3. Connect to Nostr relays
 *  4. Start traffic padding + heartbeat
 *  5. Render contacts
 *
 * All global state is attached to `window` so modules can share it
 * without circular imports. In a full Vite/React build these would
 * be proper module-level stores.
 */

'use strict';

import { genNKP, buildEv, schnorrSign } from './crypto/secp256k1.js';
import { kemKG, kemE, kemD }            from './crypto/mlkem.js';
import { mldsaKG, mldsaSign }           from './crypto/mldsa.js';
import { SHA3_256 }                      from './crypto/sha3.js';
import {
  drEncrypt, drDecrypt, pqEncStr, pqDecStr,
  pqEncBin, pqDecBin, pqEncPadded,
  aesEnc, aesDec, hkdf1, yieldUI,
} from './crypto/ratchet.js';
import { hex, fhex, rnd, te, td, cat }  from './utils.js';
import {
  RELAYS, WS, CONN, relConn, resubAll, nostrPub, setRp,
} from './transport/nostr.js';
import { onEv }                          from './transport/events.js';
import { sendHybrid, startHeartbeat, stopHeartbeat } from './transport/onion.js';
import { startPadding, stopPadding, sendWithCoverSealed } from './transport/padding.js';
import {
  PCManager, getTurnServers, waitForGathering, sanitizeSDP,
  startCall, answerCall, rejectCall, endCall,
  toggleMute, toggleSpk, sendMedia, startRec, stopRec, cancelRec,
  playVoice, ensureDC, updateP2PStatus,
} from './transport/webrtc.js';
import { CRDT, idbSave, idbLoad }        from './storage/crdt.js';
import {
  hasEncryptedSKs, saveEncryptedSKs, loadEncryptedSKs,
  bioSupported, bioEnroll, bioUnlock,
  showPinScreen, hidePinScreen, pinKey, pinDel, tryBiometric, awaitPin, changePin,
} from './storage/pin.js';
import { renderContacts, renderMsgs, renderPeers, showBadge, ktRender, loadBytesIfNeeded } from './ui/render.js';
import {
  addPeer, delPeer, openFP, closeFP, verifyFP,
  openKT, closeKT, setDisappearing, runDisappearing,
  emergencyWipe, exportKeys, importKeys, copyShareBundle, ktRecord,
} from './ui/settings.js';

// ── Expose globals needed by inline HTML onclick handlers ──

const G = window;
G.pinKey        = pinKey;
G.pinDel        = pinDel;
G.tryBiometric  = tryBiometric;
G.changePin     = changePin;
G.answerCall    = answerCall;
G.rejectCall    = rejectCall;
G.endCall       = endCall;
G.toggleMute    = toggleMute;
G.toggleSpk     = toggleSpk;
G.playVoice     = (id) => playVoice(id);
G.startCall     = (pub) => { startCall(pub); };
G.addPeer       = addPeer;
G.delPeer       = delPeer;
G.openFP        = openFP;
G.closeFP       = closeFP;
G.verifyFP      = verifyFP;
G.openKT        = () => { ktRender(); document.getElementById('ktModal').classList.add('show'); };
G.closeKT       = () => document.getElementById('ktModal').classList.remove('show');
G.setDisappearing = (val) => setDisappearing(val);
G.emergencyWipe = emergencyWipe;
G.exportKeys    = exportKeys;
G.importKeys    = (file) => importKeys(file);
G.copyBundle    = copyShareBundle;
G.clearData     = () => {
  if (!confirm('Clear all data? PIN and all keys will be deleted!')) return;
  localStorage.clear(); sessionStorage.clear(); location.reload();
};
G.hideWipeModal = () => document.getElementById('wipeModal').classList.remove('show');
G.openTTL       = () => {
  const v = parseInt(localStorage.getItem('rl6_ttl_' + G.AP) || '0');
  ['0','3600','86400','604800'].forEach(val => {
    const el = document.getElementById('ttlSel' + val);
    if (el) el.textContent = (val === String(v)) ? '✓' : '—';
  });
  document.getElementById('ttlModal').classList.add('show');
};
G.closeTTL      = () => document.getElementById('ttlModal').classList.remove('show');
G.setTTL        = (sec) => {
  if (sec === 0) localStorage.removeItem('rl6_ttl_' + G.AP);
  else localStorage.setItem('rl6_ttl_' + G.AP, String(sec));
  G.updateDMBar();
  G.updateTTLBtn();
  G.closeTTL();
  G.openTTL();
};
G.openImg = (url) => {
  document.getElementById('imgVImg').src = url;
  document.getElementById('imgV').classList.add('show');
};
G.closeImg = () => document.getElementById('imgV').classList.remove('show');
G._renderMsgs   = renderMsgs;
G._idbSave      = idbSave;
G._WS           = WS;
G._CONN         = CONN;

// ── Color palette for peer avatars ──

const COLORS = ['#e8ff00','#00aaff','#00ff88','#ff5588','#ff9900','#cc44ff'];
const randCol = () => COLORS[Math.floor(Math.random() * COLORS.length)];

// ── Navigation ──

let _curScreen = 'C';
G.AP = null; // Active peer (open chat)

function showScreen(id) {
  ['C','Chat','Call','S'].forEach(s => {
    const el = document.getElementById('sc' + s);
    if (!el) return;
    el.className = 'screen' + (s === id ? ' act' : (s === 'C' && id !== 'C' ? ' hl' : ' hr'));
  });
  ['C','S'].forEach(s => document.getElementById('nb' + s)?.classList.toggle('act', s === id));
  _curScreen = id;
}

G.goContacts = () => { G.AP = null; showScreen('C'); renderContacts(); };
G.goSettings = () => {
  showScreen('S');
  // Refresh key display every time settings opens
  const NK = G._NK, KK = G._KKkeys;
  const nostrEl = document.getElementById('myNostr');
  const kyberEl = document.getElementById('myKyber');
  const topKey  = document.getElementById('topKey');
  if (nostrEl && NK?.pub)  nostrEl.textContent = NK.pub;
  if (kyberEl && KK?.pk)   kyberEl.textContent = KK.pk.slice(0, 64) + '...' + KK.pk.slice(-16);
  if (topKey  && NK?.pub)  topKey.textContent  = NK.pub.slice(0, 10) + '...';
  renderPeers();
  ktRender();
};

G.sendTxt       = sendTxt;

G.openChat      = (pub) => {
  G.AP = pub;
  const peer = G._PEERS?.[pub];
  if (!peer) return;
  const nmEl = document.getElementById('chatName');
  const keyEl = document.getElementById('chatKey');
  if (nmEl) {
    nmEl.textContent  = peer.name;
    nmEl.style.color  = peer.color;
  }
  if (keyEl) keyEl.textContent = pub;
  G.updateFPBtn(pub);
  G.updateTTLBtn();
  G.updateDMBar();
  peer.lastRead = Date.now();
  localStorage.setItem('rl5_peers', JSON.stringify(G._PEERS));
  renderContacts();
  showScreen('Chat');
  renderMsgs();
};
G.openChatFromContacts = G.openChat;

G._showCallScreen = (pub, statusText, statusCls) => {
  const peer = G._PEERS?.[pub];
  const nm   = peer?.name || pub.slice(0, 14);
  const col  = peer?.color || 'var(--pq)';
  document.getElementById('callAv').textContent   = nm[0].toUpperCase();
  document.getElementById('callAv').style.background = col + '22';
  document.getElementById('callAv').style.color   = col;
  document.getElementById('callNm').textContent   = nm;
  document.getElementById('callSt').textContent   = statusText;
  document.getElementById('callSt').className     = 'call-st ' + (statusCls || '');
  showScreen('Call');
};

G.startCallFromChat = () => { if (G.AP) startCall(G.AP); };

// ── Text input auto-resize ──

G.rsz = (el) => {
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 120) + 'px';
  const sbtn = document.getElementById('sbtn');
  if (sbtn) sbtn.disabled = !el.value.trim();
};

document.getElementById('minp').addEventListener('input', () => {
  document.getElementById('sbtn').disabled = !document.getElementById('minp').value.trim();
});

// ── Send text message ──

G.sendTxt = async () => {
  const inp  = document.getElementById('minp');
  const text = inp.value.trim();
  if (!text || !G.AP) return;
  const peer = G._PEERS?.[G.AP];
  if (!peer?.kyberPk) {
    alert('Peer has no key. Add their key bundle via ⚙ Settings → Add Peer.');
    return;
  }
  inp.value  = ''; inp.style.height = 'auto';
  document.getElementById('sbtn').disabled = true;
  const op = G._C.add('text', { text }, G.AP);
  renderMsgs();
  renderContacts();
  const fullOp = { ...op, _sender: { nostr: G._NK.pub, kyber: G._KKkeys.pk } };
  if (CONN.size > 0) {
    try {
      await sendHybrid(G.AP, peer.kyberPk, fullOp);
    } catch (e) {
      console.error('Send failed:', e);
      G._OQ.push({ to: G.AP, op: fullOp }); G._saveOQ();
      document.getElementById('obar').classList.add('on');
    }
  } else {
    G._OQ.push({ to: G.AP, op: fullOp }); G._saveOQ();
    document.getElementById('obar').classList.add('on');
  }
  document.getElementById('sbtn').disabled = false;
  document.getElementById('minp').focus();
};

async function _queueOrSend(toPub, kyberPk, op) {
  const peer = G._PEERS?.[toPub];
  if (!kyberPk || !CONN.size) {
    G._OQ.push({ to: toPub, op }); G._saveOQ();
    document.getElementById('obar').classList.add('on');
    return;
  }
  try {
    await sendHybrid(toPub, kyberPk, op);
  } catch (e) {
    console.error('Send failed, queuing:', e);
    G._OQ.push({ to: toPub, op }); G._saveOQ();
    document.getElementById('obar').classList.add('on');
  }
}
G._sendHybrid = sendHybrid;

// ── File attachment ──

G.onFile = async (ev) => {
  const file = ev.target.files?.[0]; if (!file || !G.AP) return;
  ev.target.value = '';
  if (!G._PEERS?.[G.AP]?.kyberPk) { alert('Peer has no key yet. Send a text message first.'); return; }
  await sendMedia(G.AP, file);
};

// ── Image viewer ──

G.openImg = (url) => {
  document.getElementById('imgVImg').src = url;
  document.getElementById('imgV').classList.add('show');
};
G.closeImg = () => { document.getElementById('imgV').classList.remove('show'); };

// ── Voice recording ──

G.startRec = startRec;
G.stopRec  = stopRec;
G.cancelRec = cancelRec;

// ── Copy key bundle ──

G.copyBundle = () => {
  const NK = G._NK, KK = G._KKkeys;
  if (!NK || !KK) return;
  const bundle = JSON.stringify({ nostrPub: NK.pub, kyberPk: KK.pk, v: 1 });
  navigator.clipboard.writeText(bundle).then(() => {
    const btn = document.getElementById('copyBtn');
    btn.textContent = '✓ Copied!'; btn.classList.add('copy-ok');
    setTimeout(() => { btn.textContent = '📋 \u00a0Copy Key Bundle (JSON)'; btn.classList.remove('copy-ok'); }, 2200);
  }).catch(() => prompt('Copy this JSON:', bundle));
};

// ── Fingerprint confirm ──

G.confirmVerify = () => {
  const npub = document.getElementById('fpModal').dataset.npub;
  if (!npub || !G._PEERS?.[npub]) return;
  G._PEERS[npub].fpVerified = true;
  localStorage.setItem('rl5_peers', JSON.stringify(G._PEERS));
  document.getElementById('fpStatus').textContent = '✓ Verified';
  document.getElementById('fpStatus').style.color = 'var(--grn)';
  const fpBtn = document.getElementById('fpBtn');
  if (G.AP === npub) fpBtn.className = 'fp-btn verified';
  renderPeers(); renderContacts();
};

// ── Disappearing Messages (per-chat) ──

let _chatTTL = 0;

G.openTTL = () => {
  ['0','3600','86400','604800'].forEach(v => {
    document.getElementById('ttlSel' + v).textContent = (Number(v) * 1000 === _chatTTL) ? '✓' : '—';
  });
  document.getElementById('ttlModal').classList.add('show');
};

G.closeTTL = () => document.getElementById('ttlModal').classList.remove('show');

G.setTTL = (sec) => {
  _chatTTL = sec * 1000;
  localStorage.setItem('rl6_chatttl_' + G.AP, String(_chatTTL));
  updateDMBar();
  G.closeTTL();
};

function updateDMBar() {
  if (!G.AP) return;
  const v   = parseInt(localStorage.getItem('rl6_chatttl_' + G.AP) || '0');
  _chatTTL  = v;
  const bar = document.getElementById('dmBar');
  bar.classList.toggle('on', v > 0);
}

// ── Emergency Wipe ──

let _wipeTimer = null;

G.showWipeModal = () => {
  document.getElementById('wipeModal').classList.add('show');
  document.getElementById('wipeProgress').classList.remove('on');
  document.getElementById('wipeBar').style.width = '0';
  document.getElementById('wipeHint').textContent = 'Hold button for 3 seconds';
};

G.hideWipeModal = () => document.getElementById('wipeModal').classList.remove('show');

G.startWipeHold = (e) => {
  if (e?.preventDefault) e.preventDefault();
  document.getElementById('wipeProgress').classList.add('on');
  let pct = 0;
  const bar = document.getElementById('wipeBar');
  _wipeTimer = setInterval(() => {
    pct += 100 / 30;
    bar.style.width = Math.min(pct, 100) + '%';
    if (pct >= 100) { clearInterval(_wipeTimer); _wipeTimer = null; emergencyWipe(); }
  }, 100);
};

G.cancelWipeHold = () => {
  if (_wipeTimer) { clearInterval(_wipeTimer); _wipeTimer = null; }
  document.getElementById('wipeProgress').classList.remove('on');
  document.getElementById('wipeBar').style.width = '0';
};

// ── Reset data (soft reset — keeps keys) ──

G.clearData = () => {
  if (!confirm('Delete all messages? Keys and contacts will be kept.')) return;
  G._C.ops = []; G._C._save();
  renderContacts(); if (G.AP) renderMsgs();
};

// ── Offline queue ──

G._OQ = [];
G._saveOQ = () => {
  try {
    const safe = G._OQ.map(q => ({ to: q.to, op: { ...q.op, payload: { ...q.op.payload, _bytes: undefined } } }));
    localStorage.setItem('rl6_oq', JSON.stringify(safe));
  } catch {}
};

function _loadOQ() {
  try { G._OQ = JSON.parse(localStorage.getItem('rl6_oq') || '[]'); } catch { G._OQ = []; }
  if (G._OQ.length) document.getElementById('obar').classList.add('on');
}

async function _flushOQ() {
  if (!G._OQ.length) return;
  const q = [...G._OQ]; G._OQ = []; G._saveOQ();
  for (const item of q) {
    const peer = G._PEERS?.[item.to];
    if (peer?.kyberPk) {
      try { await sendHybrid(item.to, peer.kyberPk, item.op); }
      catch { G._OQ.push(item); }
    }
  }
  if (!G._OQ.length) document.getElementById('obar').classList.add('on');
  else document.getElementById('obar').classList.remove('on');
}

// ── Relay pills ── 

function buildRelayPills() {
  const c = document.getElementById('rpills'); c.innerHTML = '';
  RELAYS.forEach(u => {
    const d   = document.createElement('div');
    const id  = 'rp' + btoa(u).replace(/\W/g,'');
    d.className = 'rp try'; d.id = id;
    d.innerHTML = `<div class="rdot"></div>${u.split('/')[2].split('.').slice(-2).join('.')}`;
    c.appendChild(d);
  });
}

// ── Fingerprint emoji logic (matches original index.html exactly) ──

const FP_EMOJIS = ['🔥','🌊','⚡','🌙','🦋','🐉','🌺','🎯','🔮','🌈',
  '🦅','🐬','🌸','⭐','🎪','🦊','🌴','🎭','🔱','🦁',
  '🌋','🐙','🎨','🏔','🦄','🌊','🎸','🦜','🌙','🔮',
  '🎯','🦋','⚡','🌺','🐉','🔥','🎪','🦅','🐬','🌸',
  '🎭','🔱','🦁','🌋','🐙','🎨','🏔','🦄','🎸','🦜',
  '🍄','🦩','🎲','🌿','🔭','🦚','🎠','🌠','🦋','🔑',
  '🌊','⚗️','🦈','🎡'];

async function computeFP(peerPub) {
  const peer = G._PEERS?.[peerPub]; if (!peer?.kyberPk) return null;
  const [a, b] = G._NK.pub < peerPub
    ? [G._NK.pub + G._KKkeys.pk, peerPub + peer.kyberPk]
    : [peerPub + peer.kyberPk,   G._NK.pub + G._KKkeys.pk];
  const raw  = new TextEncoder().encode(a + '|' + b);
  const { SHA3_256: sha3 } = await import('./crypto/sha3.js');
  return sha3(raw);
}

function fpToEmojis(hash) {
  return Array.from({ length: 12 }, (_, i) => FP_EMOJIS[hash[i] % FP_EMOJIS.length]);
}

function fpToHex(hash) {
  return Array.from(hash).map(x => x.toString(16).padStart(2,'0')).join('').match(/.{1,8}/g).join(' ');
}

let _fpCurrentPeer = null;

G.openFP = async (peerPub) => {
  if (!peerPub || !G._PEERS?.[peerPub]) return;
  _fpCurrentPeer = peerPub;
  const peer = G._PEERS[peerPub];
  const hash = await computeFP(peerPub);
  if (!hash) return;
  const emojis = fpToEmojis(hash);
  const hexStr = fpToHex(hash);
  const verified = peer.fpVerified === hexStr;

  document.getElementById('fpEmojis').innerHTML = emojis.map(e => `<div class="fp-em">${e}</div>`).join('');
  document.getElementById('fpHex').textContent  = hexStr;
  document.getElementById('fpSubtitle').innerHTML =
    `Compare emojis with <b>${peer.name}</b> out-of-band.<br>All match? Connection is secure.`;

  const statusEl = document.getElementById('fpStatus');
  const verifyBtn = document.getElementById('fpVerifyBtn');
  if (verified) {
    statusEl.innerHTML = `<div class="fp-ok">✓ This peer is verified. Connection is secure.</div>`;
    verifyBtn.textContent = '✓ Verified';
    verifyBtn.style.background = 'var(--b2)';
    verifyBtn.style.color = 'var(--mut)';
  } else {
    statusEl.innerHTML = `<div class="fp-warn">⚠ Not yet verified. Compare with your peer!</div>`;
    verifyBtn.textContent = '✓ Mark as Verified';
    verifyBtn.style.background = 'var(--grn)';
    verifyBtn.style.color = '#000';
  }

  document.getElementById('fpModal').classList.add('show');
};

G.closeFP = () => { document.getElementById('fpModal').classList.remove('show'); _fpCurrentPeer = null; };

G.confirmVerify = async () => {
  const npub = _fpCurrentPeer;
  if (!npub || !G._PEERS?.[npub]) return;
  const hash = await computeFP(npub); if (!hash) return;
  const hexStr = fpToHex(hash);
  G._PEERS[npub].fpVerified = hexStr;
  localStorage.setItem('rl5_peers', JSON.stringify(G._PEERS));
  const fpBtn = document.getElementById('fpBtn');
  if (G.AP === npub) G.updateFPBtn(npub);
  G.closeFP();
  renderContacts(); renderPeers();
};

G.updateFPBtn = (peerPub) => {
  const btn = document.getElementById('fpBtn'); if (!btn) return;
  const peer = G._PEERS?.[peerPub]; if (!peer) return;
  if (!peer.kyberPk) { btn.className = 'fp-btn'; btn.title = 'No key'; return; }
  if (peer.fpVerified) {
    btn.className = 'fp-btn verified'; btn.textContent = '✓'; btn.title = 'Key verified';
  } else {
    btn.className = 'fp-btn unverified'; btn.textContent = '⚠'; btn.title = 'Key NOT VERIFIED — click!';
  }
};

G.updateTTLBtn = () => {
  const btn = document.getElementById('ttlBtn'); if (!btn) return;
  const ttl = parseInt(localStorage.getItem('rl6_ttl_' + G.AP) || '0');
  btn.textContent = ttl > 0 ? '⏱' : '⏲';
  btn.title = ttl > 0 ? 'Disappearing messages: ON' : 'Disappearing messages: OFF';
};

G.updateDMBar = () => {
  const bar = document.getElementById('dmBar'); if (!bar) return;
  const ttl = parseInt(localStorage.getItem('rl6_ttl_' + G.AP) || '0');
  if (ttl > 0) {
    bar.textContent = `⏱ Disappearing ON (${ttl >= 86400 ? (ttl/86400)+'d' : (ttl/3600)+'h'})`;
    bar.classList.add('show');
  } else {
    bar.classList.remove('show');
  }
};

// ── App boot ──

console.log('RELAY: app.js loaded');

async function boot() {
  console.log('RELAY: boot() started');
  try {
    const loadingEl = document.getElementById('loading');
    const lmsgEl = document.getElementById('lmsg');
    
    if (loadingEl) loadingEl.style.display = 'flex';
    if (lmsgEl) lmsgEl.textContent = 'Initialising ML-KEM-768...';
    await yieldUI();

  // Load peers + offline queue
  G._PEERS = {};
  try { G._PEERS = JSON.parse(localStorage.getItem('rl5_peers') || '{}'); } catch {}
  _loadOQ();

  // Key transparency log
  try { G._ktLog = JSON.parse(localStorage.getItem('rl6_kt') || '[]'); } catch { G._ktLog = []; }

  // Disappearing messages
  const dis = parseInt(localStorage.getItem('rl6_disappear') || '0');
  G._disappearMs = dis > 0 ? dis : 0;
  if (G._disappearMs > 0) setInterval(runDisappearing, 60000);

  // WebRTC state
  G._PCM = null; G._callPeer = null; G._callState = 'idle'; G._muted = false;
  G._localStream = null; G._remoteAudio = null;
  G._pendingOffer = null;

  // ── Load or generate keys ──

  let nkPriv, kkSk;

  if (hasEncryptedSKs()) {
    document.getElementById('loading').style.display = 'none';
    const result = await awaitPin('unlock');
    nkPriv = result.nkPriv; kkSk = result.kkSk;
    document.getElementById('loading').style.display = 'flex';
  } else {
    // First run — generate keys
    document.getElementById('lmsg').textContent = 'Generating post-quantum keypair...';
    await yieldUI();
    const nk = genNKP();
    document.getElementById('lmsg').textContent = 'ML-KEM-768 (FIPS 203)...';
    await yieldUI();
    const kk = kemKG();
    // Save public parts unencrypted (needed to survive unlock)
    localStorage.setItem('rl5_nkey_pub', nk.pub);
    localStorage.setItem('rl5_kkey_pub', kk.pk);
    localStorage.setItem('rl5_nkey', JSON.stringify({ pub: nk.pub }));
    localStorage.setItem('rl5_kkey', JSON.stringify({ pk: kk.pk }));

    document.getElementById('loading').style.display = 'none';
    const pin = await awaitPin('setup');
    document.getElementById('loading').style.display = 'flex';
    document.getElementById('lmsg').textContent = 'Encrypting keys with PIN...';
    await saveEncryptedSKs(pin, nk.priv, kk.sk);
    nkPriv = nk.priv; kkSk = kk.sk;

    if (await bioSupported()) {
      const enroll = await bioEnroll(pin);
      if (enroll) console.log('Biometric enrolled');
    }
  }

  // Reconstruct full key objects — pub from localStorage, priv/sk from PIN-decrypted store
  document.getElementById('lmsg').textContent = 'Loading keys...';
  await yieldUI();

  // Read pub keys from the same keys the original app uses
  const nkPub = JSON.parse(localStorage.getItem('rl5_nkey') || '{}').pub ||
                localStorage.getItem('rl5_nkey_pub') || '';
  const kkPub = JSON.parse(localStorage.getItem('rl5_kkey') || '{}').pk  ||
                localStorage.getItem('rl5_kkey_pub') || '';

  G._NK     = { priv: nkPriv, pub: nkPub };
  G._KKkeys = { pk: kkPub,    sk: kkSk  };

  // Double Ratchet state
  document.getElementById('lmsg').textContent = 'Double Ratchet state...';
  await yieldUI();
  G._C = CRDT.load(G._NK.pub);

  // Reload IDB bytes for any media ops
  document.getElementById('lmsg').textContent = 'Loading media from storage...';
  await yieldUI();
  for (const op of G._C.ops) {
    if (['image','voice','file'].includes(op.type) && !op.payload?._bytes) {
      const rec = await idbLoad(op.id);
      if (rec?.bytes) { op.payload._bytes = rec.bytes; if (!op.payload.mimeType) op.payload.mimeType = rec.mime; }
    }
  }

  // Settings display
  document.getElementById('myNostr').textContent = G._NK.pub.slice(0, 32) + '...';
  document.getElementById('myKyber').textContent = G._KKkeys.pk.slice(0, 32) + '...';
  const topKey = document.getElementById('topKey');
  topKey.textContent = G._NK.pub.slice(0, 14) + '...';

  // Relay pills + connections
  buildRelayPills();
  document.getElementById('lmsg').textContent = 'Connecting to Nostr relays...';
  await yieldUI();
  RELAYS.forEach(u => relConn(u));
  setTimeout(_flushOQ, 4000);

  // Render
  renderContacts();
  ktRender();
  renderPeers();
  showBadge();

  // Done
  document.getElementById('loading').style.display = 'none';
  // Send resub to all relays
  resubAll();

  // Start traffic padding + heartbeat
  setTimeout(startPadding, 8000);
  setTimeout(startHeartbeat, 3000);

  // Generate ML-DSA key in background — does NOT block app start
  let mldsaSk = localStorage.getItem('rl6_mldsa_sk');
  let mldsaPk = localStorage.getItem('rl6_mldsa_pk');
  if (!mldsaSk || !mldsaPk) {
    setTimeout(async () => {
      try {
        const dk = mldsaKG();
        G._MLDSAkeys = dk;
        localStorage.setItem('rl6_mldsa_sk', dk.sk);
        localStorage.setItem('rl6_mldsa_pk', dk.pk);
        console.log('ML-DSA-44 ready');
      } catch (e) { console.warn('ML-DSA keygen failed', e); }
    }, 100);
  } else {
    G._MLDSAkeys = { sk: mldsaSk, pk: mldsaPk };
  }
  } catch (e) {
    console.error('Boot error:', e);
    const lmsgEl = document.getElementById('lmsg');
    if (lmsgEl) lmsgEl.textContent = 'Startup error: ' + e.message;
  }
}

boot();
