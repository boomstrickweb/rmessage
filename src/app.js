import { G, te, td, hex, fhex, rnd, cat, esc, rn, ft, rsz, wsha256, computeFP, fpToEmojis, fpToHex } from './utils.js';
import { genNKP, schnorrSign, buildEv } from './crypto/secp256k1.js';
import { kemKG, kemE, kemD, aesEnc, aesDec } from './crypto/mlkem.js';
import { mldsaKG, mldsaSign, mldsaVerify } from './crypto/mldsa.js';
import { drLoad, drSave, drInit, drInitRecv, hkdf2, hkdf1 } from './crypto/ratchet.js';
import { CRDT, idbSave, idbLoad, idbDelete } from './storage/crdt.js';
import { hasEncryptedSKs, loadEncryptedSKs, saveEncryptedSKs, awaitPin, showPinScreen, pinKey, pinDel, tryBiometric, bioSupported, bioEnroll, bioUnlock, changePin } from './storage/pin.js';
import { padPlain, unpadPlain, pqEncPadded, sendDummySealed, startPadding, stopPadding } from './transport/padding.js';
import { markOnline, isOnline, getOnlinePeers, sendHeartbeat, startHeartbeat, stopHeartbeat, buildOnion, sendOnion } from './transport/onion.js';
import { RELAYS, WS, CONN, relConn, resubAll, nostrPub, isReplay, iStat, setRp } from './transport/nostr.js';
import { renderContacts, renderMsgs, renderPeers, showBadge } from './ui/render.js';
import { addPeer, delPeer } from './ui/settings.js';
import { onEv } from './transport/events.js';
import { sendMedia, ensureDC, addToDCQ, sanitizeSDP, PCManager, waitForGathering } from './transport/webrtc.js';

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

// Move global exposures here to avoid ReferenceError if boot fails later
window.onFile = (e) => onFile(e);
window.openImg = (u) => openImg(u);
window.closeImg = () => closeImg();
window.startRec = (e) => startRec(e);
window.stopRec = (e) => stopRec(e);
window.cancelRec = () => cancelRec();
window.playVoice = (id) => playVoice(id);
window.sendTxt = () => sendTxt();
window.openChat = (p) => openChat(p);
window.goContacts = () => goContacts();
window.goSettings = () => goSettings();
window.openFP = (p) => openFP(p);
window.closeFP = () => closeFP();
window.confirmVerify = () => confirmVerify();
window.copyBundle = () => copyBundle();
window.startCall = (p) => startCall(p);
window.startCallFromChat = () => startCallFromChat();
window.answerCall = () => answerCall();
window.rejectCall = () => rejectCall();
window.endCall = () => endCall();
window.toggleMute = () => toggleMute();
window.toggleSpk = () => toggleSpk();
window.confirmCall = () => { };
window.addPeer = () => addPeer();
window.delPeer = (k) => delPeer(k);
window.rsz = (e) => rsz(e);
window.pinKey = (n) => window.pKey(n);
window.pinDel = () => window.pDel();
window.tryBiometric = () => window.tBio();
window.openTTL = () => openTTL();
window.closeTTL = () => closeTTL();
window.setTTL = (s) => setTTL(s);
window.setDisappearing = (v) => setDisappearing(v);
window.changePin = () => changePin();
window.showWipeModal = () => showWipeModal();
window.hideWipeModal = () => hideWipeModal();
window.startWipeHold = (e) => startWipeHold(e);
window.cancelWipeHold = () => cancelWipeHold();
window.clearData = () => clearData();
window.flushOQ = () => flushOQ();

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

  if (G.updateMyKeys) G.updateMyKeys();

  try { G._PEERS = JSON.parse(localStorage.getItem('rl5_peers')) || {}; } catch { G._PEERS = {}; }
  try { G._OQ = JSON.parse(localStorage.getItem('rl6_oq')) || []; } catch { G._OQ = []; }
  try { const dk = JSON.parse(localStorage.getItem('rl6_mldsa_key')); if (dk?.pk && dk?.sk) G.MLDSAkeys = dk; } catch { }
  
  // Load Key Transparency log
  try { if (G.ktLoad) G.ktLoad(); } catch { }

  G._C = CRDT.load(G._NK.pub);
  updateMyKeys();
  const tk = document.getElementById('topKey');
  if (tk) tk.textContent = G._NK.pub.slice(0, 10) + '...';
  document.getElementById('rpills').innerHTML = RELAYS.map(u => `<div class="rp" id="rp${btoa(u).replace(/\W/g, '')}"><div class="rdot"></div>${rn(u)}</div>`).join('');
  
  renderContacts();
  document.getElementById('loading').style.display = 'none';
  RELAYS.forEach(url => relConn(url, onEv));
  iStat();

  // Background start
  try { if (startPadding) setTimeout(startPadding, 8000); } catch { }
  try { if (startHeartbeat) setTimeout(startHeartbeat, 3000); } catch { }

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

// ── Local UI Helpers ──
const clearData = () => {
  if (!confirm('Clear all data? PIN and all keys will be deleted!')) return;
  localStorage.clear(); sessionStorage.clear(); location.reload();
};

const openChat = (pub) => {
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

const goContacts = () => { sl('scC', 'act'); sl('scChat', 'hr'); sl('scCall', 'hr'); sl('scS', 'hr'); na('nbC'); };
const goSettings = () => { sl('scS', 'act'); sl('scC', 'hl'); sl('scChat', 'hr'); sl('scCall', 'hr'); na('nbS'); renderPeers(); if (G.updateMyKeys) G.updateMyKeys(); };

const updateMyKeys = () => {
  const n = document.getElementById('myNostr');
  const k = document.getElementById('myKyber');
  if (n && G._NK) n.textContent = G._NK.pub;
  if (k && G._KKkeys) k.textContent = G._KKkeys.pk.slice(0, 64) + '...' + G._KKkeys.pk.slice(-16);
};
G.updateMyKeys = updateMyKeys;

const yieldUI = () => new Promise(res => setTimeout(res, 0));

const sendHybrid = async (destPub, destKyberPk, obj) => {
  const innerObj = { ...obj, _sender: { nostr: G._NK.pub, kyber: G._KKkeys.pk } };
  const plaintext = JSON.stringify(innerObj);
  await yieldUI();
  const { ct, K } = kemE(destKyberPk);
  const padded = padPlain(plaintext);
  const { iv, ct: a } = await aesEnc(K, padded);
  const enc = JSON.stringify({ v: 4, kem: ct, iv, ct: a });

  const online = getOnlinePeers().filter(p => p !== destPub);
  let sent = false;
  if (online.length >= 1) {
    try { sent = await sendOnion(destPub, enc); } catch { }
  }
  if (!sent) {
    const ephNK = genNKP();
    const ev = await buildEv(4, enc, [['p', destPub]], ephNK.priv, ephNK.pub);
    let n = 0;
    Object.values(WS).forEach(ws => { if (ws.readyState === 1) { ws.send(JSON.stringify(['EVENT', ev])); n++; } });
    if (n === 0) return false;
  }
  const others = Object.keys(G._PEERS).filter(p => p !== destPub && G._PEERS[p]?.kyberPk);
  others.forEach(p => setTimeout(() => sendDummySealed(p).catch(() => { }), 50 + Math.random() * 250));
  return true;
};

const sendTxt = async () => {
  const inp = document.getElementById('minp'); const txt = inp.value.trim(); if (!txt || !G.AP) return;
  const peer = G._PEERS[G.AP];
  if (!peer?.kyberPk) { alert('Peer key missing. Add via Settings.'); return; }
  
  document.getElementById('sbtn').disabled = true;
  const op = G._C.add('text', { text: txt }, G.AP); renderMsgs();
  inp.value = ''; inp.style.height = 'auto';
  
  try {
    const s = await sendHybrid(G.AP, peer.kyberPk, op);
    if (!s) { G._OQ.push({ to: G.AP, op }); saveOQ(); document.getElementById('obar').classList.add('on'); }
    else { const ob = document.getElementById('obar'); if (ob) ob.classList.remove('on'); }
  } catch (err) {
    console.warn('sendTxt failed', err);
    G._OQ.push({ to: G.AP, op }); saveOQ(); document.getElementById('obar').classList.add('on');
  }
  
  iStat();
  document.getElementById('sbtn').disabled = false; inp.focus();
};

document.getElementById('minp').addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey && window.innerWidth > 600) {
    e.preventDefault();
    sendTxt();
  }
});

function saveOQ() { localStorage.setItem('rl6_oq', JSON.stringify(G._OQ)); }

const flushOQ = async () => {
  if (!G._OQ.length || !CONN.size) return;
  const q = [...G._OQ]; G._OQ = [];
  for (const item of q) {
    const peer = G._PEERS[item.to];
    if (peer?.kyberPk) {
      const s = await nostrPub(item.to, peer.kyberPk, item.op);
      if (!s) G._OQ.push(item);
    }
  }
  saveOQ();
  const ob = document.getElementById('obar');
  if (ob) ob.classList.toggle('on', G._OQ.length > 0);
  renderMsgs();
};

const onFile = (e) => {
  const f = e.target.files[0]; if (!f || !G.AP) return;
  e.target.value = '';
  sendMedia(G.AP, f);
};

const openImg = (url) => { document.getElementById('imgVImg').src = url; document.getElementById('imgV').classList.add('show'); };
const closeImg = () => { document.getElementById('imgV').classList.remove('show'); };

// ── Voice UI ──

let _mediaRec = null, _vChunks = [], _recStart = 0, _recCancelled = false;
const AUDIO_MIME = 'audio/webm;codecs=opus';

const startRec = (e) => {
  if (e) e.preventDefault();
  if (_mediaRec || !G.AP) return;
  _recCancelled = false; _recStart = Date.now();
  document.getElementById('voiceBtn').classList.add('rec');
  navigator.mediaDevices.getUserMedia({ audio: true }).then(stream => {
    _vChunks = [];
    let opts = {};
    if (MediaRecorder.isTypeSupported(AUDIO_MIME)) opts.mimeType = AUDIO_MIME;
    _mediaRec = new MediaRecorder(stream, opts);
    _mediaRec.ondataavailable = e => { if (e.data?.size > 0) _vChunks.push(e.data); };
    _mediaRec.start(200);
  }).catch(err => {
    document.getElementById('voiceBtn').classList.remove('rec');
    alert('Microphone access needed: ' + err.message);
  });
};

const stopRec = (e) => {
  if (e) e.preventDefault();
  document.getElementById('voiceBtn').classList.remove('rec');
  if (!_mediaRec || _mediaRec.state === 'inactive') { _mediaRec = null; return; }
  const dur = Math.round((Date.now() - _recStart) / 1000);
  if (dur < 1 || _recCancelled) {
    if (_mediaRec.state !== 'inactive') _mediaRec.stop();
    _mediaRec.stream.getTracks().forEach(t => t.stop()); _mediaRec = null; return;
  }
  _mediaRec.onstop = async () => {
    const mime = _vChunks[0]?.type || AUDIO_MIME || 'audio/mp4';
    const blob = new Blob(_vChunks, { type: mime });
    _mediaRec.stream.getTracks().forEach(t => t.stop()); _mediaRec = null;
    if (!G.AP || !G._PEERS[G.AP]?.kyberPk) return;
    const ext = mime.includes('mp4') ? 'mp4' : mime.includes('webm') ? 'webm' : 'm4a';
    const vFile = new File([blob], 'voice.' + ext, { type: mime });
    vFile._duration = dur;
    await sendMedia(G.AP, vFile);
  };
  _mediaRec.stop();
};

const cancelRec = () => {
  _recCancelled = true; document.getElementById('voiceBtn').classList.remove('rec');
  if (_mediaRec && _mediaRec.state !== 'inactive') {
    _mediaRec.stop(); _mediaRec.stream?.getTracks().forEach(t => t.stop()); _mediaRec = null;
  }
};

const playVoice = async (opId) => {
  const op = G._C.ops.find(o => o.id === opId); if (!op) return;
  const bytes = op.payload?._bytes;
  if (!bytes) { alert('Audio still loading...'); return; }
  const blob = new Blob([bytes], { type: op.payload?.mimeType || 'audio/webm' });
  const url = URL.createObjectURL(blob);
  const audio = new Audio(url); audio.play();
};

// ── Call UI ──

let _callPeer = null, _callState = 'idle', _localStream = null, _remoteAudio = null, _pendingOffer = null;

const setCallSt = (t, cls) => {
  const el = document.getElementById('callSt');
  if (el) { el.textContent = t; el.className = 'call-st' + (cls ? ' ' + cls : ''); }
};

const showCallScreen = (peerPub, status, cls) => {
  const peer = G._PEERS[peerPub]; if (!peer) return;
  const av = document.getElementById('callAv');
  if (av) {
    av.style.background = `${peer.color}22`;
    av.style.color = peer.color;
    av.textContent = peer.name[0].toUpperCase();
  }
  const nm = document.getElementById('callNm');
  if (nm) nm.textContent = peer.name;
  setCallSt(status, cls);
  sl('scCall', 'act');
  // Reset other screens
  sl('scC', 'hl'); sl('scChat', 'hl'); sl('scS', 'hr');
};

const showIncoming = (pub) => {
  const p = G._PEERS[pub]; if (!p) return;
  const av = document.getElementById('incAv');
  if (av) {
    av.textContent = p.name[0].toUpperCase();
    av.style.background = `${p.color}22`;
    av.style.color = p.color;
  }
  const nm = document.getElementById('incName');
  if (nm) { nm.textContent = p.name; nm.style.color = p.color; }
  document.getElementById('incoming').classList.add('show');
};

const startCall = async (peerPub) => {
  const peer = G._PEERS[peerPub];
  if (!peer?.kyberPk) { alert('Peer key missing. Send a text message first.'); return; }
  _callPeer = peerPub; _callState = 'calling';
  showCallScreen(peerPub, 'Calling...', 'ring');
  const pcm = new PCManager(true);
  window.PCM = pcm;
  await pcm.init(peerPub, true);
  
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    _localStream = stream;
    stream.getTracks().forEach(t => pcm.pc.addTrack(t, stream));
  } catch (err) {
    console.error('Mic access failed', err);
  }
  
  const offer = await pcm.pc.createOffer();
  await pcm.pc.setLocalDescription(offer);
  await waitForGathering(pcm.pc, 6000);
  const sdp = sanitizeSDP(pcm.pc.localDescription.sdp);
  await nostrPub(peerPub, peer.kyberPk, { type: 'offer', from: G._NK.pub, sdp, kyberPk: G._KKkeys.pk }, 25050);
  setCallSt('Waiting for answer... (TURN)', 'ring');
  
  // Timeout if no answer in 45s
  setTimeout(() => {
    if (_callState === 'calling') {
      setCallSt('No answer', 'err');
      setTimeout(() => endCall(), 2000);
    }
  }, 45000);
};

const startCallFromChat = () => { if (G.AP) startCall(G.AP); };

const answerCall = async () => {
  document.getElementById('incoming').classList.remove('show');
  if (!_pendingOffer) return;
  const { sdp, from } = _pendingOffer; _pendingOffer = null;
  _callPeer = from; _callState = 'connecting';
  showCallScreen(from, 'Answering...', 'ring');
  const peer = G._PEERS[from];
  const pcm = new PCManager(true);
  window.PCM = pcm;
  await pcm.init(from, true);
  await pcm.setRemote(new RTCSessionDescription({ type: 'offer', sdp }));
  
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    _localStream = stream;
    stream.getTracks().forEach(t => pcm.pc.addTrack(t, stream));
  } catch (err) {
    console.error('Mic access failed', err);
  }
  
  const answer = await pcm.pc.createAnswer();
  await pcm.pc.setLocalDescription(answer);
  await waitForGathering(pcm.pc, 6000);
  const aSdp = sanitizeSDP(pcm.pc.localDescription.sdp);
  await nostrPub(from, peer.kyberPk, { type: 'answer', from: G._NK.pub, sdp: aSdp }, 25050);
  setCallSt('Connecting... (TURN)', 'ring');
};

const rejectCall = () => {
  document.getElementById('incoming').classList.remove('show');
  if (_pendingOffer?.from) {
    const p = G._PEERS[_pendingOffer.from];
    if (p?.kyberPk) nostrPub(_pendingOffer.from, p.kyberPk, { type: 'reject', from: G._NK.pub }, 25050).catch(() => { });
  }
  _pendingOffer = null;
};

const endCall = () => {
  if (_callPeer && G._PEERS[_callPeer]?.kyberPk && _callState !== 'idle') {
    nostrPub(_callPeer, G._PEERS[_callPeer].kyberPk, { type: 'end', from: G._NK.pub }, 25050).catch(() => { });
  }
  if (window.PCM) { window.PCM.close(); window.PCM = null; }
  if (_localStream) { _localStream.getTracks().forEach(t => t.stop()); _localStream = null; }
  _callPeer = null; _callState = 'idle';
  goContacts();
};

G.onIncomingCall = async (obj) => {
  const { from } = obj;
  const peer = G._PEERS[from];
  if (!peer) {
    G._PEERS[from] = { name: from.slice(0, 10), color: 'var(--pq)', kyberPk: obj.kyberPk || '' };
    localStorage.setItem('rl5_peers', JSON.stringify(G._PEERS));
    renderContacts();
  }
  if (_callState !== 'idle') {
    if (from !== _callPeer) showIncoming(from);
    return;
  }
  _pendingOffer = { sdp: obj.sdp, from: from };
  showIncoming(from);
};

G.onCallAnswer = () => {
  _callState = 'connecting';
  setCallSt('ICE gathering...', 'ring');
};

G.onCallReject = () => {
  setCallSt('Rejected', 'err');
  setTimeout(() => endCall(), 1500);
};

G.onCallEnd = () => {
  endCall();
};

G.onRemoteStream = (stream) => {
  _remoteAudio = new Audio();
  _remoteAudio.srcObject = stream;
  _remoteAudio.play();
  setCallSt('Connected (Secure)', 'conn');
  _callState = 'connected';
};

const toggleMute = () => {
  if (!_localStream) return;
  const t = _localStream.getAudioTracks()[0];
  t.enabled = !t.enabled;
  const btn = document.getElementById('muteBtn');
  btn.classList.toggle('on', !t.enabled);
  btn.textContent = t.enabled ? '🎙' : '🔇';
};

const toggleSpk = () => {
  const btn = document.getElementById('spkBtn');
  btn.classList.toggle('on');
  // Browser speaker toggle is limited, usually just UI feedback or setSinkId if supported
};

const copyBundle = async () => {
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
const openFP = async (peerPub) => {
  if (!peerPub || !G._PEERS[peerPub]) return;
  _fpCurrentPeer = peerPub;
  const peer = G._PEERS[peerPub];
  const hash = await computeFP(peerPub); if (!hash) return;
  const emojis = fpToEmojis(hash);
  const hexStr = fpToHex(hash);
  const verified = peer.fpVerified === hexStr;

  const emojiDiv = document.getElementById('fpEmojis');
  if (emojiDiv) emojiDiv.innerHTML = emojis.map(e => `<div class="fp-em">${e}</div>`).join('');
  
  const hexEl = document.getElementById('fpHex');
  if (hexEl) hexEl.textContent = hexStr;
  
  const statusEl = document.getElementById('fpStatus');
  const verifyBtn = document.getElementById('fpVerifyBtn');
  
  if (verified) {
    if (statusEl) statusEl.innerHTML = `<div class="fp-ok">✓ Verified. Connection is secure.</div>`;
    if (verifyBtn) {
      verifyBtn.textContent = '✓ Verified';
      verifyBtn.style.background = 'var(--b2)';
    }
  } else {
    if (statusEl) statusEl.innerHTML = `<div class="fp-warn">⚠ Not verified. Compare with peer!</div>`;
    if (verifyBtn) {
      verifyBtn.textContent = '✓ Verify';
      verifyBtn.style.background = 'var(--grn)';
    }
  }
  
  const subEl = document.getElementById('fpSubtitle');
  if (subEl) subEl.innerHTML = `Compare these emojis with <b>${peer.name}</b>.`;
  
  const modal = document.getElementById('fpModal');
  if (modal) modal.classList.add('show');
};

const closeFP = () => { document.getElementById('fpModal').classList.remove('show'); _fpCurrentPeer = null; };
const confirmVerify = async () => {
  if (!_fpCurrentPeer) return;
  const peer = G._PEERS[_fpCurrentPeer]; if (!peer) return;
  const hash = await computeFP(_fpCurrentPeer); if (!hash) return;
  peer.fpVerified = fpToHex(hash);
  localStorage.setItem('rl5_peers', JSON.stringify(G._PEERS));
  updateFPBtn(_fpCurrentPeer);
  closeFP(); renderContacts();
};

function updateFPBtn(peerPub) {
  const btn = document.getElementById('fpBtn'); if (!btn) return;
  const peer = G._PEERS[peerPub]; if (!peer) return;
  if (!peer.kyberPk) { btn.className = 'fp-btn'; return; }
  if (peer.fpVerified) { btn.className = 'fp-btn verified'; btn.textContent = '✓'; }
  else { btn.className = 'fp-btn unverified'; btn.textContent = '⚠'; }
}

// ── TTL UI ──

const openTTL = () => {
  const ttl = parseInt(localStorage.getItem('rl6_ttl_' + G.AP) || '0');
  ['0', '3600', '86400', '604800'].forEach(v => {
    const el = document.getElementById('ttlSel' + v);
    if (el) el.textContent = (v === String(ttl / 1000)) ? '✓' : '—';
  });
  document.getElementById('ttlModal').classList.add('show');
};
const closeTTL = () => document.getElementById('ttlModal').classList.remove('show');
const setTTL = (sec) => {
  localStorage.setItem('rl6_ttl_' + G.AP, String(sec * 1000));
  updateTTLBtn(); closeTTL();
};
const setDisappearing = (val) => {
  localStorage.setItem('rl6_ttl_global', val);
};
function updateTTLBtn() {
  const btn = document.getElementById('ttlBtn'); if (!btn) return;
  const ttl = parseInt(localStorage.getItem('rl6_ttl_' + G.AP) || '0');
  btn.className = ttl > 0 ? 'ttl-btn on' : 'ttl-btn';
  const bar = document.getElementById('dmBar');
  if (ttl > 0) { bar.classList.add('on'); bar.textContent = '⏱ Messages vanish after ' + TTL_LABELS[ttl / 1000]; }
  else { bar.classList.remove('on'); }
}

// ── Emergency Wipe UI ──

let _wipeTimer = null, _wipeStart = 0;
const showWipeModal = () => document.getElementById('wipeModal').classList.add('show');
const hideWipeModal = () => { cancelWipeHold(); document.getElementById('wipeModal').classList.remove('show'); };

const startWipeHold = (e) => {
  if (e) e.preventDefault();
  _wipeStart = Date.now();
  document.getElementById('wipeBar').style.transition = 'width 3s linear';
  document.getElementById('wipeBar').style.width = '100%';
  _wipeTimer = setTimeout(async () => {
    localStorage.clear(); sessionStorage.clear();
    document.getElementById('wipeHint').textContent = 'DESTROYING...';
    document.getElementById('wipeBtn').style.background = 'var(--red)';
    setTimeout(() => location.reload(), 1500);
  }, 3000);
};

const cancelWipeHold = () => {
  clearTimeout(_wipeTimer);
  document.getElementById('wipeBar').style.transition = 'none';
  document.getElementById('wipeBar').style.width = '0%';
};

// ── Event Helpers ──

const sl = (id, cls) => { const el = document.getElementById(id); if (el) el.className = 'screen ' + cls; };
const na = (id) => { document.querySelectorAll('.nb').forEach(b => b.classList.remove('act')); const el = document.getElementById(id); if (el) el.classList.add('act'); };

// ── PIN Global Exposure ──
// Mapping imported PIN functions directly to window object
window.pKey = pinKey;
window.pDel = pinDel;
window.tBio = tryBiometric;

// ── Start ──
document.addEventListener('DOMContentLoaded', boot);
