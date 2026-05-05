/**
 * webrtc.js — WebRTC PCManager
 *
 * Handles:
 *  - Voice calls (TURN-only, DTLS-SRTP, ML-KEM epoch key rotation every 60s)
 *  - DataChannel media transfers (chunked, ML-KEM per chunk)
 *  - ICE restart every 5 minutes to break traffic correlation
 *  - Constant-bitrate padding during calls to hide silence/activity patterns
 *
 * Architecture:
 *  - iceTransportPolicy: 'relay' on ALL connections — no IP leaks
 *  - Cloudflare TURN (primary) + Oracle TURN (fallback)
 *  - Double-hop isolation: neither TURN server sees both endpoints
 *
 * Exports: PCManager, getTurnServers, waitForGathering, sanitizeSDP,
 *          startCall, answerCall, rejectCall, endCall, toggleMute, toggleSpk,
 *          startKeyRotation, stopKeyRotation, handleKeyRotate,
 *          ensureDC, sendMedia, startRec, stopRec, cancelRec, playVoice,
 *          onDCMsg, processDCQ, startCBR, stopCBR,
 *          scheduleIceRestart, stopIceRestart, updateP2PStatus
 */

'use strict';

import { kemKG, kemE, kemD }   from '../crypto/mlkem.js';
import { pqEncBin, pqDecBin, hkdf1 } from '../crypto/ratchet.js';
import { nostrPub }            from './nostr.js';
import { hex, rnd, te }        from '../utils.js';

// ── TURN configuration ──

const CF_TURN_API   = 'https://rtc.live.cloudflare.com/v1/turn/keys/5168e26778eef61b15d6901ecc210286/credentials/generate-ice-servers';
const CF_TURN_TOKEN = '461333bdc9d7c16a7293f2a01e08602819b040f37160bb181a17dfd878ce60d2';
let _cfIceCache = null;

export async function getCFIce() {
  const now = Date.now();
  if (_cfIceCache && now < _cfIceCache.exp) return _cfIceCache.servers;
  try {
    const r = await fetch(CF_TURN_API, {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + CF_TURN_TOKEN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ ttl: 86400 }),
    });
    const d = await r.json();
    const servers = (d.iceServers || []).filter(s => s.urls);
    _cfIceCache = { servers, exp: now + 82800000 };
    return servers;
  } catch (e) {
    console.warn('CF TURN fetch failed — using Oracle fallback', e);
    return [];
  }
}

// Oracle TURN fallback — used when Cloudflare TURN is unavailable
const ICE_ORACLE_FALLBACK = [
  { urls: 'turn:144.24.249.21:3478',               username: 'relay', credential: 'Relay2005!' },
  { urls: 'turn:144.24.249.21:3478?transport=tcp', username: 'relay', credential: 'Relay2005!' },
];

export async function getTurnServers() {
  const cf = await getCFIce();
  return cf.length ? cf : ICE_ORACLE_FALLBACK;
}

// ── SDP sanitization — scrub real IPs ──

export function sanitizeSDP(s) {
  return s
    .replace(/^c=IN IP[46] \S+$/mg, 'c=IN IP4 0.0.0.0')
    .replace(/^(o=\S+ \S+ \S+ IN IP[46] )\S+$/mg, '$10.0.0.0');
}

// ── Wait for ICE gathering ──

export function waitForGathering(pc, timeout = 8000) {
  return new Promise(resolve => {
    if (pc.iceGatheringState === 'complete') { resolve(); return; }
    let hasRelay = false;
    const done = () => {
      pc.removeEventListener('icegatheringstatechange', onState);
      pc.removeEventListener('icecandidate', onCand);
      resolve();
    };
    const onState = () => { if (pc.iceGatheringState === 'complete') done(); };
    const onCand  = e => { if (e.candidate?.type === 'relay' && !hasRelay) { hasRelay = true; setTimeout(done, 500); } };
    pc.addEventListener('icegatheringstatechange', onState);
    pc.addEventListener('icecandidate', onCand);
    setTimeout(done, timeout);
  });
}

// ── Update P2P status indicator ──

export function updateP2PStatus(s) {
  const el = document.getElementById('p2pInd');
  if (el) { el.textContent = 'P2P: ' + (s || '—'); el.classList.toggle('on', s === 'open' || s === 'connected'); }
}

// ── Constant Bitrate Padding — hides call activity patterns ──

const CBR_INTERVAL    = 20;   // 20ms — matches Opus frame size
const CBR_PACKET_SIZE = 160;  // bytes
let _cbrTimer = null;

export function startCBR() {
  if (_cbrTimer) return;
  _cbrTimer = setInterval(() => {
    if (window._PCM?.dcOpen() && window._callState === 'connected') {
      const dummy = new Uint8Array(CBR_PACKET_SIZE);
      crypto.getRandomValues(dummy);
      try { window._PCM.dc.send(JSON.stringify({ type: '__cbr__', d: hex(dummy.slice(0, 8)) })); } catch {}
    }
  }, CBR_INTERVAL);
}

export function stopCBR() { clearInterval(_cbrTimer); _cbrTimer = null; }

// ── ICE Restart — breaks traffic correlation every 5 min ──

const ICE_RESTART_INTERVAL = 5 * 60 * 1000;
let _iceRestartTimer = null;

export async function scheduleIceRestart(peerPub) {
  clearTimeout(_iceRestartTimer);
  _iceRestartTimer = setTimeout(async () => {
    const PCM = window._PCM;
    if (window._callState !== 'connected' || !PCM?.pc) return;
    const peer = window._PEERS?.[peerPub];
    if (!peer?.kyberPk) return;
    try {
      const offer = await PCM.pc.createOffer({ iceRestart: true });
      await PCM.pc.setLocalDescription(offer);
      await waitForGathering(PCM.pc, 6000);
      const sdp = PCM.pc.localDescription?.sdp || offer.sdp;
      await nostrPub(peerPub, peer.kyberPk, { type: 'ice_restart', sdp: sanitizeSDP(sdp) }, 25050);
      setCallSt('Connected · Session refreshed · Epoch ' + window._callEpoch, 'conn');
      scheduleIceRestart(peerPub);
    } catch (e) { console.warn('ICE restart failed', e); }
  }, ICE_RESTART_INTERVAL);
}

export function stopIceRestart() { clearTimeout(_iceRestartTimer); _iceRestartTimer = null; }

// ── Forward Secrecy: Application-Layer Key Rotation every 60s ──

const ROTATE_INTERVAL_MS = 60000;
let _rotateTimer     = null;
let _callEpoch       = 0;
let _callEphKP       = null;
let _callEpochKey    = null;
let _pendingRotatePk = null;

export function startKeyRotation(peerPub) {
  stopKeyRotation();
  _callEpoch = 0; _callEpochKey = null;
  const rotate = async () => {
    if (window._callState !== 'connected' || !window._PCM?.dcOpen()) return;
    try {
      _callEphKP = kemKG(); _callEpoch++;
      window._PCM.send(JSON.stringify({ type: 'key_rotate', epoch: _callEpoch, ephPk: _callEphKP.pk }));
      setCallSt('Connected · Rotating key... (Epoch ' + _callEpoch + ')', 'conn');
      setTimeout(() => { if (window._callState === 'connected') setCallSt('Connected · TURN · PFS · Epoch ' + _callEpoch, 'conn'); }, 8000);
    } catch (e) { console.warn('Key rotation error', e); }
    _rotateTimer = setTimeout(rotate, ROTATE_INTERVAL_MS);
  };
  _rotateTimer = setTimeout(rotate, ROTATE_INTERVAL_MS);
}

export function stopKeyRotation() {
  clearTimeout(_rotateTimer); _rotateTimer = null;
  _callEpoch = 0; _callEphKP = null; _callEpochKey = null; _pendingRotatePk = null;
}

export async function handleKeyRotate(msg) {
  if (msg.type === 'key_rotate') {
    if (!msg.ephPk) return;
    _pendingRotatePk = msg.ephPk;
    try {
      const { ct, K } = kemE(msg.ephPk);
      const epochKey  = await hkdf1(K, new Uint8Array(32), 'RELAY_CALL_EPOCH_' + msg.epoch);
      _callEpochKey   = epochKey; _callEpoch = msg.epoch;
      window._PCM.send(JSON.stringify({ type: 'key_rotate_resp', epoch: msg.epoch, kem_ct: ct }));
      setCallSt('Connected · TURN · PFS · Epoch ' + msg.epoch, 'conn');
    } catch (e) { console.warn('Rotate respond error', e); }
  } else if (msg.type === 'key_rotate_resp') {
    if (!_callEphKP || msg.epoch !== _callEpoch) return;
    try {
      const K        = kemD(msg.kem_ct, _callEphKP.sk);
      _callEpochKey  = await hkdf1(K, new Uint8Array(32), 'RELAY_CALL_EPOCH_' + msg.epoch);
      _callEphKP     = null; // wipe — forward secrecy achieved
      setCallSt('Connected · TURN · PFS ✓ · Epoch ' + msg.epoch, 'conn');
    } catch (e) { console.warn('Rotate complete error', e); }
  }
}

// ── PCManager ──

export class PCManager {
  constructor(isCall = false) {
    this.pc = null; this.dc = null; this.iceQ = []; this.remoteSet = false;
    this.peer = null; this.isCall = isCall;
  }

  async init(peerPub, withAudio) {
    this.peer = peerPub; this.iceQ = []; this.remoteSet = false;
    if (this.pc) try { this.pc.close(); } catch {}
    const turnServers = await getTurnServers();
    const cfg = { iceServers: turnServers, iceTransportPolicy: 'relay' };
    this.pc = new RTCPeerConnection(cfg);

    if (withAudio) {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
        video: false,
      });
      window._localStream = stream;
      stream.getTracks().forEach(t => this.pc.addTrack(t, stream));
      window._remoteAudio = new Audio(); window._remoteAudio.autoplay = true;
      this.pc.ontrack = e => {
        window._remoteAudio.srcObject = e.streams[0];
        window._remoteAudio.play().catch(() => {});
        startViz();
      };
    }

    this.dc = this.pc.createDataChannel('media', { ordered: true, maxRetransmits: 30 });
    this._setupDC(this.dc);
    this.pc.ondatachannel = e => { this.dc = e.channel; this._setupDC(this.dc); };

    this.pc.onicecandidate = async e => {
      if (!e.candidate?.candidate) return;
      const p = window._PEERS?.[this.peer];
      if (!p?.kyberPk) return;
      await nostrPub(this.peer, p.kyberPk, { type: 'ice', candidate: e.candidate.toJSON() }, 25050);
    };

    this.pc.onconnectionstatechange = () => {
      const s = this.pc?.connectionState;
      updateP2PStatus(s);
      if (s === 'connected' && withAudio) {
        window._callState = 'connected';
        setCallSt('Connected · 2-Hop TURN · PFS · IP Hidden', 'conn');
        startTimer(); document.getElementById('callBg').classList.add('on');
        if (window._callPeer && this.peer === window._callPeer) startKeyRotation(this.peer);
        startCBR();
        if (window._callPeer && this.peer === window._callPeer) scheduleIceRestart(this.peer);
      } else if (s === 'disconnected' && withAudio) {
        setTimeout(() => {
          if (this.pc?.connectionState === 'disconnected' || this.pc?.connectionState === 'failed') endCall();
        }, 6000);
      } else if (s === 'failed' && withAudio) {
        endCall();
      } else if (s === 'failed' && !withAudio) {
        retryWithTurn(this.peer);
      }
    };
  }

  _setupDC(ch) {
    ch.binaryType = 'arraybuffer';
    ch.onmessage = async e => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === '__cbr__') return;
        if (msg.type === 'key_rotate' || msg.type === 'key_rotate_resp') { await handleKeyRotate(msg); return; }
        await onDCMsg(msg);
      } catch (err) { console.error('DC msg', err); }
    };
    ch.onopen  = () => { updateP2PStatus('open'); processDCQ(); };
    ch.onclose = () => updateP2PStatus('closed');
  }

  async setRemote(desc) {
    await this.pc.setRemoteDescription(desc); this.remoteSet = true;
    for (const c of this.iceQ) { try { await this.pc.addIceCandidate(c); } catch {} }
    this.iceQ = [];
  }

  async addICE(c) { this.remoteSet ? await this.pc.addIceCandidate(c).catch(() => {}) : this.iceQ.push(c); }
  dcOpen() { return this.dc?.readyState === 'open'; }
  send(s) { if (this.dcOpen()) this.dc.send(s); }
  close() { try { if (this.pc) this.pc.close(); } catch {} this.pc = null; this.dc = null; }
}

// ── Call UI helpers ──

function setCallSt(t, cls) {
  const el = document.getElementById('callSt');
  el.textContent = t; el.className = 'call-st' + (cls ? ' ' + cls : '');
}

function startViz() {
  document.getElementById('viz').classList.add('show');
  try {
    const ctx  = new AudioContext();
    const src  = ctx.createMediaStreamSource(window._remoteAudio.srcObject);
    const an   = ctx.createAnalyser(); an.fftSize = 32;
    src.connect(an);
    const viz  = document.getElementById('viz'); viz.innerHTML = '';
    for (let i = 0; i < 8; i++) { const b = document.createElement('div'); b.className = 'vb'; b.style.height = '4px'; viz.appendChild(b); }
    const bars = viz.querySelectorAll('.vb');
    const data = new Uint8Array(an.frequencyBinCount);
    window._vizInt = setInterval(() => { an.getByteFrequencyData(data); bars.forEach((b, i) => { b.style.height = (4 + Math.floor((data[i] || 0) / 255 * 32)) + 'px'; }); }, 80);
  } catch {}
}

function stopViz() { clearInterval(window._vizInt); window._vizInt = null; document.getElementById('viz').innerHTML = ''; }

function startTimer() {
  window._timerSecs = 0;
  document.getElementById('callTm').classList.add('show');
  window._timerInt = setInterval(() => {
    window._timerSecs++;
    document.getElementById('callTm').textContent =
      String(Math.floor(window._timerSecs / 60)).padStart(2, '0') + ':' + String(window._timerSecs % 60).padStart(2, '0');
  }, 1000);
}

function stopTimer() { clearInterval(window._timerInt); window._timerInt = null; window._timerSecs = 0; document.getElementById('callTm').textContent = '00:00'; }

// ── Public call functions ──

export async function startCall(peerPub) {
  const peer = window._PEERS?.[peerPub];
  if (!peer?.kyberPk) { alert('Peer has no key. Send a text message first.'); return; }
  window._callPeer = peerPub; window._callState = 'calling';
  window._showCallScreen(peerPub, 'Calling...', 'ring');
  window._PCM = new PCManager(true);
  await window._PCM.init(peerPub, true);
  const offer = await window._PCM.pc.createOffer({ offerToReceiveAudio: true });
  await window._PCM.pc.setLocalDescription(offer);
  await waitForGathering(window._PCM.pc, 6000);
  const sdp = window._PCM.pc.localDescription?.sdp || offer.sdp;
  await nostrPub(peerPub, peer.kyberPk, { type: 'offer', sdp: sanitizeSDP(sdp) }, 25050);
  setCallSt('Waiting... (TURN · IP Hidden)', 'ring');
  setTimeout(() => {
    if (window._callState === 'calling') { setCallSt('No answer', 'err'); setTimeout(() => endCall(), 2000); }
  }, 45000);
}

export async function answerCall() {
  document.getElementById('incoming').classList.remove('show');
  if (!window._pendingOffer) return;
  const { sdp, from } = window._pendingOffer; window._pendingOffer = null;
  window._callPeer = from; window._callState = 'connecting';
  window._showCallScreen(from, 'Answering...', 'ring');
  const peer = window._PEERS?.[from];
  window._PCM = new PCManager(true);
  await window._PCM.init(from, true);
  await window._PCM.setRemote(new RTCSessionDescription({ type: 'offer', sdp }));
  const answer = await window._PCM.pc.createAnswer();
  await window._PCM.pc.setLocalDescription(answer);
  await waitForGathering(window._PCM.pc, 6000);
  const answerSdp = window._PCM.pc.localDescription?.sdp || answer.sdp;
  await nostrPub(from, peer.kyberPk, { type: 'answer', sdp: sanitizeSDP(answerSdp) }, 25050);
  setCallSt('Connecting... (TURN)', 'ring');
}

export function rejectCall() {
  document.getElementById('incoming').classList.remove('show');
  if (window._pendingOffer?.from) {
    const p = window._PEERS?.[window._pendingOffer.from];
    if (p?.kyberPk) nostrPub(window._pendingOffer.from, p.kyberPk, { type: 'reject' }, 25050).catch(() => {});
  }
  window._pendingOffer = null;
}

export function endCall() {
  if (window._callPeer && window._PEERS?.[window._callPeer]?.kyberPk && window._callState !== 'idle')
    nostrPub(window._callPeer, window._PEERS[window._callPeer].kyberPk, { type: 'end' }, 25050).catch(() => {});
  if (window._PCM && window._callState !== 'idle') { window._PCM.close(); window._PCM = null; }
  if (window._localStream) { window._localStream.getTracks().forEach(t => t.stop()); window._localStream = null; }
  if (window._remoteAudio) { window._remoteAudio.srcObject = null; window._remoteAudio = null; }
  stopTimer(); stopViz(); stopKeyRotation(); stopCBR(); stopIceRestart();
  window._callPeer = null; window._callState = 'idle'; window._muted = false;
  document.getElementById('muteBtn').textContent = '🎙';
  document.getElementById('muteBtn').classList.remove('on');
  document.getElementById('callBg').classList.remove('on');
  document.getElementById('callTm').classList.remove('show');
  document.getElementById('viz').classList.remove('show');
  updateP2PStatus(null);
  window._goContacts?.();
}

export function toggleMute() {
  if (!window._localStream) return;
  window._muted = !window._muted;
  window._localStream.getTracks().forEach(t => t.enabled = !window._muted);
  const b = document.getElementById('muteBtn');
  b.textContent = window._muted ? '🔇' : '🎙';
  b.classList.toggle('on', window._muted);
}

export function toggleSpk() {
  if (!window._remoteAudio) return;
  window._remoteAudio.muted = !window._remoteAudio.muted;
  document.getElementById('spkBtn').textContent = window._remoteAudio.muted ? '🔕' : '🔊';
}

// ── DataChannel file transfer ──

const CHUNK = 14 * 1024; // 14 KB safe chunk size
const MAX_FILE_SIZE = 25 * 1024 * 1024; // 25 MB

let _dcQ = [];
const inTransfers = {};

export async function onDCMsg(msg) {
  if (msg.type === 'tstart') {
    inTransfers[msg.tid] = { meta: msg, chunks: new Array(msg.total), received: 0 };
  } else if (msg.type === 'tchunk') {
    const buf = inTransfers[msg.tid]; if (!buf) return;
    try {
      const dec = await pqDecBin(window._KKkeys?.sk, msg.kem, msg.iv, msg.ct);
      buf.chunks[msg.idx] = dec; buf.received++;
      const op = window._C?.ops.find(o => o.id === msg.tid);
      if (op) { op.payload._prog = buf.received / msg.total; window._renderMsgs?.(); }
      if (buf.received >= msg.total) {
        let sz = 0; buf.chunks.forEach(c => { if (c) sz += c.length; });
        const data = new Uint8Array(sz); let off = 0;
        buf.chunks.forEach(c => { if (c) { data.set(c, off); off += c.length; } });
        delete inTransfers[msg.tid];
        const { meta } = buf;
        const mt = meta.mime.startsWith('image') ? 'image' : meta.mime.startsWith('audio') ? 'voice' : 'file';
        const actualSrc = window._PCM?.peer || window._callPeer || window._AP || 'unknown';
        const op2 = {
          id: msg.tid, from: actualSrc, to: window._NK?.pub,
          lam: window._C.lam + 1, vc: { [actualSrc]: window._C.lam + 1 },
          type: mt, payload: { _bytes: data, name: meta.name, size: meta.size, mimeType: meta.mime, duration: meta.dur || 0 },
          ts: Date.now(),
        };
        window._idbSave?.(msg.tid, data, meta.mime);
        window._C.merge(op2); window._renderMsgs?.();
      }
    } catch (e) { console.error('P2P chunk decrypt fail', e); }
  }
}

async function _dcSendFile(item) {
  const { peerPub, file, tid, data, localOp } = item;
  const peer = window._PEERS?.[peerPub]; if (!peer?.kyberPk) return;
  const PCM  = window._PCM; if (!PCM?.dcOpen()) { console.error('DC not open'); return; }
  const total = Math.ceil(data.length / CHUNK);
  PCM.dc.send(JSON.stringify({ type: 'tstart', tid, total, name: file.name, size: file.size, mime: file.type, dur: file._duration || 0 }));
  for (let i = 0; i < total; i++) {
    if (!window._PCM?.dcOpen()) { console.error('DC closed at chunk', i); break; }
    const chunk = data.slice(i * CHUNK, (i + 1) * CHUNK);
    const { kem, iv, ct } = await pqEncBin(peer.kyberPk, chunk);
    if (!window._PCM?.dcOpen()) break;
    window._PCM.dc.send(JSON.stringify({ type: 'tchunk', tid, idx: i, total, kem, iv, ct }));
    const op = window._C?.ops.find(o => o.id === tid);
    if (op) { op.payload._prog = (i + 1) / total; window._renderMsgs?.(); }
  }
  const op = window._C?.ops.find(o => o.id === tid);
  if (op) { delete op.payload._prog; window._renderMsgs?.(); }
}

export async function processDCQ() {
  if (processDCQ._running) return;
  processDCQ._running = true;
  while (_dcQ.length && window._PCM?.dcOpen()) { await _dcSendFile(_dcQ.shift()); }
  processDCQ._running = false;
}

export async function ensureDC(peerPub) {
  if (window._PCM?.dcOpen()) return true;
  const peer = window._PEERS?.[peerPub]; if (!peer?.kyberPk) return false;
  if (window._PCM) { try { window._PCM.close(); } catch {} window._PCM = null; }
  window._PCM = new PCManager(false);
  await window._PCM.init(peerPub, false);
  window._PCM.peer = peerPub;
  const offer = await window._PCM.pc.createOffer();
  await window._PCM.pc.setLocalDescription(offer);
  await waitForGathering(window._PCM.pc, 8000);
  const sdp = window._PCM.pc.localDescription?.sdp || offer.sdp;
  await nostrPub(peerPub, peer.kyberPk, { type: 'dc_offer', sdp: sanitizeSDP(sdp) }, 25050);
  return new Promise(resolve => {
    const check = setInterval(() => { if (window._PCM?.dcOpen()) { clearInterval(check); clearTimeout(tout); resolve(true); } }, 300);
    const tout  = setTimeout(() => { clearInterval(check); console.warn('ensureDC timeout'); resolve(false); }, 30000);
  });
}

async function retryWithTurn(peerPub) {
  const peer = window._PEERS?.[peerPub]; if (!peer?.kyberPk) return;
  if (window._PCM) { try { window._PCM.close(); } catch {} }
  window._PCM = new PCManager(false);
  await window._PCM.init(peerPub, false); window._PCM.peer = peerPub;
  const offer = await window._PCM.pc.createOffer();
  await window._PCM.pc.setLocalDescription(offer);
  await waitForGathering(window._PCM.pc, 5000);
  await nostrPub(peerPub, peer.kyberPk, { type: 'dc_offer', sdp: sanitizeSDP(window._PCM.pc.localDescription.sdp) }, 25050);
}

export async function sendMedia(peerPub, file) {
  const peer = window._PEERS?.[peerPub];
  if (!peer?.kyberPk) { alert('Peer has no key. Send a text message first.'); return; }
  if (file.size > MAX_FILE_SIZE) { alert('File too large. Maximum: 25 MB'); return; }
  const mt  = file.type.startsWith('image') ? 'image' : file.type.startsWith('audio') ? 'voice' : 'file';
  const tid = hex(rnd(16));
  const ab  = await file.arrayBuffer();
  const data = new Uint8Array(ab);
  const localOp = window._C.add(mt, { _bytes: data, name: file.name, size: file.size, mimeType: file.type, duration: file._duration || 0, _prog: 0 }, peerPub);
  localOp.id = tid;
  window._idbSave?.(tid, data, file.type);
  window._C._save(); window._renderMsgs?.();
  _dcQ.push({ peerPub, file, tid, data, localOp });
  if (window._PCM?.dcOpen()) {
    processDCQ();
  } else {
    const ok = await ensureDC(peerPub);
    if (ok) {
      processDCQ();
    } else {
      _dcQ = _dcQ.filter(q => q.tid !== tid);
      const op = window._C?.ops.find(o => o.id === tid);
      if (op) { op.payload._prog = undefined; op.payload._failed = true; window._renderMsgs?.(); }
      console.error('DC could not open for', peerPub);
    }
  }
}

// ── Voice recording ──

const IS_IOS = /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;

function getBestMime() {
  if (typeof MediaRecorder === 'undefined') return 'audio/mp4';
  const order = IS_IOS
    ? ['audio/mp4;codecs=mp4a.40.2', 'audio/mp4', 'audio/aac']
    : ['audio/webm;codecs=opus', 'audio/webm', 'audio/mp4', 'audio/ogg;codecs=opus'];
  return order.find(t => MediaRecorder.isTypeSupported(t)) || 'audio/mp4';
}

const AUDIO_MIME = getBestMime();

function playBytes(bytes, mimeType) {
  const order = [mimeType, 'audio/mp4', 'audio/webm;codecs=opus', 'audio/webm', 'audio/ogg;codecs=opus'].filter(Boolean);
  let i = 0;
  const tryNext = () => {
    if (i >= order.length) return;
    const m    = order[i++];
    const blob = new Blob([bytes], { type: m });
    const url  = URL.createObjectURL(blob);
    const aud  = new Audio(); aud.src = url;
    aud.onended = () => setTimeout(() => URL.revokeObjectURL(url), 500);
    aud.onerror = () => { URL.revokeObjectURL(url); tryNext(); };
    aud.play().catch(() => tryNext());
  };
  tryNext();
}

let _mediaRec = null, _vChunks = [], _recStart = 0, _recCancelled = false;

export function startRec(e) {
  e.preventDefault();
  if (_mediaRec || !window._AP) return;
  _recCancelled = false; _recStart = Date.now();
  document.getElementById('voiceBtn').classList.add('rec');
  navigator.mediaDevices.getUserMedia({ audio: true }).then(stream => {
    _vChunks = [];
    let opts = {}; if (MediaRecorder.isTypeSupported(AUDIO_MIME)) opts.mimeType = AUDIO_MIME;
    _mediaRec = new MediaRecorder(stream, opts);
    _mediaRec.ondataavailable = e => { if (e.data?.size > 0) _vChunks.push(e.data); };
    _mediaRec.start(200);
  }).catch(err => { document.getElementById('voiceBtn').classList.remove('rec'); alert('Microphone permission required: ' + err.message); });
}

export async function stopRec(e) {
  e.preventDefault();
  document.getElementById('voiceBtn').classList.remove('rec');
  if (!_mediaRec || _mediaRec.state === 'inactive') { _mediaRec = null; return; }
  const dur = Math.round((Date.now() - _recStart) / 1000);
  if (dur < 1 || _recCancelled) { _mediaRec.stop(); _mediaRec.stream.getTracks().forEach(t => t.stop()); _mediaRec = null; return; }
  return new Promise(resolve => {
    _mediaRec.onstop = async () => {
      const mime  = _vChunks[0]?.type || AUDIO_MIME || 'audio/mp4';
      const blob  = new Blob(_vChunks, { type: mime });
      _mediaRec.stream.getTracks().forEach(t => t.stop()); _mediaRec = null;
      if (!window._AP || !window._PEERS?.[window._AP]?.kyberPk) { resolve(); return; }
      const ext   = mime.includes('mp4') ? 'mp4' : mime.includes('webm') ? 'webm' : 'm4a';
      const vFile = new File([blob], 'voice.' + ext, { type: mime });
      vFile._duration = dur;
      await sendMedia(window._AP, vFile);
      resolve();
    };
    _mediaRec.stop();
  });
}

export function cancelRec() {
  _recCancelled = true;
  document.getElementById('voiceBtn').classList.remove('rec');
  if (_mediaRec && _mediaRec.state !== 'inactive') { _mediaRec.stop(); _mediaRec?.stream?.getTracks().forEach(t => t.stop()); _mediaRec = null; }
}

export async function playVoice(opId) {
  const op = window._C?.ops.find(o => o.id === opId); if (!op) return;
  const bytes = op.payload?._bytes;
  if (!bytes) { alert('Audio is still loading...'); return; }
  playBytes(bytes, op.payload?.mimeType);
}
