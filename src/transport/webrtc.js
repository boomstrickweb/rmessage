import { hex, fhex, rnd } from '../utils.js';
import { pqEncBin, pqDecBin } from '../crypto/mlkem.js';
import { idbSave } from '../storage/crdt.js';
import { nostrPub } from './nostr.js';
import { renderMsgs } from '../ui/render.js';

const G = window;

// ── Cloudflare TURN ──
const CF_TURN_API = 'https://rtc.live.cloudflare.com/v1/turn/keys/5168e26778eef61b15d6901ecc210286/credentials/generate-ice-servers';
const CF_TURN_TOKEN = '461333bdc9d7c16a7293f2a01e08602819b040f37160bb181a17dfd878ce60d2';
let _cfIceCache = null;

async function getCFIce() {
  const now = Date.now();
  if (_cfIceCache && now < _cfIceCache.exp) return _cfIceCache.servers;
  try {
    const r = await fetch(CF_TURN_API, {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + CF_TURN_TOKEN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ ttl: 86400 })
    });
    const d = await r.json();
    const servers = (d.iceServers || []).filter(s => s.urls);
    _cfIceCache = { servers, exp: now + 82800000 };
    return servers;
  } catch (e) {
    console.warn('CF TURN fetch failed', e);
    return [];
  }
}

const ICE_ORACLE_FALLBACK = [
  { urls: 'turn:144.24.249.21:3478', username: 'relay', credential: 'Relay2005!' },
  { urls: 'turn:144.24.249.21:3478?transport=tcp', username: 'relay', credential: 'Relay2005!' },
];

async function getTurnServers() {
  const cfServers = await getCFIce();
  return cfServers.length ? cfServers : ICE_ORACLE_FALLBACK;
}

export class PCManager {
  constructor(isCall = false) {
    this.pc = null; this.dc = null; this.iceQ = []; this.remoteSet = false;
    this.peer = null; this.isCall = isCall;
  }
  async init(peerPub, withAudio) {
    this.peer = peerPub; this.iceQ = []; this.remoteSet = false;
    if (this.pc) try { this.pc.close(); } catch { }
    const turnServers = await getTurnServers();
    const cfg = { 
      iceServers: turnServers, 
      iceTransportPolicy: 'relay', 
      bundlePolicy: 'max-bundle', 
      rtcpMuxPolicy: 'require',
      sdpSemantics: 'unified-plan'
    };
    this.pc = new RTCPeerConnection(cfg);

    if (withAudio) {
      this.pc.ontrack = e => { if (G.onRemoteStream) G.onRemoteStream(e.streams[0]); };
      this.pc.addTransceiver('audio', { direction: 'sendrecv' });
    }

    if (!withAudio) {
      this.dc = this.pc.createDataChannel('media', { ordered: true });
      this._setupDC(this.dc);
    }
    
    this.pc.ondatachannel = e => { this.dc = e.channel; this._setupDC(this.dc); };
    this.pc.onicecandidate = async e => {
      if (!e.candidate || !e.candidate.candidate) return;
      const p = G._PEERS[this.peer]; if (!p?.kyberPk) return;
      nostrPub(this.peer, p.kyberPk, { type: 'ice', from: G._NK.pub, candidate: e.candidate.toJSON() }, 25050).catch(() => { });
    };
    this.pc.oniceconnectionstatechange = () => {
      if (this.pc?.iceConnectionState === 'failed') {
        // ICE restart logic could go here
      }
    };
    this.pc.onconnectionstatechange = () => {
      const s = this.pc?.connectionState;
      updateP2PStatus(s);
      if (G.onConnectionStateChange) G.onConnectionStateChange(s, withAudio, this.peer);
    };
  }
  _setupDC(ch) {
    ch.binaryType = 'arraybuffer';
    ch.onmessage = async e => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === '__cbr__') return;
        await onDCMsg(msg, this.peer);
      } catch (err) { console.error('DC msg', err); }
    };
    ch.onopen = () => { updateP2PStatus('open'); processDCQ(); };
    ch.onclose = () => updateP2PStatus('closed');
    ch.onerror = (e) => console.error('DC Error:', e);
  }
  async setRemote(desc) {
    if (!this.pc) return;
    await this.pc.setRemoteDescription(desc); this.remoteSet = true;
    for (const c of this.iceQ) { try { await this.pc.addIceCandidate(c); } catch { } }
    this.iceQ = [];
  }
  async addICE(c) { 
    if (!this.pc) return;
    this.remoteSet ? await this.pc.addIceCandidate(c).catch(() => { }) : this.iceQ.push(c); 
  }
  dcOpen() { return this.dc?.readyState === 'open'; }
  send(s) { if (this.dcOpen()) this.dc.send(s); }
  close() { try { if (this.pc) this.pc.close(); } catch { } this.pc = null; this.dc = null; }
}

export let PCM = null;
const inTransfers = {};
let dcQ = [];

function updateP2PStatus(s) {
  const el = document.getElementById('p2pInd');
  if (el) { el.textContent = 'P2P: ' + (s || '—'); el.classList.toggle('on', s === 'open' || s === 'connected'); }
}

export function sanitizeSDP(s) { return s.replace(/^c=IN IP[46] \S+$/mg, 'c=IN IP4 0.0.0.0').replace(/^(o=\S+ \S+ \S+ IN IP[46] )\S+$/mg, '$10.0.0.0'); }

export function waitForGathering(pc, timeout = 8000) {
  return new Promise(resolve => {
    if (pc.iceGatheringState === 'complete') { resolve(); return; }
    const done = () => {
      pc.removeEventListener('icegatheringstatechange', onState);
      pc.removeEventListener('icecandidate', onCand);
      resolve();
    };
    const onState = () => { if (pc.iceGatheringState === 'complete') done(); };
    let hasRelay = false;
    const onCand = e => { if (e.candidate?.type === 'relay' && !hasRelay) { hasRelay = true; setTimeout(done, 500); } };
    pc.addEventListener('icegatheringstatechange', onState);
    pc.addEventListener('icecandidate', onCand);
    setTimeout(done, timeout);
  });
}

export async function onDCMsg(msg, peerPub) {
  if (msg.type === 'tstart') { inTransfers[msg.tid] = { meta: msg, chunks: new Array(msg.total), received: 0 }; }
  else if (msg.type === 'tchunk') {
    const buf = inTransfers[msg.tid]; if (!buf) return;
    try {
      const dec = await pqDecBin(G._KKkeys.sk, msg.kem, msg.iv, msg.ct);
      buf.chunks[msg.idx] = dec; buf.received++;
      const op = G._C.ops.find(o => o.id === msg.tid);
      if (op) { op.payload._prog = buf.received / msg.total; renderMsgs(); }
      if (buf.received >= msg.total) {
        let sz = 0; buf.chunks.forEach(c => { if (c) sz += c.length; });
        const data = new Uint8Array(sz); let off = 0; buf.chunks.forEach(c => { if (c) { data.set(c, off); off += c.length; } });
        delete inTransfers[msg.tid];
        const { meta } = buf;
        const mt = meta.mime.startsWith('image') ? 'image' : meta.mime.startsWith('audio') ? 'voice' : 'file';
        const actualSrc = peerPub || 'unknown';
        const op2 = { id: msg.tid, from: actualSrc, to: G._NK.pub, lam: G._C.lam + 1, vc: { [actualSrc]: G._C.lam + 1 }, type: mt, payload: { _bytes: data, name: meta.name, size: meta.size, mimeType: meta.mime, duration: meta.dur || 0 }, ts: Date.now() };
        idbSave(msg.tid, data, meta.mime);
        G._C.merge(op2); renderMsgs();
      }
    } catch (e) { console.error('P2P decrypt fail', e); }
  } else if (msg.type === 'key_rotate') {
    if (G.handleKeyRotate) G.handleKeyRotate(peerPub, msg);
  } else if (msg.type === 'key_rotate_resp') {
    if (G.handleKeyRotateResp) G.handleKeyRotateResp(peerPub, msg);
  }
}

async function processDCQ() {
  if (processDCQ._running) return;
  processDCQ._running = true;
  while (dcQ.length) {
    const item = dcQ[0];
    const ok = await ensureDC(item.peerPub);
    if (ok && PCM?.dcOpen()) {
      dcQ.shift();
      await _dcSendFile(item);
    } else {
      console.warn('DC not ready for', item.peerPub);
      await new Promise(r => setTimeout(r, 5000));
      if (!dcQ.length) break;
    }
  }
  processDCQ._running = false;
}

const CHUNK = 14 * 1024;

async function _dcSendFile(item) {
  const { peerPub, file, tid, data } = item;
  const peer = G._PEERS[peerPub]; if (!peer?.kyberPk) return;
  if (!PCM?.dcOpen()) return;

  const total = Math.ceil(data.length / CHUNK);
  try {
    PCM.dc.send(JSON.stringify({ type: 'tstart', tid, total, name: file.name, size: file.size, mime: file.type, dur: file._duration || 0 }));
  } catch (e) { console.warn('Send tstart failed', e); return; }

  for (let i = 0; i < total; i++) {
    if (!PCM?.dcOpen()) break;
    
    // Low-tech backpressure
    if (PCM.dc.bufferedAmount > 2 * 1024 * 1024) {
      await new Promise(r => {
        const check = () => {
          if (!PCM?.dcOpen()) { r(); return; }
          if (PCM.dc.bufferedAmount < 512 * 1024) r();
          else setTimeout(check, 100);
        };
        check();
      });
    }

    const chunk = data.slice(i * CHUNK, (i + 1) * CHUNK);
    const { kem, iv, ct } = await pqEncBin(peer.kyberPk, chunk);
    if (!PCM?.dcOpen()) break;
    
    try {
      PCM.dc.send(JSON.stringify({ type: 'tchunk', tid, idx: i, total, kem, iv, ct }));
    } catch (e) { console.warn('Send tchunk failed', e); break; }

    const op = G._C.ops.find(o => o.id === tid);
    if (op) { op.payload._prog = (i + 1) / total; renderMsgs(); }
    else if (item.localOp) { item.localOp.payload._prog = (i + 1) / total; renderMsgs(); }
    
    // Safety yield
    if (i % 5 === 0) await new Promise(r => setTimeout(r, 0));
  }
  const op = G._C.ops.find(o => o.id === tid);
  if (op) { delete op.payload._prog; renderMsgs(); }
  else if (item.localOp) { delete item.localOp.payload._prog; renderMsgs(); }
}

export async function ensureDC(peerPub) {
  if (PCM?.dcOpen() && PCM.peer === peerPub) return true;
  if (PCM) { try { PCM.close(); } catch { } PCM = null; }
  PCM = new PCManager(false);
  await PCM.init(peerPub, false);
  const offer = await PCM.pc.createOffer();
  await PCM.pc.setLocalDescription(offer);
  await waitForGathering(PCM.pc, 8000);
  const sdp = sanitizeSDP(PCM.pc.localDescription.sdp);
  const p = G._PEERS[peerPub]; if (!p?.kyberPk) return false;
  await nostrPub(peerPub, p.kyberPk, { type: 'dc_offer', from: G._NK.pub, sdp }, 25050);
  return new Promise(res => {
    let t = setTimeout(() => { clearInterval(i); res(false); }, 30000);
    let i = setInterval(() => { if (PCM?.dcOpen()) { clearTimeout(t); clearInterval(i); res(true); } }, 200);
  });
}

export function addToDCQ(item) { dcQ.push(item); processDCQ(); }

export async function sendMedia(peerPub, file) {
  const peer = G._PEERS[peerPub];
  if (!peer?.kyberPk) { alert('Peer key missing. Send a text message first.'); return; }
  const MAX_FILE_SIZE = 25 * 1024 * 1024;
  if (file.size > MAX_FILE_SIZE) { alert('File too large. Max 25MB'); return; }

  const mt = file.type.startsWith('image') ? 'image' : file.type.startsWith('audio') ? 'voice' : 'file';
  const tid = hex(rnd(16));
  const ab = await file.arrayBuffer();
  const data = new Uint8Array(ab);
  
  const localOp = G._C.add(mt, {
    _bytes: data, name: file.name, size: file.size,
    mimeType: file.type, duration: file._duration || 0, _prog: 0
  }, peerPub);
  localOp.id = tid;
  idbSave(tid, data, file.type);
  renderMsgs();

  addToDCQ({ peerPub, file, tid, data, localOp });
}

export function setPCM(val) { PCM = val; }
