import { hex, fhex, rnd } from '../utils.js';
import { pqEncBin, kemE, aesEncGCM } from '../crypto/mlkem.js';
import { idbSave } from '../storage/crdt.js';
import { nostrPub } from './nostr.js';
import { renderMsgs } from '../ui/render.js';
import { uploadToIPFS } from './ipfs.js';

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
      sdpSemantics: 'unified-plan',
    };
    this.pc = new RTCPeerConnection(cfg);

    if (withAudio) {
      this.pc.ontrack = e => { if (G.onRemoteStream) G.onRemoteStream(e.streams[0]); };
    }

    if (!withAudio) {
      this.dc = this.pc.createDataChannel('media', { ordered: true, maxRetransmits: 30 });
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
export const inTransfers = {};
// dcQ and processDCQ are deprecated in favor of IPFS media sending
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
    const onCand = e => {
      if (e.candidate?.type === 'relay' && !hasRelay) { hasRelay = true; setTimeout(done, 500); }
    };
    pc.addEventListener('icegatheringstatechange', onState);
    pc.addEventListener('icecandidate', onCand);
    setTimeout(done, timeout);
  });
}

export async function onDCMsg(msg, peerPub) {
  // Legacy P2P signaling/media messages
  if (msg.type === 'key_rotate') {
    if (G.handleKeyRotate) G.handleKeyRotate(peerPub, msg);
  } else if (msg.type === 'key_rotate_resp') {
    if (G.handleKeyRotateResp) G.handleKeyRotateResp(peerPub, msg);
  }
}

async function processDCQ() {
  if (processDCQ._running) return;
  processDCQ._running = true;
  let retries = 0;
  while (dcQ.length) {
    const item = dcQ[0];
    const ok = await ensureDC(item.peerPub);
    if (ok && PCM?.dcOpen() && PCM.peer === item.peerPub) {
      retries = 0;
      dcQ.shift();
      await _dcSendFile(item);
    } else {
      retries++;
      console.warn('DC not ready for', item.peerPub, '(attempt', retries + ')');
      if (retries >= 3) {
        console.warn('Giving up on DC for', item.peerPub, 'after 3 attempts');
        dcQ.shift();
        retries = 0;
      } else {
        await new Promise(r => setTimeout(r, 3000));
        if (!dcQ.length) break;
      }
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
  console.log(`Sending file: ${file.name}, total chunks: ${total}, tid: ${tid}`);
  if (item.localOp) { item.localOp.payload._prog = 0.01; renderMsgs(); }
  try {
    PCM.dc.send(JSON.stringify({ type: 'tstart', tid, total, name: file.name, size: file.size, mime: file.type, dur: file._duration || 0 }));
  } catch (e) { console.warn('Send tstart failed', e); return; }

  for (let i = 0; i < total; i++) {
    if (!PCM?.dcOpen()) {
      console.warn('DC closed during transfer', tid);
      break;
    }
    
    // Low-tech backpressure
    if (PCM.dc.bufferedAmount > 1 * 1024 * 1024) {
      await new Promise(r => {
        let count = 0;
        const check = () => {
          if (!PCM?.dcOpen()) { r(); return; }
          if (PCM.dc.bufferedAmount < 256 * 1024 || count > 100) r();
          else { count++; setTimeout(check, 50); }
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

    if (item.localOp) { item.localOp.payload._prog = (i + 1) / total; }
    if (G.AP === peerPub) renderMsgs();
    
    // Safety yield every 10 chunks
    if (i % 10 === 0) await new Promise(r => setTimeout(r, 0));
  }
  const op = G._C.ops.find(o => o.id === tid);
  if (op) { delete op.payload._prog; renderMsgs(); }
  else if (item.localOp) { delete item.localOp.payload._prog; renderMsgs(); }
}

export async function ensureDC(peerPub) {
  // WebRTC Data Channel is no longer used for media but might be used for future low-latency signaling
  if (PCM?.dcOpen() && PCM.peer === peerPub) return true;
  const peer = G._PEERS[peerPub]; if (!peer?.kyberPk) return false;

  // Close stale connection
  if (PCM) { try { PCM.close(); } catch { } PCM = null; }

  PCM = new PCManager(false);
  await PCM.init(peerPub, false);

  const offer = await PCM.pc.createOffer();
  await PCM.pc.setLocalDescription(offer);
  await waitForGathering(PCM.pc, 8000);
  const sdp = sanitizeSDP(PCM.pc.localDescription?.sdp || offer.sdp);
  await nostrPub(peerPub, peer.kyberPk, { type: 'dc_offer', from: G._NK.pub, sdp }, 25050);

  // Wait up to 30s for DC to open
  return new Promise(resolve => {
    const check = setInterval(() => {
      if (PCM?.dcOpen() && PCM.peer === peerPub) { clearInterval(check); clearTimeout(tout); resolve(true); }
    }, 300);
    const tout = setTimeout(() => {
      clearInterval(check);
      console.warn('ensureDC timeout');
      resolve(false);
    }, 30000);
  });
}

export function addToDCQ(item) { dcQ.push(item); processDCQ(); }

export async function sendMedia(peerPub, file) {
  const peer = G._PEERS[peerPub];
  if (!peer?.kyberPk) { alert('Peer key missing. Send a text message first.'); return; }
  const MAX_FILE_SIZE = 100 * 1024 * 1024; // Increased for IPFS (100MB)
  if (file.size > MAX_FILE_SIZE) { alert('File too large. Max 100MB'); return; }

  const mt = file.type.startsWith('image') ? 'image' : file.type.startsWith('audio') ? 'voice' : 'file';
  const tid = hex(rnd(16));
  const ab = await file.arrayBuffer();
  const data = new Uint8Array(ab);

  // 1. Create local CRDT op for UI
  const localOp = G._C.add(mt, {
    _bytes: data, name: file.name, size: file.size,
    mimeType: file.type, duration: file._duration || 0, _prog: 0.05
  }, peerPub);
  localOp.id = tid;
  idbSave(tid, data, file.type);
  G._C._save();
  renderMsgs();

  try {
    // 2 & 4. Hybrid Local Crypto & PQC Encapsulation
    const { ct: kemCiphertext, K: rawAesKey } = kemE(peer.kyberPk);
    const { iv, ct: encryptedHex } = await aesEncGCM(rawAesKey, data);
    const mediaBin = fhex(encryptedHex);

    // 3. API Ingestion: Send to Crust Cloud
    localOp.payload._prog = 0.2; renderMsgs();
    const cid = await uploadToIPFS(mediaBin, file.name + '.bin');
    localOp.payload._prog = 0.8; renderMsgs();

    // 5. Nostr Transit: Send CID + ML-KEM Ciphertext + metadata
    const payload = {
      type: 'ipfs_media',
      id: tid,
      cid: cid,
      kem: kemCiphertext,
      iv: iv,
      mime: file.type,
      name: file.name,
      size: file.size,
      dur: file._duration || 0
    };

    await nostrPub(peerPub, peer.kyberPk, payload, 4);

    delete localOp.payload._prog;
    renderMsgs();
  } catch (e) {
    console.error('IPFS Media Send Fail', e);
    localOp.payload._prog = undefined;
    localOp.payload._failed = true;
    renderMsgs();
  }
}

export function setPCM(val) { PCM = val; }
