import { td, te, hex } from '../utils.js';
import { kemD, aesDecGCM } from '../crypto/mlkem.js';
import { renderMsgs, renderContacts, showBadge } from '../ui/render.js';
import { markOnline, handleOnionRelay } from './onion.js';
import { nostrPub } from './nostr.js';
import { unpadPlain } from './padding.js';
import { PCM, sanitizeSDP, PCManager, setPCM, waitForGathering } from './webrtc.js';
import { fetchFromIPFS } from './ipfs.js';
import { idbSave } from '../storage/crdt.js';
import { verifyDeniable } from '../crypto/ratchet.js';
import { SHA3_256 } from '../crypto/sha3.js';
import { mldsaSign } from '../crypto/mldsa.js';

const G = window;

function isExpired(op) { return op._exp && Date.now() > op._exp; }

// Key Transparency Log
export let _ktLog = [];
const KT_LOG_KEY = 'rl6_kt_log';

export function ktLoad() {
  try { _ktLog = JSON.parse(localStorage.getItem(KT_LOG_KEY)) || []; } catch { _ktLog = []; }
}

export function ktSave() {
  try { localStorage.setItem(KT_LOG_KEY, JSON.stringify(_ktLog.slice(-200))); } catch { }
}

// Record a key event — signed with our ML-DSA key
export async function ktRecord(peerPub, oldKyberPk, newKyberPk, event = 'key_seen') {
  if (!G.MLDSAkeys) return;
  const entry = {
    ts: Date.now(),
    peer: peerPub,
    event,
    oldHash: oldKyberPk ? hex(SHA3_256(te(oldKyberPk))).slice(0, 16) : null,
    newHash: newKyberPk ? hex(SHA3_256(te(newKyberPk))).slice(0, 16) : null,
    n: _ktLog.length
  };
  // Sign the entry with ML-DSA
  try {
    const msg = JSON.stringify({ ts: entry.ts, peer: entry.peer, newHash: entry.newHash, n: entry.n });
    entry.sig = await mldsaSign(G.MLDSAkeys.sk, msg);
  } catch { }
  _ktLog.push(entry);
  ktSave();
}

// Check if a peer's key has changed — returns 'new'|'changed'|'same'
export function ktCheck(peerPub, kyberPk) {
  const entries = _ktLog.filter(e => e.peer === peerPub);
  if (!entries.length) return 'new';
  const last = entries[entries.length - 1];
  const newHash = hex(SHA3_256(te(kyberPk))).slice(0, 16);
  return last.newHash === newHash ? 'same' : 'changed';
}

export function ktRender() {
  const el = document.getElementById('ktLog'); if (!el) return;
  const entries = [..._ktLog].reverse().slice(0, 20);
  if (!entries.length) { el.innerHTML = '<div style="font-size:10px;color:var(--dim)">No records yet.</div>'; return; }
  el.innerHTML = entries.map(e => {
    const p = G._PEERS[e.peer]; const nm = p?.name || e.peer.slice(0, 10);
    const t = new Date(e.ts).toLocaleString('en-GB', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    const cls = e.event === 'key_changed' ? 'kt-warn' : e.event === 'key_first' ? 'kt-new' : 'kt-ok';
    const icon = e.event === 'key_changed' ? '⚠' : e.event === 'key_first' ? '🆕' : '✓';
    const msg = e.event === 'key_changed' ? '<b style="color:var(--red)">KEY CHANGED!</b>' : e.event === 'key_first' ? 'First Seen' : 'Key Confirmed';
    return `<div class="kt-entry ${cls}">
      <span style="color:var(--mut)">${t}</span> · <span style="color:var(--acc2)">${nm}</span><br>
      ${icon} ${msg}
      · <span style="color:var(--dim)">${e.newHash}</span>
    </div>`;
  }).join('');
}

const _seenIds = new Map();
const REPLAY_WINDOW_MS = 5 * 60 * 1000;
const REPLAY_CACHE_TTL = 10 * 60 * 1000;
const REPLAY_CACHE_MAX = 2000;

function _cleanReplayCache() {
  const cutoff = Date.now() - REPLAY_CACHE_TTL;
  for (const [id, ts] of _seenIds) {
    if (ts < cutoff) _seenIds.delete(id);
  }
}
setInterval(_cleanReplayCache, 60000);

export function isReplay(ev) {
  const now = Date.now();
  const evTs = ev.created_at * 1000;
  if (Math.abs(now - evTs) > REPLAY_WINDOW_MS) return true;
  if (!ev.id) return true;
  if (_seenIds.has(ev.id)) return true;
  if (_seenIds.size >= REPLAY_CACHE_MAX) _seenIds.delete(_seenIds.keys().next().value);
  _seenIds.set(ev.id, now);
  return false;
}

export async function onEv(ev) {
  if (!G._KKkeys) return;
  if (isReplay(ev)) return;
  let str, realFrom = ev.pubkey;
  try {
    const parsed = JSON.parse(ev.content);
    const fp = ev.pubkey;

    // Heartbeat ping (v:5)
    if (parsed.v === 5 && ev.kind === 4) {
      try {
        const raw = await aesDec(kemD(parsed.kem, G._KKkeys.sk), parsed.iv, parsed.ct);
        const ping = JSON.parse(td(raw));
        if (ping.from && ping.from !== G._NK.pub) markOnline(ping.from);
      } catch { }
      return;
    }

    // Onion packet (v:6)
    if (parsed.v === 6 && ev.kind === 4) {
      try {
        const raw = await aesDec(kemD(parsed.kem, G._KKkeys.sk), parsed.iv, parsed.ct);
        const layer = JSON.parse(td(raw));
        if (layer.type === 'onion_relay') {
          await handleOnionRelay(layer);
        } else if (layer.type === 'onion_final') {
          try {
            const innerParsed = JSON.parse(layer.payload);
            if (innerParsed.v === 4 || innerParsed.v === 3) {
              const outerBytes = await aesDec(kemD(innerParsed.kem, G._KKkeys.sk), innerParsed.iv, innerParsed.ct);
              let msgStr;
              try {
                if (outerBytes.length >= 2) {
                  const rlen = new DataView(outerBytes.buffer, outerBytes.byteOffset, 2).getUint16(0);
                  if (rlen > 0 && rlen <= outerBytes.length - 2) msgStr = unpadPlain(outerBytes);
                }
              } catch { }
              if (!msgStr) msgStr = td(outerBytes);

              let obj;
              try { obj = JSON.parse(msgStr); } catch { return; }
              
              if (obj.type === 'offer' || obj.type === 'answer' || obj.type === 'ice' || obj.type === 'dc_offer' || obj.type === 'dc_answer' || obj.type === 'reject' || obj.type === 'end' || obj.type === 'ice_restart' || obj.type === 'ice_restart_answer') {
                obj.from = fp;
                await handleSignaling(obj);
                return;
              }
              if (!obj.id || !obj.type || obj.type === '__pad__') return;
              
              if (obj._sender?.nostr && obj._sender?.kyber) {
                const sn = obj._sender.nostr; const sk = obj._sender.kyber;
                if (!G._PEERS[sn]) {
                  G._PEERS[sn] = { name: sn.slice(0, 10), color: 'var(--pq)', kyberPk: sk };
                  localStorage.setItem('rl5_peers', JSON.stringify(G._PEERS));
                  renderContacts();
                }
                markOnline(sn);
              }

              obj.from = fp;
              await verifyDeniable(obj, fp);
              if (G._C.merge(obj)) {
                if (G.AP === fp) renderMsgs();
                else { renderContacts(); showBadge(); }
              }
            }
          } catch (e) { console.warn('Onion final fail', e); }
        }
      } catch (e) { console.warn('Onion process fail', e); }
      return;
    }

    if (parsed.v === 4 && ev.kind === 4) {
      try {
        const raw = await aesDec(kemD(parsed.kem, G._KKkeys.sk), parsed.iv, parsed.ct);
        let decrypted;
        try {
          if (raw.length >= 2) {
            const rlen = new DataView(raw.buffer, raw.byteOffset, 2).getUint16(0);
            if (rlen > 0 && rlen <= raw.length - 2) decrypted = unpadPlain(raw);
          }
        } catch { }
        if (!decrypted) decrypted = td(raw);
        str = decrypted;
      } catch { return; }
    } else if (parsed.v === 3) {
      try {
        const raw = await aesDec(kemD(parsed.kem, G._KKkeys.sk), parsed.iv, parsed.ct);
        str = td(raw);
      } catch { return; }
    } else { return; }
  } catch { return; }

  let obj;
  try { obj = JSON.parse(str); } catch { return; }
  
  if (obj._sender?.nostr && obj._sender?.kyber) {
    const sn = obj._sender.nostr; const sk = obj._sender.kyber;
    if (!G._PEERS[sn]) {
      G._PEERS[sn] = { name: sn.slice(0, 10), color: 'var(--pq)', kyberPk: sk };
      localStorage.setItem('rl5_peers', JSON.stringify(G._PEERS));
      renderContacts();
    }
    markOnline(sn);
  }

  const realSender = obj._sender?.nostr || realFrom;
  if (realSender === G._NK.pub) return; // own message echoed back
  obj.from = realSender;
  if (ev.kind === 4 && realSender && realSender !== G._NK.pub) markOnline(realSender);
  await verifyDeniable(obj, realSender);

  if (obj.type === 'offer' || obj.type === 'answer' || obj.type === 'ice' || obj.type === 'dc_offer' || obj.type === 'dc_answer' || obj.type === 'reject' || obj.type === 'end' || obj.type === 'ice_restart' || obj.type === 'ice_restart_answer') {
    await handleSignaling(obj);
    return;
  }

  if (obj.type === 'ipfs_media') {
    await handleIPFSMedia(obj, realSender);
    return;
  }

  if (!obj.id || !obj.type || obj.type === '__pad__') return;
  if (isExpired(obj)) return;
  obj._nostrId = ev.id;
  if (G._C.merge(obj)) {
    if (G.AP === realSender) renderMsgs();
    else { renderContacts(); showBadge(); }
  }
}

async function handleSignaling(obj) {
  const { type, from } = obj;
  const peer = G._PEERS[from];

  if (type === 'offer') {
    if (!peer && obj.kyberPk) {
      G._PEERS[from] = { name: from.slice(0, 10), color: 'var(--pq)', kyberPk: obj.kyberPk };
      localStorage.setItem('rl5_peers', JSON.stringify(G._PEERS));
      renderContacts();
    }
    if (G.onIncomingCall) G.onIncomingCall(obj);
  } else if (type === 'answer' && PCM) {
    await PCM.setRemote(new RTCSessionDescription({ type: 'answer', sdp: obj.sdp })).catch(() => { });
    if (G.onCallAnswer) G.onCallAnswer();
  } else if (type === 'ice_restart' && PCM) {
    try {
      await PCM.setRemote(new RTCSessionDescription({ type: 'offer', sdp: obj.sdp }));
      const answer = await PCM.pc.createAnswer();
      await PCM.pc.setLocalDescription(answer);
      await waitForGathering(PCM.pc, 6000);
      if (peer?.kyberPk) {
        await nostrPub(from, peer.kyberPk, { type: 'ice_restart_answer', from: G._NK.pub, sdp: sanitizeSDP(PCM.pc.localDescription.sdp) }, 25050);
      }
    } catch (e) { console.warn('ICE restart fail', e); }
  } else if (type === 'ice_restart_answer' && PCM) {
    await PCM.setRemote(new RTCSessionDescription({ type: 'answer', sdp: obj.sdp })).catch(() => { });
  } else if (type === 'ice' && PCM) {
    await PCM.addICE(new RTCIceCandidate(obj.candidate)).catch(() => { });
  } else if (type === 'dc_offer') {
    if (!peer?.kyberPk) return;
    if (PCM) { try { PCM.close(); } catch { } }
    const pcm = new PCManager(false);
    setPCM(pcm);
    await pcm.init(from, false);
    await pcm.setRemote(new RTCSessionDescription({ type: 'offer', sdp: obj.sdp }));
    const answer = await pcm.pc.createAnswer();
    await pcm.pc.setLocalDescription(answer);
    await waitForGathering(pcm.pc, 8000);
    const sdp = sanitizeSDP(pcm.pc.localDescription.sdp);
    await nostrPub(from, peer.kyberPk, { type: 'dc_answer', from: G._NK.pub, sdp }, 25050);
  } else if (type === 'dc_answer' && PCM) {
    await PCM.setRemote(new RTCSessionDescription({ type: 'answer', sdp: obj.sdp })).catch(() => { });
  } else if (type === 'reject') {
    if (G.onCallReject) G.onCallReject();
  } else if (type === 'end') {
    if (G.onCallEnd) G.onCallEnd();
  }
}

async function handleIPFSMedia(msg, peerPub) {
  const mt = msg.mime.startsWith('image') ? 'image' : msg.mime.startsWith('audio') ? 'voice' : 'file';
  const op = {
    id: msg.id,
    from: peerPub,
    to: G._NK.pub,
    lam: G._C.lam + 1,
    vc: { ...G._C.vc, [peerPub]: G._C.lam + 1 },
    type: mt,
    payload: {
      name: msg.name,
      size: msg.size,
      mimeType: msg.mime,
      duration: msg.dur || 0,
      _prog: 0.01 // Mark as downloading
    },
    ts: Date.now()
  };

  if (G._C.merge(op)) {
    if (G.AP === peerPub) renderMsgs();
    else { renderContacts(); showBadge(); }
  }

  try {
    // 9. Background Pull: Fetch encrypted media.bin from IPFS
    const encryptedBin = await fetchFromIPFS(msg.cid);
    
    // 8. PQC Decapsulation: Use ML-KEM to extract aesKey
    const aesKey = kemD(msg.kem, G._KKkeys.sk);

    // 10. Local AES Decrypt: Decrypt media.bin on-device
    const decrypted = await aesDecGCM(aesKey, msg.iv, hex(encryptedBin));

    // 11. UI Rendering: Save to IDB and update CRDT
    idbSave(msg.id, decrypted, msg.mime);
    const savedOp = G._C.ops.find(o => o.id === msg.id);
    if (savedOp) {
      savedOp.payload._bytes = decrypted;
      delete savedOp.payload._prog;
      renderMsgs();
    }
  } catch (e) {
    console.error('IPFS Media download/decrypt fail', e);
    const savedOp = G._C.ops.find(o => o.id === msg.id);
    if (savedOp) {
      savedOp.payload._failed = true;
      delete savedOp.payload._prog;
      renderMsgs();
    }
  }
}
