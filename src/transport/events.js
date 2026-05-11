/**
 * events.js — Incoming Nostr event dispatcher
 * Matches original single-file onEv exactly.
 */

'use strict';

import { kemD }                                  from '../crypto/mlkem.js';
import { aesDec, yieldUI }                       from '../crypto/ratchet.js';
import { answerCall, endCall, waitForGathering,
         sanitizeSDP, PCManager, processDCQ }    from '../transport/webrtc.js';
import { markOnline }                            from '../transport/onion.js';
import { nostrPub }                              from '../transport/nostr.js';
import { ktRecord }                              from '../ui/settings.js';
import { renderContacts, renderMsgs, showBadge } from '../ui/render.js';
import { hex, td }                               from '../utils.js';

// ── Replay protection ──
const _seen = new Set();
function isReplay(ev) {
  if (_seen.has(ev.id)) return true;
  _seen.add(ev.id);
  if (_seen.size > 2000) { const f = _seen.values().next().value; _seen.delete(f); }
  return false;
}

// ── unpadPlain ──
function unpadPlain(bytes) {
  try {
    const rlen = new DataView(bytes.buffer, bytes.byteOffset, 2).getUint16(0);
    if (rlen > 0 && rlen <= bytes.length - 2)
      return new TextDecoder().decode(bytes.slice(2, 2 + rlen));
  } catch {}
  return new TextDecoder().decode(bytes);
}

// ── Peer helpers ──
function savePeers() {
  localStorage.setItem('rl5_peers', JSON.stringify(window._PEERS));
}

const COLS = ['#e8ff00','#00aaff','#00ff88','#ff5588','#ff9900','#cc44ff'];

function registerPeer(sn, sk) {
  const PEERS = window._PEERS, NK = window._NK;
  if (!sn || !sk || sn === NK?.pub) return;
  if (!PEERS[sn]) {
    PEERS[sn] = { name: sn.slice(0, 10), color: COLS[Object.keys(PEERS).length % COLS.length], kyberPk: sk, lastRead: 0 };
    savePeers(); renderContacts(); ktRecord(sn, null, sk, 'key_first');
  } else {
    if (!PEERS[sn].kyberPk) {
      PEERS[sn].kyberPk = sk; savePeers(); ktRecord(sn, null, sk, 'key_first');
    } else if (PEERS[sn].kyberPk !== sk) {
      ktRecord(sn, PEERS[sn].kyberPk, sk, 'key_changed');
      PEERS[sn].kyberPk = sk; PEERS[sn].fpVerified = null; savePeers();
      setTimeout(() => alert('⚠ KEY CHANGE: ' + (PEERS[sn]?.name || sn.slice(0,10)) + '\nMay be MITM. Re-verify fingerprint!'), 500);
    } else {
      ktRecord(sn, PEERS[sn].kyberPk, sk, 'key_ok');
    }
  }
}

// ── Onion relay forward ──
async function handleOnionRelay(layer) {
  const next = layer.next, nextPeer = window._PEERS?.[next];
  if (!next || !nextPeer?.kyberPk) return;
  const { genNKP, buildEv } = await import('../crypto/secp256k1.js');
  const ephNK = genNKP();
  const ev = await buildEv(4, layer.ct, [['p', next]], ephNK.priv, ephNK.pub);
  Object.values(window._WS || {}).forEach(ws => { if (ws.readyState === 1) ws.send(JSON.stringify(['EVENT', ev])); });
}

// ── Merge message into CRDT ──
function mergeMsg(obj, fp) {
  const C = window._C, NK = window._NK;
  if (!obj?.id || !obj?.type) return;
  if (obj.type === '__pad__' || obj.type === '__hb__') return;
  if (fp === NK?.pub) return;
  obj.from = fp;
  if (fp && fp !== NK?.pub) markOnline(fp);
  if (!C?.merge(obj)) return;
  if (window._AP === fp) renderMsgs();
  else { renderContacts(); showBadge(); }
  // Disappearing messages
  const dis = window._disappearMs;
  if (dis > 0) setTimeout(() => {
    C.ops = C.ops.filter(o => o.id !== obj.id);
    C._save(); renderContacts();
    if (window._AP === fp) renderMsgs();
  }, dis);
}

// ── Main event handler — matches original onEv exactly ──
export async function onEv(ev) {
  const KKkeys = window._KKkeys;
  if (!KKkeys?.sk) return;
  if (isReplay(ev)) return;

  // NOTE: NO tags filter here — sealed sender uses ephemeral pubkey,
  // so we must attempt decrypt regardless (matches original)
  const NK = window._NK; if (!NK) return;

  let str, realSenderPub = ev.pubkey;
  try {
    const parsed = JSON.parse(ev.content);

    // v:5 — heartbeat
    if (parsed.v === 5 && ev.kind === 4) {
      try {
        const raw = await aesDec(kemD(parsed.kem, KKkeys.sk), parsed.iv, parsed.ct);
        const ping = JSON.parse(td(raw));
        if (ping.from && ping.from !== NK.pub) markOnline(ping.from);
      } catch {}
      return;
    }

    // v:6 — onion routing
    if (parsed.v === 6 && ev.kind === 4) {
      try {
        const raw = await aesDec(kemD(parsed.kem, KKkeys.sk), parsed.iv, parsed.ct);
        const layer = JSON.parse(td(raw));
        if (layer.type === 'onion_relay') {
          await handleOnionRelay(layer); return;
        }
        if (layer.type === 'onion_final') {
          try {
            const innerParsed = JSON.parse(layer.payload);
            if (innerParsed.v === 4 || innerParsed.v === 3) {
              const outerBytes = await aesDec(kemD(innerParsed.kem, KKkeys.sk), innerParsed.iv, innerParsed.ct);
              let msgStr;
              try {
                const rlen = new DataView(outerBytes.buffer, outerBytes.byteOffset, 2).getUint16(0);
                if (rlen > 0 && rlen <= outerBytes.length - 2) msgStr = unpadPlain(outerBytes);
              } catch {}
              if (!msgStr) msgStr = td(outerBytes);
              const obj = JSON.parse(msgStr);
              if (!obj.id || !obj.type || obj.type === '__pad__') return;
              if (obj._sender?.nostr && obj._sender?.kyber) registerPeer(obj._sender.nostr, obj._sender.kyber);
              const fp = obj._sender?.nostr || ev.pubkey;
              if (fp === NK.pub) return;
              mergeMsg(obj, fp);
            }
          } catch (e) { console.warn('Onion final error', e); }
          return;
        }
      } catch (e) { console.warn('Onion error', e); }
      return;
    }

    // v:4 — padded message
    if (parsed.v === 4 && ev.kind === 4) {
      try {
        const raw = await aesDec(kemD(parsed.kem, KKkeys.sk), parsed.iv, parsed.ct);
        let decrypted;
        try {
          if (raw.length >= 2) {
            const rlen = new DataView(raw.buffer, raw.byteOffset, 2).getUint16(0);
            if (rlen > 0 && rlen <= raw.length - 2) decrypted = unpadPlain(raw);
          }
        } catch {}
        if (!decrypted) decrypted = td(raw);
        str = decrypted;
      } catch { return; }
    }
    // v:3 — legacy/signaling, no padding
    else if (parsed.v === 3) {
      try {
        const raw = await aesDec(kemD(parsed.kem, KKkeys.sk), parsed.iv, parsed.ct);
        str = td(raw);
      } catch { return; }
    }
    else { return; }

  } catch { return; }

  let obj; try { obj = JSON.parse(str); } catch { return; }

  const fp = obj._sender?.nostr || realSenderPub;
  if (fp === NK.pub) return;

  // Register/update peer
  if (obj._sender?.nostr && obj._sender?.kyber) registerPeer(obj._sender.nostr, obj._sender.kyber);

  // Legacy kyber tag
  const kyberTag = ev.tags?.find(t => t[0] === 'kyber' && t[1]?.length > 100);
  if (kyberTag && fp && !window._PEERS?.[fp]?.kyberPk) {
    const PEERS = window._PEERS;
    if (!PEERS[fp]) PEERS[fp] = { name: fp.slice(0,10), color: COLS[Object.keys(PEERS).length % COLS.length], kyberPk: kyberTag[1], lastRead: 0 };
    else PEERS[fp].kyberPk = kyberTag[1];
    savePeers();
  }

  // kind:4 — chat message
  if (ev.kind === 4) {
    if (!obj.id || !obj.type) return;
    if (obj.type === '__pad__') return;
    obj.from = fp;
    if (fp && fp !== NK.pub) markOnline(fp);

    // Deniable auth check (matches original — drops if invalid)
    try {
      const { verifyDeniable } = await import('../transport/padding.js');
      const daResult = await verifyDeniable(obj, fp);
      if (daResult === false) { console.warn('DA: invalid auth tag from', fp?.slice(0,8)); return; }
    } catch {}

    // WebRTC signaling via kind:4
    if (['offer','answer','ice','reject','end','ice_restart','dc_offer','dc_answer'].includes(obj.type)) {
      await handleSignaling(obj, fp); return;
    }

    mergeMsg(obj, fp);
  }
  // kind:25050 — WebRTC signaling
  else if (ev.kind === 25050) {
    await handleSignaling(obj, fp);
  }
}

// ── Signaling handler ──
async function handleSignaling(payload, from) {
  const type = payload.type;
  const peer = window._PEERS?.[from];

  if (type === 'offer') {
    window._pendingOffer = { sdp: payload.sdp, from };
    document.getElementById('incName').textContent = peer?.name || from.slice(0, 12);
    document.getElementById('incoming').classList.add('show');
    markOnline(from); return;
  }
  if (type === 'dc_offer') {
    if (window._PCM) { try { window._PCM.close(); } catch {} }
    window._PCM = new PCManager(false);
    await window._PCM.init(from, false); window._PCM.peer = from;
    await window._PCM.setRemote(new RTCSessionDescription({ type: 'offer', sdp: payload.sdp }));
    const ans = await window._PCM.pc.createAnswer();
    await window._PCM.pc.setLocalDescription(ans);
    await waitForGathering(window._PCM.pc, 5000);
    if (peer?.kyberPk) await nostrPub(from, peer.kyberPk, { type: 'dc_answer', sdp: sanitizeSDP(window._PCM.pc.localDescription.sdp) }, 25050);
    return;
  }
  if (type === 'dc_answer') {
    if (window._PCM?.pc) await window._PCM.setRemote(new RTCSessionDescription({ type: 'answer', sdp: payload.sdp }));
    return;
  }
  if (type === 'answer') {
    if (window._PCM?.pc && window._callState === 'calling') {
      window._callState = 'connecting';
      setCallSt('Connecting... (TURN)', 'ring');
      await window._PCM.setRemote(new RTCSessionDescription({ type: 'answer', sdp: payload.sdp }));
    }
    return;
  }
  if (type === 'ice') {
    if (window._PCM?.pc && payload.candidate)
      await window._PCM.addICE(new RTCIceCandidate(payload.candidate)).catch(() => {});
    return;
  }
  if (type === 'ice_restart') {
    if (window._PCM?.pc && window._callState === 'connected') {
      await window._PCM.pc.setRemoteDescription(new RTCSessionDescription({ type: 'offer', sdp: payload.sdp }));
      const ans = await window._PCM.pc.createAnswer();
      await window._PCM.pc.setLocalDescription(ans);
      await waitForGathering(window._PCM.pc, 5000);
      if (peer?.kyberPk) await nostrPub(from, peer.kyberPk, { type: 'answer', sdp: sanitizeSDP(window._PCM.pc.localDescription.sdp) }, 25050);
    }
    return;
  }
  if (type === 'reject') {
    if (window._callState === 'calling') { setCallSt('Call declined', 'err'); setTimeout(() => endCall(), 2000); }
    return;
  }
  if (type === 'end') {
    if (window._callState !== 'idle') { setCallSt('Call ended', 'err'); setTimeout(() => endCall(), 1000); }
    return;
  }
}

function setCallSt(t, cls) {
  const el = document.getElementById('callSt');
  if (el) { el.textContent = t; el.className = 'call-st' + (cls ? ' ' + cls : ''); }
}
