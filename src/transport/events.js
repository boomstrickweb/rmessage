/**
 * events.js — Incoming Nostr event dispatcher
 *
 * Decrypts incoming events: v:3 (signaling/legacy), v:4 (padded messages),
 * v:5 (heartbeat), v:6 (onion routing).
 * Routes to: chat messages, WebRTC signaling, onion relay forwarding,
 *            heartbeats, dummy/padding events (silently dropped).
 *
 * Matches the original single-file implementation exactly.
 *
 * Exports: onEv
 */

'use strict';

import { kemD }                                     from '../crypto/mlkem.js';
import { aesDec, yieldUI }                          from '../crypto/ratchet.js';
import { answerCall, endCall, waitForGathering,
         sanitizeSDP, PCManager, processDCQ }       from '../transport/webrtc.js';
import { markOnline }                               from '../transport/onion.js';
import { nostrPub }                                 from '../transport/nostr.js';
import { verifyDeniable }                           from '../transport/padding.js';
import { ktRecord }                                 from '../ui/settings.js';
import { renderContacts, renderMsgs, showBadge }    from '../ui/render.js';
import { hex }                                      from '../utils.js';

const _seen = new Set();
const COLS = ['#e8ff00','#00aaff','#00ff88','#ff5588','#ff9900','#cc44ff'];

// ── unpadPlain helper (matches original) ──
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

function autoRegisterPeer(nostrPub, kyberPk) {
  const PEERS = window._PEERS;
  const NK    = window._NK;
  if (!nostrPub || !kyberPk || nostrPub === NK?.pub) return;
  if (!PEERS[nostrPub]) {
    PEERS[nostrPub] = {
      name: nostrPub.slice(0, 10),
      color: COLS[Object.keys(PEERS).length % COLS.length],
      kyberPk, lastRead: 0,
    };
    savePeers(); renderContacts(); ktRecord(nostrPub, null, kyberPk, 'key_first');
  } else {
    const peer = PEERS[nostrPub];
    if (!peer.kyberPk) {
      peer.kyberPk = kyberPk; savePeers();
      ktRecord(nostrPub, null, kyberPk, 'key_first');
    } else if (peer.kyberPk !== kyberPk) {
      ktRecord(nostrPub, nostrPub && window._PEERS?.[nostrPub]?.kyberPk, kyberPk, 'key_changed');
      peer.kyberPk = kyberPk; peer.fpVerified = null; savePeers();
      setTimeout(() => alert(
        '⚠ KEY CHANGE DETECTED for ' + (peer.name || nostrPub.slice(0, 10)) +
        '!\nThis may be a MITM attack.\nPlease re-verify the fingerprint.'
      ), 500);
    }
  }
  markOnline(nostrPub);
}

// ── Onion relay forwarding ──
async function handleOnionRelay(layer) {
  const next     = layer.next;
  const nextPeer = window._PEERS?.[next];
  if (!next || !nextPeer?.kyberPk) return;
  const { genNKP, buildEv } = await import('../crypto/secp256k1.js');
  const ephNK = genNKP();
  const ev = await buildEv(4, layer.ct, [['p', next]], ephNK.priv, ephNK.pub);
  Object.values(window._WS || {}).forEach(ws => {
    if (ws.readyState === 1) ws.send(JSON.stringify(['EVENT', ev]));
  });
}

// ── Process a decrypted chat message object (async for deniable auth) ──
async function processMsg(obj, fromPub) {
  const NK = window._NK;
  const C  = window._C;
  if (!obj?.id || !obj?.type) return;
  if (obj.type === '__pad__' || obj.type === '__hb__') return;
  if (fromPub === NK?.pub) return; // own message echoed back
  obj.from = fromPub;
  markOnline(fromPub);

  // Verify deniable auth tag (matches original — drops if invalid/tampered)
  try {
    const { verifyDeniable } = await import('../transport/padding.js');
    const daResult = await verifyDeniable(obj, fromPub);
    if (daResult === false) {
      console.warn('DA: invalid auth tag from', fromPub?.slice(0, 8));
      return; // drop tampered message
    }
  } catch {}

  if (!C) return;
  if (!C.merge(obj)) return;
  if (window._AP === fromPub) renderMsgs();
  else { renderContacts(); showBadge(); }
  // Disappearing messages
  const dis = window._disappearMs;
  if (dis > 0) {
    setTimeout(() => {
      C.ops = C.ops.filter(o => o.id !== obj.id);
      C._save(); renderContacts();
      if (window._AP === fromPub) renderMsgs();
    }, dis);
  }
}

// ── Main event handler ──
export async function onEv(ev) {
  if (_seen.has(ev.id)) return;
  _seen.add(ev.id);
  if (_seen.size > 1000) { const first = _seen.values().next().value; _seen.delete(first); }

  const NK     = window._NK;   if (!NK) return;
  const KKkeys = window._KKkeys; if (!KKkeys?.sk) return;

  // Filter: only process events addressed to us
  if (!ev.tags?.some(t => t[0] === 'p' && t[1] === NK.pub)) return;

  let parsed;
  try { parsed = JSON.parse(ev.content); } catch { return; }
  if (!parsed?.kem) return;

  await yieldUI();

  // ── v:6 — Onion routing ──
  if (parsed.v === 6 && ev.kind === 4) {
    try {
      const raw   = await aesDec(kemD(parsed.kem, KKkeys.sk), parsed.iv, parsed.ct);
      const layer = JSON.parse(new TextDecoder().decode(raw));

      if (layer.type === 'onion_relay') {
        await handleOnionRelay(layer);
        return;
      }

      if (layer.type === 'onion_final') {
        try {
          const innerParsed = JSON.parse(layer.payload);
          if (innerParsed.v === 4 || innerParsed.v === 3) {
            const outerBytes = await aesDec(kemD(innerParsed.kem, KKkeys.sk), innerParsed.iv, innerParsed.ct);
            const msgStr     = unpadPlain(outerBytes);
            const obj        = JSON.parse(msgStr);
            if (obj._sender?.nostr) autoRegisterPeer(obj._sender.nostr, obj._sender.kyber);
            processMsg(obj, obj._sender?.nostr || ev.pubkey);
          }
        } catch (e) { console.warn('Onion final error', e); }
        return;
      }
    } catch (e) { console.warn('Onion v:6 error', e); }
    return;
  }

  // ── v:4 — Padded message (sealed sender) ──
  if (parsed.v === 4 && ev.kind === 4) {
    let str;
    try {
      const raw = await aesDec(kemD(parsed.kem, KKkeys.sk), parsed.iv, parsed.ct);
      str = unpadPlain(raw);
    } catch { return; }
    let obj; try { obj = JSON.parse(str); } catch { return; }

    const fp = obj._sender?.nostr || ev.pubkey;
    if (fp === NK.pub) return;

    // Auto-register peer
    if (obj._sender?.nostr) autoRegisterPeer(obj._sender.nostr, obj._sender.kyber);

    // Legacy kyber tag
    const kyberTag = ev.tags?.find(t => t[0] === 'kyber' && t[1]?.length > 100);
    if (kyberTag && fp) autoRegisterPeer(fp, kyberTag[1]);

    markOnline(fp);

    // Heartbeat / padding — drop after registering peer
    if (obj.type === '__hb__' || obj.type === '__pad__') return;

    // WebRTC signaling
    if (ev.kind === 25050 || ['offer','answer','ice','reject','end','ice_restart','dc_offer','dc_answer'].includes(obj.type)) {
      await handleSignaling(obj, fp);
      return;
    }

    processMsg(obj, fp);
    return;
  }

  // ── v:3 — Legacy / signaling (no padding) ──
  if (parsed.v === 3) {
    let str;
    try {
      const raw = await aesDec(kemD(parsed.kem, KKkeys.sk), parsed.iv, parsed.ct);
      str = new TextDecoder().decode(raw);
    } catch { return; }
    let obj; try { obj = JSON.parse(str); } catch { return; }

    const fp = obj._sender?.nostr || ev.pubkey;
    if (fp === NK.pub) return;
    if (obj._sender?.nostr) autoRegisterPeer(obj._sender.nostr, obj._sender.kyber);
    markOnline(fp);
    if (obj.type === '__hb__' || obj.type === '__pad__') return;

    if (ev.kind === 25050 || ['offer','answer','ice','reject','end','ice_restart','dc_offer','dc_answer'].includes(obj.type)) {
      await handleSignaling(obj, fp);
      return;
    }
    processMsg(obj, fp);
    return;
  }

  // ── v:5 — Heartbeat (simple AES-KEM, no padding) ──
  if (parsed.v === 5) {
    try {
      const raw = await aesDec(kemD(parsed.kem, KKkeys.sk), parsed.iv, parsed.ct);
      const obj = JSON.parse(new TextDecoder().decode(raw));
      if (obj.type === '__hb__' && obj.from) markOnline(obj.from);
    } catch {}
    return;
  }
}

// ── Signaling handler ──
async function handleSignaling(payload, from) {
  const NK   = window._NK;
  const type = payload.type;
  const peer = window._PEERS?.[from];

  if (type === 'offer') {
    window._pendingOffer = { sdp: payload.sdp, from };
    document.getElementById('incName').textContent = peer?.name || from.slice(0, 12);
    document.getElementById('incoming').classList.add('show');
    markOnline(from);
    return;
  }

  if (type === 'dc_offer') {
    if (window._PCM) { try { window._PCM.close(); } catch {} }
    window._PCM = new PCManager(false);
    await window._PCM.init(from, false);
    window._PCM.peer = from;
    await window._PCM.setRemote(new RTCSessionDescription({ type: 'offer', sdp: payload.sdp }));
    const answer = await window._PCM.pc.createAnswer();
    await window._PCM.pc.setLocalDescription(answer);
    await waitForGathering(window._PCM.pc, 5000);
    if (peer?.kyberPk)
      await nostrPub(from, peer.kyberPk, { type: 'dc_answer', sdp: sanitizeSDP(window._PCM.pc.localDescription.sdp) }, 25050);
    return;
  }

  if (type === 'dc_answer') {
    if (window._PCM?.pc)
      await window._PCM.setRemote(new RTCSessionDescription({ type: 'answer', sdp: payload.sdp }));
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
      const answer = await window._PCM.pc.createAnswer();
      await window._PCM.pc.setLocalDescription(answer);
      await waitForGathering(window._PCM.pc, 5000);
      if (peer?.kyberPk)
        await nostrPub(from, peer.kyberPk, { type: 'answer', sdp: sanitizeSDP(window._PCM.pc.localDescription.sdp) }, 25050);
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
