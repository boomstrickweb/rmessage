/**
 * events.js — Incoming Nostr event dispatcher
 *
 * Decrypts incoming kind:4 (messages) and kind:25050 (signaling) events.
 * Routes to: chat messages, WebRTC signaling, heartbeats, onion relay,
 *            dummy/padding events (silently dropped), key rotation.
 *
 * Exports: onEv
 */

'use strict';

import { kemD }           from '../crypto/mlkem.js';
import { aesDec, drDecrypt, pqDecStr } from '../crypto/ratchet.js';
import { mldsaVerify }    from '../crypto/mldsa.js';
import { answerCall, endCall, waitForGathering, sanitizeSDP, PCManager, ensureDC, processDCQ } from '../transport/webrtc.js';
import { markOnline }     from '../transport/onion.js';
import { nostrPub }       from '../transport/nostr.js';
import { verifyDeniable } from '../transport/padding.js';
import { ktRecord }       from '../ui/settings.js';
import { renderContacts, renderMsgs, showBadge } from '../ui/render.js';
import { idbSave }        from '../storage/crdt.js';
import { fhex, hex }      from '../utils.js';

const _seen = new Set();

async function decEv(ev) {
  const KKkeys = window._KKkeys;
  if (!KKkeys?.sk) return null;
  try {
    const outer = JSON.parse(ev.content);
    if (!outer.kem) return null;
    const K   = kemD(outer.kem, KKkeys.sk);
    const raw = await aesDec(K, outer.iv, outer.ct);
    return JSON.parse(new TextDecoder().decode(raw));
  } catch { return null; }
}

export async function onEv(ev) {
  if (_seen.has(ev.id)) return;
  _seen.add(ev.id);
  if (_seen.size > 1000) { const first = _seen.values().next().value; _seen.delete(first); }

  const NK = window._NK; if (!NK) return;
  if (!ev.tags?.some(t => t[0] === 'p' && t[1] === NK.pub)) return;

  const payload = await decEv(ev);
  if (!payload) return;

  // Resolve sender — Sealed Sender: sender's real identity inside payload
  const senderNpub  = payload._sender?.nostr || payload.from || ev.pubkey;
  const senderKyber = payload._sender?.kyber || (window._PEERS?.[senderNpub]?.kyberPk);

  // Heartbeat
  if (payload.type === '__hb__') { markOnline(senderNpub); return; }

  // Dummy (traffic padding) — drop silently
  if (payload.type === '__pad__') { markOnline(senderNpub); return; }

  // Onion relay: forward to next hop if we are not the destination
  if (payload.type === '__onion__' && payload.ct) {
    const inner = JSON.parse(payload.ct);
    if (inner.type === 'onion_relay') {
      const next = inner.next, nextPeer = window._PEERS?.[next];
      if (next && nextPeer?.kyberPk && next !== NK.pub) {
        await nostrPub(next, nextPeer.kyberPk, { type: '__onion__', ct: inner.ct }, 4);
      } else if (next === NK.pub && inner.ct) {
        // We are the destination — recurse with the inner ciphertext
        const finalPayload = JSON.parse(inner.ct);
        if (finalPayload.type === 'onion_final') {
          await onEv({ ...ev, content: JSON.stringify({ v: 3, ...JSON.parse(finalPayload.payload) }), id: hex(crypto.getRandomValues(new Uint8Array(16))) });
        }
      }
    }
    return;
  }

  // Deniable auth check (best-effort — does not block delivery)
  const daResult = await verifyDeniable(payload, senderNpub);
  if (daResult === false) { console.warn('Deniable auth mismatch from', senderNpub); }

  // Update peer's Kyber key if bundled
  if (senderKyber && window._PEERS?.[senderNpub]) {
    const peer = window._PEERS[senderNpub];
    if (!peer.kyberPk) { peer.kyberPk = senderKyber; savePeers(); }
    else if (peer.kyberPk !== senderKyber) {
      ktRecord(senderNpub, senderKyber, 'key_changed');
      peer.kyberPk = senderKyber; peer.fpVerified = false; savePeers();
    }
  }

  // ── WebRTC signaling ──

  if (ev.kind === 25050 || payload.type === 'offer' || payload.type === 'answer' || payload.type === 'ice' || payload.type === 'reject' || payload.type === 'end' || payload.type === 'ice_restart' || payload.type === 'dc_offer') {
    await handleSignaling(payload, senderNpub, senderKyber, ev);
    return;
  }

  // ── Chat messages ──

  if (!window._C) return;
  const C = window._C;

  // Key rotate (DR text messages use a nested DR payload)
  let finalPayload = payload;
  if (payload.v === 4 && payload.initCt) {
    try {
      const decBytes = await drDecrypt(senderNpub, JSON.stringify(payload), KKkeys.sk);
      finalPayload   = JSON.parse(new TextDecoder().decode(decBytes));
    } catch (e) { console.warn('DR decrypt failed, using raw', e); }
  }

  if (!finalPayload.type || finalPayload.type === 'text' || finalPayload.type === 'image' || finalPayload.type === 'voice' || finalPayload.type === 'file') {
    const op = {
      id:      finalPayload.id   || hex(crypto.getRandomValues(new Uint8Array(16))),
      from:    senderNpub,
      to:      NK.pub,
      lam:     finalPayload.lam  || 0,
      vc:      finalPayload.vc   || {},
      type:    finalPayload.type || 'text',
      payload: finalPayload.payload || finalPayload,
      ts:      finalPayload.ts   || ev.created_at * 1000,
    };
    if (C.merge(op)) {
      renderContacts();
      if (window._AP === senderNpub) renderMsgs();
      showBadge();
      // Auto-delete if disappearing messages enabled
      const dis = window._disappearMs;
      if (dis > 0) setTimeout(() => { C.ops = C.ops.filter(o => o.id !== op.id); C._save(); renderContacts(); if (window._AP === senderNpub) renderMsgs(); }, dis);
    }
  }
}

// ── Signaling handler ──

async function handleSignaling(payload, from, fromKyber, ev) {
  const NK = window._NK;
  const type = payload.type;

  if (type === 'offer') {
    window._pendingOffer = { sdp: payload.sdp, from };
    document.getElementById('incName').textContent = window._PEERS?.[from]?.name || from.slice(0, 12);
    document.getElementById('incoming').classList.add('show');
    markOnline(from);
  }

  else if (type === 'dc_offer') {
    if (window._PCM) { try { window._PCM.close(); } catch {} }
    window._PCM = new PCManager(false);
    await window._PCM.init(from, false);
    window._PCM.peer = from;
    await window._PCM.setRemote(new RTCSessionDescription({ type: 'offer', sdp: payload.sdp }));
    const answer = await window._PCM.pc.createAnswer();
    await window._PCM.pc.setLocalDescription(answer);
    await waitForGathering(window._PCM.pc, 5000);
    const peer = window._PEERS?.[from];
    if (peer?.kyberPk) await nostrPub(from, peer.kyberPk, { type: 'dc_answer', sdp: sanitizeSDP(window._PCM.pc.localDescription.sdp) }, 25050);
  }

  else if (type === 'dc_answer') {
    if (window._PCM?.pc) {
      await window._PCM.setRemote(new RTCSessionDescription({ type: 'answer', sdp: payload.sdp }));
    }
  }

  else if (type === 'answer') {
    if (window._PCM?.pc && window._callState === 'calling') {
      window._callState = 'connecting';
      setCallSt('Connecting... (TURN)', 'ring');
      await window._PCM.setRemote(new RTCSessionDescription({ type: 'answer', sdp: payload.sdp }));
    }
  }

  else if (type === 'ice') {
    if (window._PCM?.pc && payload.candidate) {
      const c = new RTCIceCandidate(payload.candidate);
      await window._PCM.addICE(c);
    }
  }

  else if (type === 'ice_restart') {
    if (window._PCM?.pc && window._callState === 'connected') {
      await window._PCM.pc.setRemoteDescription(new RTCSessionDescription({ type: 'offer', sdp: payload.sdp }));
      const answer = await window._PCM.pc.createAnswer();
      await window._PCM.pc.setLocalDescription(answer);
      await waitForGathering(window._PCM.pc, 5000);
      const peer = window._PEERS?.[from];
      if (peer?.kyberPk) await nostrPub(from, peer.kyberPk, { type: 'answer', sdp: sanitizeSDP(window._PCM.pc.localDescription.sdp) }, 25050);
    }
  }

  else if (type === 'reject') {
    if (window._callState === 'calling') { setCallSt('Call declined', 'err'); setTimeout(() => endCall(), 2000); }
  }

  else if (type === 'end') {
    if (window._callState !== 'idle') { setCallSt('Call ended', 'err'); setTimeout(() => endCall(), 1000); }
  }
}

function setCallSt(t, cls) {
  const el = document.getElementById('callSt');
  if (el) { el.textContent = t; el.className = 'call-st' + (cls ? ' ' + cls : ''); }
}

function savePeers() {
  localStorage.setItem('rl5_peers', JSON.stringify(window._PEERS));
}
