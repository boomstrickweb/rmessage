import { td, fhex } from '../utils.js';
import { kemD, aesDec } from '../crypto/mlkem.js';
import { renderMsgs, renderContacts, showBadge } from '../ui/render.js';
import { markOnline, handleOnionRelay } from './onion.js';
import { unpadPlain } from './padding.js';
import { PCM, onDCMsg, sanitizeSDP, PCManager, setPCM, waitForGathering } from './webrtc.js';
import { isReplay, nostrPub } from './nostr.js';

const G = window;

export async function onEv(ev) {
  if (!G._KKkeys) return;
  if (isReplay(ev)) return;
  let str, realSenderPub = ev.pubkey;
  try {
    const parsed = JSON.parse(ev.content);

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
              const obj = JSON.parse(msgStr);
              if (!obj.id || !obj.type || obj.type === '__pad__') return;
              
              const fp = obj._sender?.nostr || ev.pubkey;
              if (fp === G._NK.pub) return;
              
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

  let obj; try { obj = JSON.parse(str); } catch { return; }
  const fp = obj._sender?.nostr || realSenderPub;
  if (fp === G._NK.pub) return;

  if (obj._sender?.nostr && obj._sender?.kyber) {
    const sn = obj._sender.nostr; const sk = obj._sender.kyber;
    if (!G._PEERS[sn]) {
      G._PEERS[sn] = { name: sn.slice(0, 10), color: 'var(--pq)', kyberPk: sk };
      localStorage.setItem('rl5_peers', JSON.stringify(G._PEERS));
      renderContacts();
    }
    markOnline(sn);
  }

  if (ev.kind === 25050 || obj.type === 'offer' || obj.type === 'answer' || obj.type === 'ice' || obj.type === 'dc_offer' || obj.type === 'dc_answer') {
    obj.from = fp;
    await handleSignaling(obj);
    return;
  }

  if (!obj.id || !obj.type || obj.type === '__pad__') return;
  obj.from = fp;
  if (G._C.merge(obj)) {
    if (G.AP === fp) renderMsgs();
    else { renderContacts(); showBadge(); }
  }
}

async function handleSignaling(obj) {
  const { type, from } = obj;
  const peer = G._PEERS[from];

  if (type === 'offer') {
    if (!G._PEERS[from] && obj.kyberPk) {
      G._PEERS[from] = { name: from.slice(0, 10), color: 'var(--pq)', kyberPk: obj.kyberPk };
      localStorage.setItem('rl5_peers', JSON.stringify(G._PEERS));
      renderContacts();
    }
    if (G.onIncomingCall) G.onIncomingCall(obj);
  } else if (type === 'answer' && PCM) {
    await PCM.setRemote(new RTCSessionDescription({ type: 'answer', sdp: obj.sdp })).catch(() => { });
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
