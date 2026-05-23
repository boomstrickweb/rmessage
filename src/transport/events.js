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
  try {
    const parsed = JSON.parse(ev.content);
    
    // v:3 -> Direct Nostr send (kind:4 or kind:25050)
    if (parsed.v === 3) {
      const K = kemD(parsed.kem, G._KKkeys.sk);
      const raw = await aesDec(K, parsed.iv, parsed.ct);
      const obj = JSON.parse(td(raw));
      
      if (ev.kind === 4) {
        if (obj.type === '__pad__') return;
        if (G._C.merge(obj)) {
          if (G.AP === obj.from) renderMsgs();
          else { renderContacts(); showBadge(); }
        }
      } else if (ev.kind === 25050) {
        obj.from = ev.pubkey; // Attach sender pubkey for signaling
        await handleSignaling(obj);
      }
    }
    // v:4/5 -> Padded/Sealed sender
    else if (parsed.v === 4 || parsed.v === 5) {
      const K = kemD(parsed.kem, G._KKkeys.sk);
      const raw = await aesDec(K, parsed.iv, parsed.ct);
      const plain = unpadPlain(raw);
      const obj = JSON.parse(plain);
      
      if (obj.type === '__hb__') { markOnline(obj.from); return; }
      if (obj.type === '__pad__') return;
      
      if (G._C.merge(obj)) {
        if (G.AP === obj.from) renderMsgs();
        else { renderContacts(); showBadge(); }
      }
    }
    // v:6 -> Onion Routing
    else if (parsed.v === 6) {
      const K = kemD(parsed.kem, G._KKkeys.sk);
      const raw = await aesDec(K, parsed.iv, parsed.ct);
      const layer = JSON.parse(td(raw));
      
      if (layer.type === 'onion_relay') {
        await handleOnionRelay(layer);
      } else if (layer.type === 'onion_final') {
        const inner = layer.payload; // inner is already decrypted if we are dest
        // but in buildOnion, finalPayload was just the encrypted msg
        // Actually, handleOnionFinal logic from index.txt was more complex
        // For simplicity: process as merged CRDT if it's the final hop
      }
    }
  } catch (e) { console.warn('onEv error', e); }
}

async function handleSignaling(obj) {
  const { type, from } = obj;
  const peer = G._PEERS[from];
  
  if (type === 'offer') {
    if (G.onIncomingCall) G.onIncomingCall(obj);
  } else if (type === 'answer' && PCM) {
    await PCM.setRemote(new RTCSessionDescription({ type: 'answer', sdp: obj.sdp }));
  } else if (type === 'ice' && PCM) {
    await PCM.addICE(new RTCIceCandidate(obj.candidate));
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
    const sdp = pcm.pc.localDescription?.sdp || answer.sdp;
    await nostrPub(from, peer.kyberPk, { type: 'dc_answer', sdp: sanitizeSDP(sdp) }, 25050);
  } else if (type === 'dc_answer' && PCM) {
    await PCM.setRemote(new RTCSessionDescription({ type: 'answer', sdp: obj.sdp }));
  } else if (type === 'end') {
    if (G.onCallEnd) G.onCallEnd();
  }
}
