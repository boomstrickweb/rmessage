import { resubAll } from '../transport/nostr.js';
import { renderContacts, renderPeers } from './render.js';

const G = window;

const COLS = ['#e8ff00', '#00ff88', '#b44fff', '#00aaff', '#ff3366', '#ff8800', '#00ffcc', '#ff00ff'];

import { ktCheck, ktRecord } from '../transport/events.js';

export function addPeer() {
  const inp = document.getElementById('peerInp');
  let b;
  try {
    b = JSON.parse(inp.value.trim());
  } catch {
    alert('Invalid JSON format.\nExample: {"nostr":"ab12...", "kyber":"04ab..."}');
    return;
  }
  const nk = b.nostr?.toLowerCase().replace(/[^a-f0-9]/g, '');
  if (!nk || nk.length !== 64) {
    alert('Nostr key must be 64 hex characters.');
    return;
  }
  if (!b.kyber || b.kyber.length < 100) {
    alert('ML-KEM key (kyber field) is missing or too short.');
    return;
  }
  if (nk === G._NK.pub) {
    alert('This is your own key!');
    return;
  }

  const peer = G._PEERS[nk];
  if (peer) {
    const status = ktCheck(nk, b.kyber);
    if (status === 'changed') {
      if (!confirm('WARNING: This peer\'s key has changed! This could be a MITM attack. Continue?')) return;
      ktRecord(nk, peer.kyberPk, b.kyber, 'key_changed');
    }
    peer.kyberPk = b.kyber;
    G.savePeers();
    inp.value = '';
    renderContacts(); renderPeers();
    return;
  }

  ktRecord(nk, null, b.kyber, 'key_first');
  G._PEERS[nk] = {
    name: nk.slice(0, 10),
    color: COLS[Object.keys(G._PEERS).length % COLS.length],
    kyberPk: b.kyber
  };
  G.savePeers();
  inp.value = '';
  resubAll();
  renderContacts(); renderPeers();
}

export function delPeer(k) {
  if (!confirm('Delete this peer?')) return;
  delete G._PEERS[k];
  localStorage.setItem('rl5_peers', JSON.stringify(G._PEERS));
  if (G.AP === k) G.AP = null;
  renderContacts(); renderPeers();
}
