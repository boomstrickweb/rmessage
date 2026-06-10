import { esc } from '../utils.js';
import { idbLoad } from '../storage/crdt.js';

const G = window;

function getBlobUrl(payload) {
  if (!payload?._bytes) return null;
  const blob = new Blob([payload._bytes], { type: payload.mimeType || 'application/octet-stream' });
  return URL.createObjectURL(blob);
}

async function loadBytesIfNeeded(opId) {
  const op = G._C.ops.find(o => o.id === opId);
  if (!op || op.payload?._bytes) return;
  const rec = await idbLoad(opId);
  if (rec?.bytes) {
    op.payload._bytes = rec.bytes;
    if (!op.payload.mimeType && rec.mime) op.payload.mimeType = rec.mime;
    renderMsgs();
  }
}

export function renderContacts() {
  const el = document.getElementById('clist'), keys = Object.keys(G._PEERS || {});
  if (!keys.length) {
    el.innerHTML = '<div class="no-c">No contacts yet.<br><b>⚙</b> Add peer from Settings.</div>';
    return;
  }
  el.innerHTML = keys.map(k => {
    const p = G._PEERS[k];
    const msgs = G._C.chat(G._NK.pub, k);
    const last = msgs[msgs.length - 1];
    const ur = msgs.filter(m => m.from === k && m.ts > (p.lastRead || 0)).length;
    const lt = last ? (last.type === 'text' ? esc(last.payload?.text || '').slice(0, 30) : last.type === 'image' ? '🖼' : last.type === 'voice' ? '🎙' : '📎') : '';
    return `<div class="ci">
      <div class="av" style="background:${p.color}22;color:${p.color}">${p.name[0].toUpperCase()}</div>
      <div class="ci-i" onclick="openChat('${k}')">
        <div class="ci-n" style="color:${p.color}">${p.name}${!p.kyberPk ? '<span style="color:var(--red);font-size:9px;margin-left:4px">⚠ key</span>' : (!p.fpVerified ? '<span style="color:rgba(255,180,0,.8);font-size:9px;margin-left:4px">⚠ verify</span>' : '<span style="color:var(--grn);font-size:9px;margin-left:4px">✓</span>')}</div>
        <div class="ci-k">${k.slice(0, 22)}...</div>
        ${lt ? `<div class="ci-last">${lt}</div>` : ''}
      </div>
      <div class="ci-acts">${ur ? `<div class="ubadge">${ur}</div>` : ''}
        <button class="ic-btn ic-chat" onclick="openChat('${k}')">💬</button>
        <button class="ic-btn ic-call" onclick="startCall('${k}')">📞</button>
      </div>
    </div>`;
  }).join('');
  showBadge();
}

export function renderMsgs() {
  const el = document.getElementById('msgs'); if (!G.AP) return;
  const ms = G._C.chat(G._NK.pub, G.AP);
  if (!ms.length) {
    el.innerHTML = '<div class="empty-chat"><div class="eg">⬡</div><div class="et">RELAY</div><div class="es">Text · Photo · Voice · Call<br><b>ML-KEM-768 · TURN · E2EE</b></div></div>';
    return;
  }
  el.innerHTML = ms.map(m => {
    const me = m.from === G._NK.pub; const p = G._PEERS[m.from];
    const col = me ? 'var(--acc)' : (p?.color || 'var(--pq)'); const nm = me ? 'Me' : (p?.name || m.from.slice(0, 10));
    const t = new Date(m.ts).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
    const inQ = (G._OQ || []).some(q => q.op?.id === m.id);
    const foot = `<div class="mf"><span>${t}</span>${me ? `<span class="${inQ ? 'pc' : 'okc'}">${inQ ? '⏳' : '✓✓'}</span><span style="font-size:8px;color:var(--dim)">${m.type === 'text' ? 'relay' : 'IPFS'}</span>` : '<span style="color:var(--pq);font-size:8px">PQ·E2E</span>'}</div>`;
    const type = m.type || 'text'; let body = '';
    const inTransfer = G.inTransfers?.[m.id];
    const prog = (m.payload?._prog !== undefined) ? m.payload._prog : inTransfer ? (inTransfer.received / inTransfer.meta.total) : undefined;
    
    if (type === 'text') { body = `<div class="mb">${esc(m.payload?.text || '')}</div>`; }
    else if (type === 'image') {
      if (prog !== undefined && prog < 1) {
        body = `<div class="mb mb-prog"><div>${esc(m.payload?.name || 'Photo')}</div><div class="pb-w"><div class="pb" style="width:${Math.round(prog * 100)}%"></div></div><div class="pb-info"><span>${Math.round((m.payload?.size || 0) / 1024)}KB</span><span>${Math.round(prog * 100)}%</span></div></div>`;
      } else if (m.payload?._bytes) {
        const url = getBlobUrl(m.payload);
        body = url ? `<div class="mb" style="padding:4px"><img class="mb-img" src="${url}" onclick="openImg('${url}')" loading="lazy"/></div>` : `<div class="mb"><span style="color:var(--mut)">🖼 Photo</span></div>`;
      } else if (m.payload?._failed) {
        body = `<div class="mb p2p-wait" style="color:var(--red)">❌ ${esc(m.payload?.name || 'Photo')} — failed</div>`;
      } else {
        loadBytesIfNeeded(m.id);
        body = `<div class="mb p2p-wait">🖼 ${esc(m.payload?.name || 'Photo')} — loading...</div>`;
      }
    }
    else if (type === 'voice') {
      const dur = m.payload?.duration || '';
      const hasBytes = !!(m.payload?._bytes);
      if (prog !== undefined && prog < 1) {
        body = `<div class="mb mb-prog"><div>🎙 Sending voice...</div><div class="pb-w"><div class="pb" style="width:${Math.round(prog * 100)}%"></div></div><div class="pb-info"><span>${Math.round((m.payload?.size || 0) / 1024)}KB</span><span>${Math.round(prog * 100)}%</span></div></div>`;
      } else {
        if (!hasBytes) loadBytesIfNeeded(m.id);
        body = `<div class="mb mb-voice">
          <button class="v-play" onclick="playVoice('${m.id}')">${hasBytes ? '▶' : '⏳'}</button>
          <div><div style="font-size:11px;color:var(--mut)">🎙 Voice message</div><div class="v-dur">${dur ? dur + 's' : ''}</div></div>
        </div>`;
      }
    }
    else if (type === 'file') {
      if (prog !== undefined && prog < 1) {
        body = `<div class="mb mb-prog"><div>📎 ${esc(m.payload?.name || 'File')}</div><div class="pb-w"><div class="pb" style="width:${Math.round(prog * 100)}%"></div></div><div class="pb-info"><span>${Math.round((m.payload?.size || 0) / 1024)}KB</span><span>${Math.round(prog * 100)}%</span></div></div>`;
      } else {
        const url = m.payload?._bytes ? getBlobUrl(m.payload) : null;
        body = `<div class="mb mb-file"><span style="font-size:20px">📎</span><div style="flex:1;min-width:0"><div style="font-size:12px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(m.payload?.name || 'File')}</div><div style="font-size:9px;color:var(--mut)">${Math.round((m.payload?.size || 0) / 1024)}KB</div></div>${url ? `<a href="${url}" download="${m.payload?.name || 'file'}" style="color:var(--acc2);font-size:20px;flex-shrink:0">⬇</a>` : ''}</div>`;
      }
    }
    return `<div class="mw ${me ? 'me' : 'them'}"><div class="mh"><span style="color:${col};font-weight:600">${nm}</span></div>${body}${foot}</div>`;
  }).join('');
  el.scrollTop = el.scrollHeight;
}

export function renderPeers() {
  const el = document.getElementById('peersDiv'); if (!el) return;
  const keys = Object.keys(G._PEERS || {});
  const pc = document.getElementById('peerCount'); if (pc) pc.textContent = keys.length;
  if (!keys.length) { el.innerHTML = '<div style="font-size:11px;color:var(--dim)">No peers yet.</div>'; return; }
  el.innerHTML = keys.map(k => {
    const p = G._PEERS[k];
    const vbadge = p.fpVerified ? '<span style="color:var(--grn);font-size:9px;margin-left:4px">✓ verified</span>' : '<span style="color:var(--red);font-size:9px;margin-left:4px;cursor:pointer" onclick="openFP(\'' + k + '\')">⚠ verify</span>';
    return `<div class="pr-row"><div class="av" style="width:36px;height:36px;border-radius:8px;background:${p.color}22;color:${p.color};font-size:16px">${p.name[0].toUpperCase()}</div><div class="pr-i"><div class="pr-n" style="color:${p.color}">${p.name}${p.kyberPk ? vbadge : ' ⚠ no key'}</div><div class="pr-k">${k.slice(0, 24)}...</div></div><button class="del-btn" onclick="delPeer('${k}')">✕</button></div>`;
  }).join('');
}

export function showBadge() {
  const tot = Object.keys(G._PEERS || {}).reduce((s, k) => {
    const p = G._PEERS[k];
    return s + G._C.chat(G._NK.pub, k).filter(m => m.from === k && m.ts > (p.lastRead || 0)).length;
  }, 0);
  const b = document.getElementById('navBadge'); if (!b) return;
  if (tot > 0) { b.style.display = 'flex'; b.textContent = tot; } else b.style.display = 'none';
}
