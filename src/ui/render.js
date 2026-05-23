/**
 * render.js — Contact list, message rendering, badge, Key Transparency UI
 *
 * Exports: renderContacts, renderMsgs, renderPeers, showBadge,
 *          ktRender, getBlobUrl, loadBytesIfNeeded
 */

'use strict';

import { idbLoad } from '../storage/crdt.js';

const COLS = ['#e8ff00', '#00aaff', '#00ff88', '#ff5588', '#ff9900', '#cc44ff'];

function esc(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\n/g, '<br>');
}

export function getBlobUrl(payload) {
  if (!payload?._bytes) return null;
  const blob = new Blob([payload._bytes], { type: payload.mimeType || 'application/octet-stream' });
  return URL.createObjectURL(blob);
}

export async function loadBytesIfNeeded(opId) {
  const op = window._C?.ops.find(o => o.id === opId);
  if (!op || op.payload?._bytes) return;
  const rec = await idbLoad(opId);
  if (rec?.bytes) {
    op.payload._bytes = rec.bytes;
    if (!op.payload.mimeType && rec.mime) op.payload.mimeType = rec.mime;
    renderMsgs();
  }
}

export function renderContacts() {
  const el   = document.getElementById('clist');
  const keys = Object.keys(window._PEERS || {});
  const NK   = window._NK;
  const C    = window._C;

  if (!keys.length) {
    el.innerHTML = '<div class="no-c">No contacts yet.<br><b>⚙</b> Add a peer in Settings.</div>';
    return;
  }

  el.innerHTML = keys.map(k => {
    const p    = window._PEERS[k];
    const msgs = C?.chat(NK?.pub, k) || [];
    const last = msgs[msgs.length - 1];
    const ur   = msgs.filter(m => m.from === k && m.ts > (p.lastRead || 0)).length;
    const lt   = last
      ? (last.type === 'text' ? esc(last.payload?.text || '').slice(0, 30)
        : last.type === 'image' ? '🖼' : last.type === 'voice' ? '🎙' : '📎')
      : '';
    const verBadge = !p.kyberPk
      ? '<span style="color:var(--red);font-size:9px;margin-left:4px">⚠ no key</span>'
      : !p.fpVerified
        ? '<span style="color:rgba(255,180,0,.8);font-size:9px;margin-left:4px">⚠ verify</span>'
        : '<span style="color:var(--grn);font-size:9px;margin-left:4px">✓</span>';
    return `<div class="ci">
      <div class="av" style="background:${p.color}22;color:${p.color}">${p.name[0].toUpperCase()}</div>
      <div class="ci-i" onclick="openChatFromContacts('${k}')">
        <div class="ci-n" style="color:${p.color}">${p.name}${verBadge}</div>
        <div class="ci-k">${k.slice(0, 22)}...</div>
        ${lt ? `<div class="ci-last">${lt}</div>` : ''}
      </div>
      <div class="ci-acts">${ur ? `<div class="ubadge">${ur}</div>` : ''}
        <button class="ic-btn ic-chat" onclick="openChatFromContacts('${k}')">💬</button>
        <button class="ic-btn ic-call" onclick="startCall('${k}')">📞</button>
      </div>
    </div>`;
  }).join('');
  showBadge();
}

export function renderMsgs() {
  const el = document.getElementById('msgs');
  const AP = window.AP;
  const NK = window._NK;
  const C  = window._C;
  const OQ = window._OQ || [];
  if (!AP) return;

  const ms = C?.chat(NK?.pub, AP) || [];

  if (!ms.length) {
    el.innerHTML = `<div class="empty-chat">
      <div class="eg">⬡</div><div class="et">RELAY</div>
      <div class="es">Text · Photo · Voice · Call<br><b>ML-KEM-768 · TURN · End-to-End Encrypted</b></div>
    </div>`;
    return;
  }

  el.innerHTML = ms.map(m => {
    const me  = m.from === NK?.pub;
    const p   = window._PEERS?.[m.from];
    const col = me ? 'var(--acc)' : (p?.color || 'var(--pq)');
    const nm  = me ? 'Me' : (p?.name || m.from.slice(0, 10));
    const t   = new Date(m.ts).toLocaleTimeString('az', { hour: '2-digit', minute: '2-digit', hour12: false });
    const inQ = OQ.some(q => q.op?.id === m.id);
    const foot = `<div class="mf"><span>${t}</span>${me
      ? `<span class="${inQ ? 'pc' : 'okc'}">${inQ ? '⏳' : '✓✓'}</span><span style="font-size:8px;color:var(--dim)">${m.type === 'text' ? 'relay' : 'TURN'}</span>`
      : '<span style="color:var(--pq);font-size:8px">PQ·E2E</span>'}</div>`;
    const type = m.type || 'text';
    let body = '';

    if (type === 'text') {
      body = `<div class="mb">${esc(m.payload?.text || '')}</div>`;
    } else if (type === 'image') {
      const prog = m.payload?._prog;
      if (prog !== undefined && prog < 1) {
        body = `<div class="mb mb-prog"><div>${esc(m.payload?.name || 'Photo')}</div><div class="pb-w"><div class="pb" style="width:${Math.round(prog*100)}%"></div></div><div class="pb-info"><span>${Math.round((m.payload?.size||0)/1024)}KB</span><span>${Math.round(prog*100)}%</span></div></div>`;
      } else if (m.payload?._bytes) {
        const url = getBlobUrl(m.payload);
        body = url ? `<div class="mb" style="padding:4px"><img class="mb-img" src="${url}" onclick="openImg('${url}')" loading="lazy"/></div>`
                   : `<div class="mb"><span style="color:var(--mut)">🖼 Photo</span></div>`;
      } else if (m.payload?._failed) {
        body = `<div class="mb p2p-wait" style="color:var(--red)">❌ ${esc(m.payload?.name || 'Photo')} — send failed</div>`;
      } else {
        loadBytesIfNeeded(m.id);
        body = `<div class="mb p2p-wait">🖼 ${esc(m.payload?.name || 'Photo')} — loading...</div>`;
      }
    } else if (type === 'voice') {
      const dur      = m.payload?.duration || '';
      const prog     = m.payload?._prog;
      const hasBytes = !!(m.payload?._bytes);
      if (prog !== undefined && prog < 1) {
        body = `<div class="mb mb-prog"><div>🎙 Sending voice message...</div><div class="pb-w"><div class="pb" style="width:${Math.round(prog*100)}%"></div></div><div class="pb-info"><span>${Math.round((m.payload?.size||0)/1024)}KB</span><span>${Math.round(prog*100)}%</span></div></div>`;
      } else {
        if (!hasBytes) loadBytesIfNeeded(m.id);
        body = `<div class="mb mb-voice">
          <button class="v-play" onclick="playVoice('${m.id}')">${hasBytes ? '▶' : '⏳'}</button>
          <div><div style="font-size:11px;color:var(--mut)">🎙 Voice message</div><div class="v-dur">${dur ? dur + 's' : ''}</div></div>
        </div>`;
      }
    } else if (type === 'file') {
      const prog = m.payload?._prog;
      if (prog !== undefined && prog < 1) {
        body = `<div class="mb mb-prog"><div>📎 ${esc(m.payload?.name || 'File')}</div><div class="pb-w"><div class="pb" style="width:${Math.round(prog*100)}%"></div></div><div class="pb-info"><span>${Math.round((m.payload?.size||0)/1024)}KB</span><span>${Math.round(prog*100)}%</span></div></div>`;
      } else {
        const url = m.payload?._bytes ? getBlobUrl(m.payload) : null;
        body = `<div class="mb mb-file"><span style="font-size:20px">📎</span><div style="flex:1;min-width:0"><div style="font-size:12px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(m.payload?.name || 'File')}</div><div style="font-size:9px;color:var(--mut)">${Math.round((m.payload?.size||0)/1024)}KB</div></div>${url ? `<a href="${url}" download="${m.payload?.name || 'file'}" style="color:var(--acc2);font-size:20px;flex-shrink:0">⬇</a>` : ''}</div>`;
      }
    }

    return `<div class="mw ${me ? 'me' : 'them'}"><div class="mh"><span style="color:${col};font-weight:600">${nm}</span></div>${body}${foot}</div>`;
  }).join('');

  el.scrollTop = el.scrollHeight;
}

export function renderPeers() {
  const el   = document.getElementById('peersDiv');
  const keys = Object.keys(window._PEERS || {});
  document.getElementById('peerCount').textContent = keys.length;
  if (!keys.length) { el.innerHTML = '<div style="font-size:11px;color:var(--dim)">No peers yet.</div>'; return; }
  el.innerHTML = keys.map(k => {
    const p      = window._PEERS[k];
    const vbadge = p.fpVerified
      ? '<span style="color:var(--grn);font-size:9px;margin-left:4px">✓ verified</span>'
      : `<span style="color:var(--red);font-size:9px;margin-left:4px;cursor:pointer" onclick="openFP('${k}')">⚠ verify</span>`;
    return `<div class="pr-row"><div class="av" style="width:36px;height:36px;border-radius:8px;background:${p.color}22;color:${p.color};font-size:16px">${p.name[0].toUpperCase()}</div><div class="pr-i"><div class="pr-n" style="color:${p.color}">${p.name}${p.kyberPk ? vbadge : ' ⚠ no key'}</div><div class="pr-k">${k.slice(0, 24)}...</div></div><button class="del-btn" onclick="delPeer('${k}')">✕</button></div>`;
  }).join('');
}

export function showBadge() {
  const NK = window._NK, C = window._C;
  const tot = Object.keys(window._PEERS || {}).reduce((s, k) => {
    const p = window._PEERS[k];
    return s + (C?.chat(NK?.pub, k).filter(m => m.from === k && m.ts > (p.lastRead || 0)).length || 0);
  }, 0);
  const b = document.getElementById('navBadge');
  if (tot > 0) { b.style.display = 'flex'; b.textContent = tot; } else b.style.display = 'none';
}

// ── Key Transparency log renderer ──

export function ktRender() {
  const el      = document.getElementById('ktLog');
  if (!el) return;
  const entries = [...(window._ktLog || [])].reverse().slice(0, 20);
  if (!entries.length) { el.innerHTML = '<div style="font-size:10px;color:var(--dim)">No entries yet.</div>'; return; }
  el.innerHTML = entries.map(e => {
    const p   = window._PEERS?.[e.peer];
    const nm  = p?.name || e.peer.slice(0, 10);
    const t   = new Date(e.ts).toLocaleString('en', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    const cls = e.event === 'key_changed' ? 'kt-warn' : e.event === 'key_first' ? 'kt-new' : 'kt-ok';
    const icon = e.event === 'key_changed' ? '⚠' : e.event === 'key_first' ? '🆕' : '✓';
    const label = e.event === 'key_changed'
      ? '<b style="color:var(--red)">KEY CHANGED!</b>'
      : e.event === 'key_first' ? 'First contact' : 'Key verified';
    return `<div class="kt-entry ${cls}">
      <span style="color:var(--mut)">${t}</span> · <span style="color:var(--acc2)">${nm}</span><br>
      ${icon} ${label} · <span style="color:var(--dim)">${e.newHash}</span>
    </div>`;
  }).join('');
}
