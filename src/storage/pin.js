/**
 * pin.js — PIN / Biometric Key Encryption
 *
 * Secret keys (Nostr private key, ML-KEM secret key) are NEVER stored in
 * plaintext. They are encrypted with AES-256-GCM using a key derived from
 * the user's 6-digit PIN via PBKDF2-SHA256 (310,000 iterations).
 *
 * A verifier blob (AES-GCM of known plaintext) allows fast PIN checking
 * without exposing the secret keys.
 *
 * Biometric (WebAuthn): on supported devices, a platform authenticator
 * credential is enrolled. Successful biometric auth retrieves the session
 * PIN from sessionStorage (set after first correct PIN entry).
 *
 * Exports: hasEncryptedSKs, saveEncryptedSKs, loadEncryptedSKs,
 *          bioSupported, bioEnroll, bioUnlock,
 *          showPinScreen, hidePinScreen, pinKey, pinDel, tryBiometric,
 *          awaitPin, changePin
 */

'use strict';

import { rnd, hex, fhex, te, td } from '../utils.js';

const PIN_SALT_KEY = 'rl6_pin_salt';
const PIN_VER_KEY  = 'rl6_pin_ver';
const SK_ENC_KEY   = 'rl6_sk_enc';
const PBKDF2_ITER  = 310000;

// ── PBKDF2 ──

async function pinToCryptoKey(pin, saltHex) {
  const raw  = te(pin);
  const base = await crypto.subtle.importKey('raw', raw, 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: fhex(saltHex), iterations: PBKDF2_ITER },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function encryptWithKey(ck, data) {
  const iv  = rnd(12);
  const inp = typeof data === 'string' ? te(data) : data;
  const ct  = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, ck, inp));
  return { iv: hex(iv), ct: hex(ct) };
}

async function decryptWithKey(ck, ivH, ctH) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fhex(ivH) }, ck, fhex(ctH)));
}

// ── Public API ──

export function hasEncryptedSKs() {
  return !!(localStorage.getItem(SK_ENC_KEY) && localStorage.getItem(PIN_VER_KEY) && localStorage.getItem(PIN_SALT_KEY));
}

export async function saveEncryptedSKs(pin, nkPriv, kkSk) {
  let saltHex = localStorage.getItem(PIN_SALT_KEY);
  if (!saltHex) { saltHex = hex(rnd(32)); localStorage.setItem(PIN_SALT_KEY, saltHex); }
  const ck = await pinToCryptoKey(pin, saltHex);
  const { iv: niv, ct: nct } = await encryptWithKey(ck, nkPriv);
  const { iv: kiv, ct: kct } = await encryptWithKey(ck, kkSk);
  const { iv: viv, ct: vct } = await encryptWithKey(ck, 'RELAY_PIN_OK');
  localStorage.setItem(SK_ENC_KEY,  JSON.stringify({ niv, nct, kiv, kct }));
  localStorage.setItem(PIN_VER_KEY, JSON.stringify({ viv, vct }));
}

export async function loadEncryptedSKs(pin) {
  const saltHex = localStorage.getItem(PIN_SALT_KEY);
  if (!saltHex) throw new Error('no salt');
  const ck      = await pinToCryptoKey(pin, saltHex);
  const ver     = JSON.parse(localStorage.getItem(PIN_VER_KEY));
  const verPlain = td(await decryptWithKey(ck, ver.viv, ver.vct));
  if (verPlain !== 'RELAY_PIN_OK') throw new Error('wrong pin');
  const enc    = JSON.parse(localStorage.getItem(SK_ENC_KEY));
  const nkPriv = td(await decryptWithKey(ck, enc.niv, enc.nct));
  const kkSk   = td(await decryptWithKey(ck, enc.kiv, enc.kct));
  return { nkPriv, kkSk };
}

// ── Biometric (WebAuthn) ──

let _bioCredId = null;

export async function bioSupported() {
  try {
    return !!(window.PublicKeyCredential &&
      await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable());
  } catch { return false; }
}

export async function bioEnroll(pin) {
  if (!await bioSupported()) return false;
  try {
    const cred = await navigator.credentials.create({ publicKey: {
      challenge: rnd(32),
      rp: { name: 'RELAY', id: location.hostname || 'localhost' },
      user: { id: rnd(16), name: 'relay-user', displayName: 'RELAY' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
      timeout: 60000,
    }});
    if (cred) { localStorage.setItem('rl6_bio_id', hex(new Uint8Array(cred.rawId))); return true; }
  } catch {}
  return false;
}

export async function bioUnlock() {
  const bioIdHex = localStorage.getItem('rl6_bio_id');
  if (!bioIdHex) return null;
  try {
    await navigator.credentials.get({ publicKey: {
      challenge: rnd(32),
      allowCredentials: [{ type: 'public-key', id: fhex(bioIdHex) }],
      userVerification: 'required',
      timeout: 60000,
    }});
    return sessionStorage.getItem('rl6_session_pin');
  } catch {}
  return null;
}

// ── PIN UI ──

let _pinBuf     = '';
let _pinMode    = 'unlock'; // 'unlock' | 'setup' | 'confirm'
let _pinFirst   = '';
let _pinResolve = null;

export function showPinScreen(mode) {
  _pinMode = mode; _pinBuf = ''; _pinFirst = '';
  updatePinDots();
  document.getElementById('pinErr').textContent = '';
  document.getElementById('pinScreen').style.display = 'flex';
  document.getElementById('loading').style.display   = 'none';
  if (mode === 'setup') {
    document.getElementById('pinLabel').textContent    = 'Create a new PIN (6 digits)';
    document.getElementById('pinNewLabel').style.display = 'block';
  } else {
    document.getElementById('pinLabel').textContent    = 'Enter your PIN';
    document.getElementById('pinNewLabel').style.display = 'none';
  }
  const bioWrap = document.getElementById('pinBioWrap');
  bioWrap.style.display = (mode === 'unlock' && localStorage.getItem('rl6_bio_id')) ? 'block' : 'none';
}

export function hidePinScreen() { document.getElementById('pinScreen').style.display = 'none'; }

function updatePinDots() {
  for (let i = 0; i < 6; i++) {
    const d = document.getElementById('pd' + i);
    d.className = 'pin-dot' + (_pinBuf.length > i ? ' filled' : '');
  }
}

function flashDots(cls) {
  for (let i = 0; i < 6; i++) document.getElementById('pd' + i).className = 'pin-dot ' + cls;
  setTimeout(updatePinDots, 600);
}

export function pinKey(k) {
  if (_pinBuf.length >= 6) return;
  _pinBuf += k; updatePinDots();
  if (_pinBuf.length === 6) setTimeout(pinSubmit, 120);
}

export function pinDel() { if (!_pinBuf.length) return; _pinBuf = _pinBuf.slice(0, -1); updatePinDots(); }

async function pinSubmit() {
  const pin = _pinBuf; _pinBuf = ''; updatePinDots();

  if (_pinMode === 'setup') {
    document.getElementById('pinLabel').textContent = 'Repeat your PIN';
    document.getElementById('pinNewLabel').style.display = 'none';
    _pinFirst = pin; _pinMode = 'confirm'; return;
  }

  if (_pinMode === 'confirm') {
    if (pin !== _pinFirst) {
      document.getElementById('pinErr').textContent = 'PINs do not match. Try again.';
      flashDots('err');
      setTimeout(() => {
        _pinMode = 'setup'; _pinFirst = '';
        document.getElementById('pinLabel').textContent = 'Create a new PIN (6 digits)';
        document.getElementById('pinNewLabel').style.display = 'block';
        document.getElementById('pinErr').textContent = '';
      }, 1200);
      return;
    }
    sessionStorage.setItem('rl6_session_pin', pin);
    hidePinScreen();
    if (_pinResolve) { _pinResolve(pin); _pinResolve = null; }
    return;
  }

  // Unlock mode
  document.getElementById('lmsg').textContent = 'Checking PIN...';
  document.getElementById('pinScreen').style.display = 'none';
  document.getElementById('loading').style.display   = 'flex';
  try {
    const { nkPriv, kkSk } = await loadEncryptedSKs(pin);
    sessionStorage.setItem('rl6_session_pin', pin);
    if (_pinResolve) { _pinResolve({ nkPriv, kkSk }); _pinResolve = null; }
  } catch {
    document.getElementById('loading').style.display   = 'none';
    document.getElementById('pinScreen').style.display = 'flex';
    document.getElementById('pinErr').textContent      = 'Wrong PIN. Try again.';
    flashDots('err');
  }
}

export async function tryBiometric() {
  const pin = await bioUnlock();
  if (pin) { _pinBuf = pin; await pinSubmit(); }
  else { document.getElementById('pinErr').textContent = 'Biometric failed. Enter PIN.'; }
}

export function awaitPin(mode) {
  return new Promise(resolve => { _pinResolve = resolve; showPinScreen(mode); });
}

export async function changePin() {
  if (!confirm('Change your PIN?')) return;
  const oldPin = sessionStorage.getItem('rl6_session_pin');
  if (!oldPin) { alert('Please reopen the app first.'); return; }
  try { await loadEncryptedSKs(oldPin); } catch { alert('Current PIN is incorrect.'); return; }
  _pinResolve = null;
  await awaitPin('setup');
  const newPin = sessionStorage.getItem('rl6_session_pin');
  if (!newPin || newPin === oldPin) { alert('PIN was not changed.'); return; }
  await saveEncryptedSKs(newPin, window._NK?.priv, window._KKkeys?.sk);
  alert('PIN changed successfully ✓');
}
