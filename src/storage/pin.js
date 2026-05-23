import { te, td, hex, fhex, rnd } from '../utils.js';

const PIN_SALT_KEY = 'rl6_pin_salt';
const PIN_VER_KEY = 'rl6_pin_ver';
const SK_ENC_KEY = 'rl6_sk_enc';
const PBKDF2_ITER = 310000;

async function pinToCryptoKey(pin, saltHex) {
  const raw = te(pin);
  const base = await crypto.subtle.importKey('raw', raw, 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: fhex(saltHex), iterations: PBKDF2_ITER },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function encryptWithKey(ck, data) {
  const iv = rnd(12);
  const inp = typeof data === 'string' ? te(data) : data;
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, ck, inp));
  return { iv: hex(iv), ct: hex(ct) };
}

async function decryptWithKey(ck, ivH, ctH) {
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fhex(ivH) }, ck, fhex(ctH)
  ));
}

export async function saveEncryptedSKs(pin, nkPriv, kkSk) {
  let saltHex = localStorage.getItem(PIN_SALT_KEY);
  if (!saltHex) { saltHex = hex(rnd(32)); localStorage.setItem(PIN_SALT_KEY, saltHex); }
  const ck = await pinToCryptoKey(pin, saltHex);
  const { iv: niv, ct: nct } = await encryptWithKey(ck, nkPriv);
  const { iv: kiv, ct: kct } = await encryptWithKey(ck, kkSk);
  const { iv: viv, ct: vct } = await encryptWithKey(ck, 'RELAY_PIN_OK');
  localStorage.setItem(SK_ENC_KEY, JSON.stringify({ niv, nct, kiv, kct }));
  localStorage.setItem(PIN_VER_KEY, JSON.stringify({ viv, vct }));
}

export async function loadEncryptedSKs(pin) {
  const saltHex = localStorage.getItem(PIN_SALT_KEY);
  if (!saltHex) throw new Error('no salt');
  const ck = await pinToCryptoKey(pin, saltHex);
  const ver = JSON.parse(localStorage.getItem(PIN_VER_KEY));
  const verPlain = td(await decryptWithKey(ck, ver.viv, ver.vct));
  if (verPlain !== 'RELAY_PIN_OK') throw new Error('wrong pin');
  const enc = JSON.parse(localStorage.getItem(SK_ENC_KEY));
  const nkPriv = td(await decryptWithKey(ck, enc.niv, enc.nct));
  const kkSk = td(await decryptWithKey(ck, enc.kiv, enc.kct));
  return { nkPriv, kkSk };
}

export function hasEncryptedSKs() {
  return !!(localStorage.getItem(SK_ENC_KEY) && localStorage.getItem(PIN_VER_KEY) && localStorage.getItem(PIN_SALT_KEY));
}

// ── PIN UI state ──
let _pinBuf = '';
let _pinMode = 'unlock'; // 'unlock' | 'setup' | 'confirm'
let _pinFirst = '';
let _pinResolve = null;

export function awaitPin(mode) {
  return new Promise(resolve => {
    _pinResolve = resolve;
    showPinScreen(mode);
  });
}

export function showPinScreen(mode) {
  _pinMode = mode; _pinBuf = ''; _pinFirst = '';
  updatePinDots();
  document.getElementById('pinErr').textContent = '';
  document.getElementById('pinScreen').style.display = 'flex';
  document.getElementById('loading').style.display = 'none';
  if (mode === 'setup') {
    document.getElementById('pinLabel').textContent = 'Create New PIN (6 digits)';
    document.getElementById('pinNewLabel').style.display = 'block';
  } else if (mode === 'confirm') {
    document.getElementById('pinLabel').textContent = 'Confirm PIN';
    document.getElementById('pinNewLabel').style.display = 'none';
  } else {
    document.getElementById('pinLabel').textContent = 'Enter PIN';
    document.getElementById('pinNewLabel').style.display = 'none';
  }
  
  const bioWrap = document.getElementById('pinBioWrap');
  if (mode === 'unlock' && localStorage.getItem('rl6_bio_id')) {
    bioWrap.style.display = 'block';
  } else {
    bioWrap.style.display = 'none';
  }
}

export function pinKey(n) {
  if (_pinBuf.length >= 6) return;
  _pinBuf += n;
  updatePinDots();
  if (_pinBuf.length === 6) {
    setTimeout(pinSubmit, 250);
  }
}

export function pinDel() {
  _pinBuf = _pinBuf.slice(0, -1);
  updatePinDots();
}

function updatePinDots() {
  for (let i = 0; i < 6; i++) {
    document.getElementById('pd' + i).className = 'pin-dot' + (i < _pinBuf.length ? ' act' : '');
  }
}

async function pinSubmit() {
  if (_pinMode === 'unlock') {
    try {
      const r = await loadEncryptedSKs(_pinBuf);
      sessionStorage.setItem('rl6_session_pin', _pinBuf);
      document.getElementById('pinScreen').style.display = 'none';
      if (_pinResolve) _pinResolve(r);
    } catch {
      _pinBuf = '';
      flashDots('err');
      document.getElementById('pinErr').textContent = 'Wrong PIN. Try again.';
    }
  } else if (_pinMode === 'setup') {
    _pinFirst = _pinBuf;
    _pinMode = 'confirm';
    _pinBuf = '';
    updatePinDots();
    document.getElementById('pinLabel').textContent = 'Confirm PIN';
  } else if (_pinMode === 'confirm') {
    if (_pinBuf === _pinFirst) {
      sessionStorage.setItem('rl6_session_pin', _pinBuf);
      document.getElementById('pinScreen').style.display = 'none';
      if (_pinResolve) _pinResolve({ pin: _pinBuf });
    } else {
      _pinBuf = '';
      flashDots('err');
      document.getElementById('pinErr').textContent = 'PINs do not match. Start over.';
      setTimeout(() => showPinScreen('setup'), 1000);
    }
  }
}

function flashDots(cls) {
  for (let i = 0; i < 6; i++) document.getElementById('pd' + i).className = 'pin-dot ' + cls;
  setTimeout(updatePinDots, 600);
}

export async function tryBiometric() {
  const pin = await bioUnlock();
  if (pin) {
    _pinBuf = pin; await pinSubmit();
  } else {
    document.getElementById('pinErr').textContent = 'Biometric failed. Enter PIN.';
  }
}

// ── Biometric (WebAuthn) ──

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
      timeout: 60000
    }});
    if (cred) {
      localStorage.setItem('rl6_bio_id', hex(new Uint8Array(cred.rawId)));
      return true;
    }
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
      timeout: 60000
    }});
    return sessionStorage.getItem('rl6_session_pin');
  } catch {}
  return null;
}
