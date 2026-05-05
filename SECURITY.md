# Security Policy

## Supported Versions

RELAY is currently in active development. Only the latest commit on `main` receives security fixes.

## Cryptographic Primitives

All primitives are implemented in pure JavaScript and verified against official NIST test vectors:

| Primitive | Standard | Role | Verified |
|-----------|----------|------|---------|
| ML-KEM-768 | FIPS 203 | Key encapsulation | ✓ NIST KAT vectors |
| ML-DSA-44  | FIPS 204 | Digital signatures | ✓ NIST KAT vectors |
| SHA3-256/512, SHAKE-128/256 | FIPS 202 | Hashing / XOF | ✓ NIST test vectors |
| secp256k1 + Schnorr BIP340 | Nostr protocol | Transport signing | ✓ BIP340 vectors |
| AES-256-GCM | NIST | Symmetric encryption | WebCrypto (browser) |
| PBKDF2-SHA256 (310,000 iter) | NIST | PIN key derivation | WebCrypto (browser) |
| HKDF-SHA256 | RFC 5869 | KDF | WebCrypto (browser) |

## Privacy Architecture

- **No IP disclosure**: all WebRTC uses `iceTransportPolicy:'relay'` — no STUN, no direct paths
- **Sealed Sender**: every message uses a throwaway ephemeral Nostr keypair; the relay cannot correlate sender ↔ recipient
- **Traffic padding**: dummy events indistinguishable from real ones are sent to all peers at random 5–14s intervals
- **Onion routing**: when ≥2 peers are online, messages route through 2 intermediate hops (mini-Tor model)
- **Deniable authentication**: HMAC-SHA256 tags derived from the shared Double Ratchet secret; neither party can prove authorship to a third party
- **Key transparency**: every key change event is logged and ML-DSA-44 signed; users can audit the full history

## Known Limitations

1. **JavaScript crypto**: all cryptographic operations run in the browser main thread. Side-channel attacks (timing, cache) are harder to prevent in JavaScript than in native code. The `yieldUI()` helper (MessageChannel-based) is used to prevent UI blocking but does not provide timing isolation.

2. **Single-file deployment**: the current build is a single `index.html` for ease of offline use and Netlify hosting. A Vite/React build with proper CSP headers is planned.

3. **TURN credentials**: the Cloudflare TURN token and Oracle TURN credentials in this repository are **public demo credentials** for evaluation only. For production, provision your own TURN server. See `src/transport/webrtc.js`.

4. **WebAuthn biometric**: biometric auth retrieves the session PIN from `sessionStorage` after first correct PIN entry. If the browser clears `sessionStorage` (e.g., on app restart), the PIN must be re-entered. This is intentional.

5. **Nostr relay trust**: Nostr relays see encrypted ciphertext and sender/recipient ephemeral pubkeys. With Sealed Sender enabled (default), the relay cannot determine the real sender. However, timing correlation attacks are possible if only one relay is used.

## Reporting a Vulnerability

Please report security vulnerabilities privately via GitHub Security Advisories or by emailing the maintainer directly. Do not open a public issue for security bugs.

Response commitment: acknowledgement within 72 hours, patch timeline communicated within 7 days.

## Scope

In scope:
- Cryptographic implementation bugs
- Protocol-level privacy leaks
- Key management flaws
- Authentication bypasses

Out of scope:
- TURN server infrastructure (third-party)
- Nostr relay infrastructure (third-party)
- Browser/OS-level vulnerabilities

## Acknowledgements

This project builds on the work of the Nostr protocol community, the CRYSTALS team (Kyber/Dilithium), and the Signal protocol specification.
