# RELAY — Post-Quantum Secure Messenger

A browser-based, end-to-end encrypted peer-to-peer messenger implementing FIPS 203/204 post-quantum cryptographic standards.

## Cryptographic Design

| Layer | Algorithm | Standard |
|-------|-----------|----------|
| Key Encapsulation | ML-KEM-768 (Kyber) | FIPS 203 |
| Digital Signatures | ML-DSA-44 (Dilithium) | FIPS 204 |
| Hashing / XOF | SHA3-256, SHA3-512, SHAKE-128/256 | FIPS 202 |
| Transport Signing | secp256k1 + Schnorr BIP340 | Nostr protocol |
| Message Encryption | AES-256-GCM | NIST |
| Forward Secrecy | Double Ratchet over ML-KEM | Signal-derived |
| Deniable Auth | HMAC-SHA256 (shared DR epoch key) | Signal-derived |
| Metadata Protection | Sealed Sender + Traffic Padding + Onion Routing | — |

## Architecture

```
Text messages  → Nostr relay  (Sealed Sender · Double Ratchet · ML-KEM)
Media / Files  → CF TURN DataChannel  (chunked · ML-KEM per chunk)
Voice calls    → CF TURN relay-only  (DTLS-SRTP · ML-KEM epoch rotation)
```

- **iceTransportPolicy: 'relay'** on ALL WebRTC connections — no IP leaks
- **Sealed Sender**: relay cannot correlate sender ↔ recipient
- **Onion Routing**: 2-hop mini-Tor when ≥2 peers online
- **Traffic Padding**: constant-stream dummy events between all peers
- **Key Transparency**: every key change logged + ML-DSA signed
- **Emergency Wipe**: 3-second hold wipes all keys, messages, DR state

## Project Structure

```
relay/
├── index.html                  # Entry point — UI shell
├── src/
│   ├── crypto/
│   │   ├── sha3.js             # FIPS 202: SHA3-256/512, SHAKE-128/256
│   │   ├── secp256k1.js        # secp256k1 + Schnorr BIP340
│   │   ├── mlkem.js            # FIPS 203: ML-KEM-768 (Kyber)
│   │   ├── mldsa.js            # FIPS 204: ML-DSA-44 (Dilithium)
│   │   └── ratchet.js          # Double Ratchet + HKDF
│   ├── transport/
│   │   ├── nostr.js            # Nostr relay WebSocket transport
│   │   ├── webrtc.js           # PCManager: DataChannel + call audio
│   │   ├── onion.js            # Onion routing (2-hop)
│   │   └── padding.js          # Traffic padding + Sealed Sender
│   ├── storage/
│   │   ├── crdt.js             # CRDT message store
│   │   ├── idb.js              # IndexedDB media store
│   │   └── pin.js              # PIN/biometric key encryption
│   └── ui/
│       ├── render.js           # Contact list, message rendering
│       ├── call.js             # Call screen, visualizer, timer
│       └── settings.js         # Settings, peer management, key transparency
└── README.md
```

## Security Properties

- **Forward Secrecy**: Double Ratchet advances per message; call epoch rotates every 60s
- **Post-Compromise Security**: ratchet re-seeds from fresh KEM ephemeral on every receive step
- **No IP Disclosure**: all WebRTC uses TURN relay only (`iceTransportPolicy:'relay'`)
- **Metadata resistance**: Sealed Sender hides sender identity from relay; onion routing hides routing graph; traffic padding hides communication patterns
- **Deniability**: HMAC auth tag derived from shared DR secret — neither party can prove authorship to a third party
- **Key Transparency**: full audit log of key changes, signed with ML-DSA

## Transport

- **Nostr relays**: `wss://relay.damus.io`, `wss://nos.lol`, `wss://relay.nostr.info`
- **TURN**: Cloudflare TURN (primary) + Oracle TURN (fallback)
- **Media limit**: 25 MB per file (TURN quota protection)

## Privacy Notes

The Cloudflare TURN API token and Oracle TURN credentials in this repository are **public demo credentials** intended for evaluation. For production deployment, provision your own TURN server.
