# Contributing to RELAY

Thank you for your interest in contributing to RELAY.

## Getting Started

RELAY is a single-page application with no build step required for development.

```bash
git clone https://github.com/boomstrickweb/rmessage.git
cd relay
# Open index.html in a browser, or serve with any static server:
npx serve .
```

For a development server with ES module support:

```bash
npm install -g vite
vite
```

## File Structure

```
relay/
├── index.html            # Entry point — UI shell (no JS logic here)
├── src/
│   ├── app.js            # Boot sequence — start here
│   ├── utils.js          # Shared byte utilities
│   ├── crypto/
│   │   ├── sha3.js       # FIPS 202
│   │   ├── secp256k1.js  # Nostr signing
│   │   ├── mlkem.js      # FIPS 203 (ML-KEM-768)
│   │   ├── mldsa.js      # FIPS 204 (ML-DSA-44)
│   │   └── ratchet.js    # Double Ratchet + HKDF + padding helpers
│   ├── transport/
│   │   ├── nostr.js      # WebSocket relay connections
│   │   ├── webrtc.js     # PCManager: voice + DataChannel
│   │   ├── onion.js      # Onion routing + heartbeat
│   │   ├── padding.js    # Traffic padding + Sealed Sender
│   │   └── events.js     # Incoming event dispatcher
│   ├── storage/
│   │   ├── crdt.js       # CRDT message store + IndexedDB
│   │   └── pin.js        # PIN/biometric key encryption
│   └── ui/
│       ├── render.js     # Contact list, message rendering
│       └── settings.js   # Settings, peer management, wipe
└── README.md
```

## Code Style

- Pure ES modules (`type="module"`)
- No dependencies (no npm packages in production)
- Every crypto function includes a comment referencing the relevant FIPS section
- All UI strings in English; no hardcoded Azerbaijani or other language strings

## Cryptography Guidelines

- Do not replace or remove existing crypto primitives without a documented rationale
- Any changes to ML-KEM or ML-DSA must be re-verified against NIST KAT vectors
- New crypto features must include a section in `SECURITY.md` describing the threat model

## Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Keep commits focused and well-described
4. Open a PR with a clear description of what changed and why
5. Security-sensitive PRs should reference the relevant threat model or CVE
5. Open a PR with a clear description of what changed and why
6. Security-sensitive PRs should reference the relevant threat model or CVE
#
