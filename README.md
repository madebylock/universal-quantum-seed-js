# Universal Quantum Seed — JavaScript Edition

The world's first quantum-safe visual + multilingual seed phrase system.

**Pure JavaScript. Zero dependencies. Browser + Node.js compatible.**

272-bit entropy | Post-quantum cryptography | 42 languages | 256 icons | 16-bit checksum

---

## Features

- **36-word quantum-safe seeds** — 272-bit entropy survives Grover's algorithm
- **42 languages** — Write your seed in any language, recover in any other
- **256 visual icons** — Skip words entirely and select icons
- **Post-quantum cryptography** — ML-DSA-65, SLH-DSA-SHAKE-128s, ML-KEM-768
- **Pure JavaScript** — SHA-2, SHA-3, HMAC, HKDF, PBKDF2, NTT — all from scratch
- **Zero dependencies** — No npm packages required

## Installation

```bash
npm install universal-quantum-seed
```

Or copy the folder directly into your project.

## Quick Start

```javascript
const uqs = require("universal-quantum-seed");

// Generate a 36-word quantum-safe seed
const words = uqs.generateWords(36);
console.log(words.map(w => w.word).join(" "));

// Derive a master key
const seed = uqs.getSeed(words.map(w => w.index), "optional passphrase");

// Generate a quantum-safe signing keypair (ML-DSA-65)
const kp = uqs.generateQuantumKeypair(seed, "ml-dsa-65", 0);
// kp.sk = 4032 bytes, kp.pk = 1952 bytes

// Sign and verify
const msg = new TextEncoder().encode("Hello quantum world");
const sig = uqs.mlSign(msg, kp.sk);
const valid = uqs.mlVerify(msg, sig, kp.pk);
// valid === true

// ML-KEM-768 key encapsulation
const kemKp = uqs.generateQuantumKeypair(seed, "ml-kem-768", 0);
const { ct, ss } = uqs.mlKemEncaps(kemKp.pk);
const ss2 = uqs.mlKemDecaps(kemKp.sk, ct);
// ss and ss2 are identical 32-byte shared secrets
```

## API

### Seed Generation & Lookup

| Function | Description |
|----------|-------------|
| `generateWords(count, extraEntropy?, lang?)` | Generate random seed words |
| `resolve(words, strict?)` | Resolve words/indexes to canonical indexes |
| `search(prefix, limit?)` | Search words by prefix |
| `getLanguages()` | List available languages |
| `verifyChecksum(seed)` | Verify seed checksum |

### Key Derivation

| Function | Description |
|----------|-------------|
| `getSeed(indexes, passphrase?)` | Derive 64-byte master key (PBKDF2-SHA512) |
| `getProfile(masterKey, password?)` | Derive profile key |
| `getFingerprint(seed, passphrase?)` | 8-char hex fingerprint |
| `getEntropyBits(wordCount, passphrase?)` | Calculate entropy bits |

### Post-Quantum Cryptography

| Function | Description |
|----------|-------------|
| `getQuantumSeed(masterKey, algorithm, keyIndex)` | Derive algorithm-specific seed |
| `generateQuantumKeypair(masterKey, algorithm, keyIndex)` | Generate PQC keypair |

**ML-DSA-65** (FIPS 204 — Digital Signature)

| Function | Description |
|----------|-------------|
| `mlKeygen(seed)` | Generate signing keypair (SK: 4032B, PK: 1952B) |
| `mlSign(msg, sk, ctx?)` | Sign message (3309B signature) |
| `mlVerify(msg, sig, pk, ctx?)` | Verify signature |

**SLH-DSA-SHAKE-128s** (FIPS 205 — Hash-Based Signature)

| Function | Description |
|----------|-------------|
| `slhKeygen(seed)` | Generate signing keypair (SK: 64B, PK: 32B) |
| `slhSign(msg, sk, ctx?)` | Sign message (7856B signature) |
| `slhVerify(msg, sig, pk, ctx?)` | Verify signature |

**ML-KEM-768** (FIPS 203 — Key Encapsulation)

| Function | Description |
|----------|-------------|
| `mlKemKeygen(seed)` | Generate KEM keypair (EK: 1184B, DK: 2400B) |
| `mlKemEncaps(ek, randomness?)` | Encapsulate (CT: 1088B, SS: 32B) |
| `mlKemDecaps(dk, ct)` | Decapsulate (SS: 32B) |

### Hash Functions

| Function | Description |
|----------|-------------|
| `sha3_256(data)` | SHA3-256 (32 bytes) |
| `sha3_512(data)` | SHA3-512 (64 bytes) |
| `shake128(data, len)` | SHAKE-128 (variable length) |
| `shake256(data, len)` | SHAKE-256 (variable length) |
| `sha256(data)` | SHA-256 (32 bytes) |
| `sha512(data)` | SHA-512 (64 bytes) |
| `hmacSha256(key, data)` | HMAC-SHA256 |
| `hmacSha512(key, data)` | HMAC-SHA512 |

### Entropy & Testing

| Function | Description |
|----------|-------------|
| `MouseEntropy` | Class for collecting mouse entropy in browsers |
| `verifyRandomness(bytes, size?, samples?)` | Statistical randomness tests |

## Supported Languages

Arabic, Bengali, Chinese (Simplified, Traditional, Cantonese), Czech, Danish, Dutch, English, Filipino, French, German, Greek, Hausa, Hebrew, Hindi, Hungarian, Icelandic, Indonesian, Irish, Italian, Japanese, Korean, Luxembourgish, Malay, Marathi, Norwegian, Persian, Polish, Portuguese, Punjabi, Romanian, Russian, Spanish, Swahili, Tamil, Telugu, Thai, Turkish, Ukrainian, Urdu, Vietnamese

## Post-Quantum Algorithms

| Algorithm | Standard | Security Level | Use Case |
|-----------|----------|---------------|----------|
| ML-DSA-65 | FIPS 204 | Level 3 (192-bit) | Digital signatures |
| SLH-DSA-SHAKE-128s | FIPS 205 | Level 1 (128-bit) | Hash-based signatures (stateless) |
| ML-KEM-768 | FIPS 203 | Level 3 (192-bit) | Key encapsulation |

## Building

Language data files (`data/languages/*.py`) are copies of the Python edition's originals. To regenerate `words.js` after updating language files:

```bash
python tools/compile-js.py
```

## Compatibility

- **Node.js** >= 16.0.0
- **Browsers** — Any browser with BigInt support (Chrome 67+, Firefox 68+, Safari 14+)
- Uses `crypto.getRandomValues()` (browser) or `crypto.randomBytes()` (Node.js) for entropy

## Note on KDF

The JavaScript edition uses PBKDF2-SHA512 with 600,000 iterations for key derivation. The Python edition additionally supports Argon2id (which requires native bindings). PBKDF2 produces identical outputs cross-platform and is suitable for production use.

## License

MIT License — see [LICENSE](LICENSE)
