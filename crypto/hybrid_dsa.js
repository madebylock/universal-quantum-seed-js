// Copyright (c) 2026 Lock.com — MIT License

"use strict";

// Hybrid Ed25519 + ML-DSA-65 digital signature scheme.
//
// AND-composition: both algorithms must independently verify for the hybrid
// signature to be valid. Security holds as long as *either* Ed25519 or
// ML-DSA-65 remains unbroken.
//
// Ed25519 provides classical (pre-quantum) security (~128-bit).
// ML-DSA-65 provides post-quantum security (NIST Level 3, ~192-bit).
//
// Stripping resistance: BOTH component signatures are domain-separated so
// neither can be extracted and used as a valid standalone signature:
//     Ed25519 signs: "hybrid-dsa-v1" || len(ctx) || ctx || message
//     ML-DSA signs the same domain-prefixed message with empty FIPS context,
//       allowing the pqcrypto backend while preserving stripping resistance.
//
// Sizes:
//     Secret key:  4,096 bytes  (Ed25519 sk 64B + ML-DSA-65 sk 4,032B)
//     Public key:  1,984 bytes  (Ed25519 pk 32B + ML-DSA-65 pk 1,952B)
//     Signature:   3,373 bytes  (Ed25519 sig 64B + ML-DSA-65 sig 3,309B)
//
// Best-effort constant-time. For hardware side-channel resistance, use C/Rust.

const { ed25519Keygen, ed25519Sign, ed25519Verify } = require("./ed25519");
const { mlKeygen, mlSignWithContext, mlVerifyWithContext } = require("./ml_dsa");
const { toBytes, zeroize } = require("./utils");

// Component sizes
const _ED25519_SK = 64;
const _ED25519_PK = 32;
const _ED25519_SIG = 64;
const _ML_DSA_SK = 4032;
const _ML_DSA_PK = 1952;
const _ML_DSA_SIG = 3309;

// Hybrid sizes
const HYBRID_DSA_SK_SIZE = _ED25519_SK + _ML_DSA_SK;    // 4,096
const HYBRID_DSA_PK_SIZE = _ED25519_PK + _ML_DSA_PK;    // 1,984
const HYBRID_DSA_SIG_SIZE = _ED25519_SIG + _ML_DSA_SIG;  // 3,373
const HYBRID_DSA_COMPONENT_ALGORITHMS = Object.freeze(["Ed25519", "ML-DSA-65"]);

// Domain prefix for stripping resistance.
const _DOMAIN = new TextEncoder().encode("hybrid-dsa-v1");
const HYBRID_DSA_VERSION = 1;
const SUPPORTED_HYBRID_DSA_VERSIONS = Object.freeze([HYBRID_DSA_VERSION]);

function normalizeHybridDsaVersion(version = HYBRID_DSA_VERSION) {
  if (version === undefined || version === null || version === "") return HYBRID_DSA_VERSION;
  let versionNumber;
  if (typeof version === "string") {
    let raw = version.trim().toLowerCase();
    if (raw.startsWith("v")) raw = raw.slice(1);
    if (!/^\d+$/.test(raw)) {
      throw new Error(`Unsupported hybrid DSA version: ${version}`);
    }
    versionNumber = Number(raw);
  } else {
    versionNumber = Number(version);
  }
  if (!Number.isInteger(versionNumber) || !SUPPORTED_HYBRID_DSA_VERSIONS.includes(versionNumber)) {
    throw new Error(`Unsupported hybrid DSA version: ${versionNumber}`);
  }
  return versionNumber;
}

function getSupportedHybridDsaVersions() {
  return [...SUPPORTED_HYBRID_DSA_VERSIONS];
}

function _domainForVersion(version = HYBRID_DSA_VERSION) {
  normalizeHybridDsaVersion(version);
  return _DOMAIN;
}

// Ed25519 message: domain || len(ctx) || ctx || message
// Prevents Ed25519 signature from being used standalone.
function _ed25519Message(message, ctx, version = HYBRID_DSA_VERSION) {
  if (ctx.length > 255) {
    throw new Error(`Context string must be 0-255 bytes, got ${ctx.length}`);
  }
  const domain = _domainForVersion(version);
  const out = new Uint8Array(domain.length + 1 + ctx.length + message.length);
  out.set(domain);
  out[domain.length] = ctx.length;
  out.set(ctx, domain.length + 1);
  out.set(message, domain.length + 1 + ctx.length);
  return out;
}

// ML-DSA message: domain || len(ctx) || ctx || message
// Signs with empty FIPS context so the pqcrypto C backend can sign the
// component. The domain and caller context are still bound into the signed
// bytes, so the ML-DSA signature remains non-portable outside the hybrid
// scheme.
function _mlDsaMessage(message, ctx, version = HYBRID_DSA_VERSION) {
  return _ed25519Message(message, ctx, version);
}

/**
 * Generate hybrid Ed25519 + ML-DSA-65 keypair.
 *
 * @param {Uint8Array} seed - 64-byte seed (first 32B → Ed25519, last 32B → ML-DSA-65)
 * @returns {{ sk: Uint8Array, pk: Uint8Array }} sk: 4,096 bytes, pk: 1,984 bytes
 */
function hybridDsaKeygen(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 64) {
    throw new Error(`Hybrid DSA seed must be a 64-byte Uint8Array, got ${seed ? seed.length : 0}`);
  }

  // Copy halves into independent buffers so we can wipe them after keygen
  // without touching the caller's seed argument.
  const edSeed = seed.slice(0, 32);
  const mlSeed = seed.slice(32, 64);
  try {
    const edResult = ed25519Keygen(edSeed);
    const mlResult = mlKeygen(mlSeed);

    const sk = new Uint8Array(HYBRID_DSA_SK_SIZE);
    sk.set(edResult.sk);
    sk.set(mlResult.sk, _ED25519_SK);

    const pk = new Uint8Array(HYBRID_DSA_PK_SIZE);
    pk.set(edResult.pk);
    pk.set(mlResult.pk, _ED25519_PK);

    return { sk, pk };
  } finally {
    zeroize(edSeed);
    zeroize(mlSeed);
  }
}

/**
 * Sign with both Ed25519 and ML-DSA-65.
 *
 * @param {Uint8Array} message - Arbitrary-length message bytes
 * @param {Uint8Array} sk - 4,096-byte hybrid secret key
 * @param {Uint8Array} [ctx=new Uint8Array(0)] - Context string (0-255 bytes)
 * @param {number|string} [version=1] - Hybrid DSA wire-format version
 * @returns {Uint8Array} 3,373-byte hybrid signature
 */
function hybridDsaSign(message, sk, ctx, version = HYBRID_DSA_VERSION) {
  message = toBytes(message);
  if (ctx === undefined || ctx === null) ctx = new Uint8Array(0);
  else ctx = toBytes(ctx);
  if (sk.length !== HYBRID_DSA_SK_SIZE) {
    throw new Error(`Hybrid DSA sk must be ${HYBRID_DSA_SK_SIZE} bytes, got ${sk.length}`);
  }
  if (ctx.length > 255) {
    throw new Error(`Context string must be 0-255 bytes for hybrid DSA, got ${ctx.length}`);
  }
  version = normalizeHybridDsaVersion(version);

  const edSk = sk.subarray(0, _ED25519_SK);
  const mlSk = sk.subarray(_ED25519_SK);

  // Ed25519: signs domain-prefixed message (stripping resistance)
  const edMsg = _ed25519Message(message, ctx, version);
  const edSig = ed25519Sign(edMsg, edSk);
  zeroize(edMsg);

  // ML-DSA: signs domain-prefixed message with empty FIPS context so
  // pqcrypto can provide the production signing backend.
  const mlMsg = _mlDsaMessage(message, ctx, version);
  const mlSig = mlSignWithContext(mlMsg, mlSk, new Uint8Array(0));

  const sig = new Uint8Array(HYBRID_DSA_SIG_SIZE);
  sig.set(edSig);
  sig.set(mlSig, _ED25519_SIG);
  return sig;
}

/**
 * Verify hybrid Ed25519 + ML-DSA-65 signature.
 * BOTH component signatures must independently verify.
 *
 * @param {Uint8Array} message - Original message bytes
 * @param {Uint8Array} sig - 3,373-byte hybrid signature
 * @param {Uint8Array} pk - 1,984-byte hybrid public key
 * @param {Uint8Array} [ctx=new Uint8Array(0)] - Context string
 * @param {number|string} [version=1] - Hybrid DSA wire-format version
 * @returns {boolean}
 */
function hybridDsaVerify(message, sig, pk, ctx, version = HYBRID_DSA_VERSION) {
  message = toBytes(message);
  if (ctx === undefined || ctx === null) ctx = new Uint8Array(0);
  else ctx = toBytes(ctx);
  if (sig.length !== HYBRID_DSA_SIG_SIZE) return false;
  if (pk.length !== HYBRID_DSA_PK_SIZE) return false;
  if (ctx.length > 255) return false;
  try {
    version = normalizeHybridDsaVersion(version);
  } catch (_e) {
    return false;
  }

  const edSig = sig.subarray(0, _ED25519_SIG);
  const mlSig = sig.subarray(_ED25519_SIG);
  const edPk = pk.subarray(0, _ED25519_PK);
  const mlPk = pk.subarray(_ED25519_PK);

  // Ed25519: verify domain-prefixed message
  const edMsg = _ed25519Message(message, ctx, version);
  const edOk = ed25519Verify(edMsg, edSig, edPk);

  // ML-DSA: verify domain-prefixed message with empty FIPS context.
  const mlMsg = _mlDsaMessage(message, ctx, version);
  const mlOk = mlVerifyWithContext(mlMsg, mlSig, mlPk, new Uint8Array(0));

  return edOk && mlOk;
}

module.exports = {
  hybridDsaKeygen,
  hybridDsaSign,
  hybridDsaVerify,
  normalizeHybridDsaVersion,
  getSupportedHybridDsaVersions,
  HYBRID_DSA_VERSION,
  SUPPORTED_HYBRID_DSA_VERSIONS,
  HYBRID_DSA_SK_SIZE,
  HYBRID_DSA_PK_SIZE,
  HYBRID_DSA_SIG_SIZE,
  HYBRID_DSA_COMPONENT_ALGORITHMS,
};
