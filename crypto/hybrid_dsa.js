// Copyright (c) 2026 Signer.io — MIT License

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
// Stripping resistance: the Ed25519 component signs a domain-prefixed message
// ("hybrid-dsa-v1" + len(ctx) + ctx + message), preventing extraction of
// the Ed25519 signature for standalone use outside the hybrid context.
//
// Sizes:
//     Secret key:  4,096 bytes  (Ed25519 sk 64B + ML-DSA-65 sk 4,032B)
//     Public key:  1,984 bytes  (Ed25519 pk 32B + ML-DSA-65 pk 1,952B)
//     Signature:   3,373 bytes  (Ed25519 sig 64B + ML-DSA-65 sig 3,309B)
//
// NOT constant-time. For side-channel-resistant deployments, use C/Rust.

const { ed25519Keygen, ed25519Sign, ed25519Verify } = require("./ed25519");
const { mlKeygen, mlSign, mlVerify } = require("./ml_dsa");

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

// Domain prefix for stripping resistance
const _DOMAIN = new TextEncoder().encode("hybrid-dsa-v1");

function _ed25519Message(message, ctx) {
  if (ctx.length > 255) {
    throw new Error(`Context string must be 0-255 bytes, got ${ctx.length}`);
  }
  const out = new Uint8Array(_DOMAIN.length + 1 + ctx.length + message.length);
  out.set(_DOMAIN);
  out[_DOMAIN.length] = ctx.length;
  out.set(ctx, _DOMAIN.length + 1);
  out.set(message, _DOMAIN.length + 1 + ctx.length);
  return out;
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

  const edResult = ed25519Keygen(seed.subarray(0, 32));
  const mlResult = mlKeygen(seed.subarray(32, 64));

  const sk = new Uint8Array(HYBRID_DSA_SK_SIZE);
  sk.set(edResult.sk);
  sk.set(mlResult.sk, _ED25519_SK);

  const pk = new Uint8Array(HYBRID_DSA_PK_SIZE);
  pk.set(edResult.pk);
  pk.set(mlResult.pk, _ED25519_PK);

  return { sk, pk };
}

/**
 * Sign with both Ed25519 and ML-DSA-65.
 *
 * @param {Uint8Array} message - Arbitrary-length message bytes
 * @param {Uint8Array} sk - 4,096-byte hybrid secret key
 * @param {Uint8Array} [ctx=new Uint8Array(0)] - Context string (0-255 bytes)
 * @returns {Uint8Array} 3,373-byte hybrid signature
 */
function hybridDsaSign(message, sk, ctx) {
  if (ctx === undefined || ctx === null) ctx = new Uint8Array(0);
  if (sk.length !== HYBRID_DSA_SK_SIZE) {
    throw new Error(`Hybrid DSA sk must be ${HYBRID_DSA_SK_SIZE} bytes, got ${sk.length}`);
  }

  const edSk = sk.subarray(0, _ED25519_SK);
  const mlSk = sk.subarray(_ED25519_SK);

  // Ed25519 signs domain-prefixed message (stripping resistance)
  const edSig = ed25519Sign(_ed25519Message(message, ctx), edSk);

  // ML-DSA signs raw message with its native context parameter
  const mlSig = mlSign(message, mlSk, ctx);

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
 * @returns {boolean}
 */
function hybridDsaVerify(message, sig, pk, ctx) {
  if (ctx === undefined || ctx === null) ctx = new Uint8Array(0);
  if (sig.length !== HYBRID_DSA_SIG_SIZE) return false;
  if (pk.length !== HYBRID_DSA_PK_SIZE) return false;

  const edSig = sig.subarray(0, _ED25519_SIG);
  const mlSig = sig.subarray(_ED25519_SIG);
  const edPk = pk.subarray(0, _ED25519_PK);
  const mlPk = pk.subarray(_ED25519_PK);

  // Both must verify
  if (!ed25519Verify(_ed25519Message(message, ctx), edSig, edPk)) return false;
  if (!mlVerify(message, mlSig, mlPk, ctx)) return false;

  return true;
}

module.exports = {
  hybridDsaKeygen,
  hybridDsaSign,
  hybridDsaVerify,
  HYBRID_DSA_SK_SIZE,
  HYBRID_DSA_PK_SIZE,
  HYBRID_DSA_SIG_SIZE,
};
