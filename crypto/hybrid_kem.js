// Copyright (c) 2026 Signer.io — MIT License

"use strict";

// Hybrid X25519 + ML-KEM-768 key encapsulation mechanism.
//
// Both shared secrets are combined via HKDF with ciphertext binding.
// Security holds as long as *either* X25519 or ML-KEM-768 remains unbroken.
//
// X25519 provides classical (pre-quantum) security (~128-bit).
// ML-KEM-768 provides post-quantum security (NIST Level 3, ~192-bit).
//
// The combined shared secret is derived via HKDF-Extract + HKDF-Expand with
// both shared secrets as input keying material and a ciphertext-derived salt,
// preventing ciphertext substitution attacks.
//
// Sizes:
//     Encapsulation key (public): 1,216 bytes  (X25519 pk 32B + ML-KEM ek 1,184B)
//     Decapsulation key (secret): 2,432 bytes  (X25519 sk 32B + ML-KEM dk 2,400B)
//     Ciphertext:                 1,120 bytes  (X25519 eph_pk 32B + ML-KEM ct 1,088B)
//     Shared secret:                 32 bytes
//
// NOT constant-time. For side-channel-resistant deployments, use C/Rust.

const { x25519Keygen, x25519 } = require("./x25519");
const { mlKemKeygen, mlKemEncaps, mlKemDecaps } = require("./ml_kem");
const { sha256, hmacSha256 } = require("./sha2");
const { randomBytes } = require("./utils");

// Component sizes
const _X25519_SK = 32;
const _X25519_PK = 32;
const _ML_KEM_EK = 1184;
const _ML_KEM_DK = 2400;
const _ML_KEM_CT = 1088;

// Hybrid sizes
const HYBRID_KEM_EK_SIZE = _X25519_PK + _ML_KEM_EK;    // 1,216
const HYBRID_KEM_DK_SIZE = _X25519_SK + _ML_KEM_DK;    // 2,432
const HYBRID_KEM_CT_SIZE = _X25519_PK + _ML_KEM_CT;    // 1,120

/**
 * Combine X25519 and ML-KEM shared secrets via ciphertext-bound HKDF.
 *
 *   salt = SHA-256(x25519_ct || ml_kem_ct)
 *   PRK  = HMAC-SHA256(salt, x25519_ss || ml_kem_ss)    // HKDF-Extract
 *   SS   = HMAC-SHA256(PRK, "hybrid-kem-v1" || 0x01)    // HKDF-Expand
 */
function _combineSecrets(x25519Ss, mlKemSs, x25519Ct, mlKemCt) {
  // salt = SHA-256(x25519_ct || ml_kem_ct)
  const ctConcat = new Uint8Array(x25519Ct.length + mlKemCt.length);
  ctConcat.set(x25519Ct);
  ctConcat.set(mlKemCt, x25519Ct.length);
  const salt = sha256(ctConcat);

  // PRK = HMAC-SHA256(salt, x25519_ss || ml_kem_ss)
  const ssConcat = new Uint8Array(x25519Ss.length + mlKemSs.length);
  ssConcat.set(x25519Ss);
  ssConcat.set(mlKemSs, x25519Ss.length);
  const prk = hmacSha256(salt, ssConcat);

  // SS = HMAC-SHA256(PRK, "hybrid-kem-v1" || 0x01)
  const info = new Uint8Array([
    0x68, 0x79, 0x62, 0x72, 0x69, 0x64, 0x2d, 0x6b, // "hybrid-k"
    0x65, 0x6d, 0x2d, 0x76, 0x31, // "em-v1"
    0x01, // counter byte
  ]);
  return hmacSha256(prk, info);
}

/**
 * Generate hybrid X25519 + ML-KEM-768 keypair.
 *
 * @param {Uint8Array} seed - 96-byte seed (first 32B → X25519, last 64B → ML-KEM-768 d||z)
 * @returns {{ ek: Uint8Array, dk: Uint8Array }} ek: 1,216 bytes, dk: 2,432 bytes
 */
function hybridKemKeygen(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 96) {
    throw new Error(`Hybrid KEM seed must be a 96-byte Uint8Array, got ${seed ? seed.length : 0}`);
  }

  const xResult = x25519Keygen(seed.subarray(0, 32));
  const mlResult = mlKemKeygen(seed.subarray(32, 96));

  const ek = new Uint8Array(HYBRID_KEM_EK_SIZE);
  ek.set(xResult.pk);
  ek.set(mlResult.ek, _X25519_PK);

  const dk = new Uint8Array(HYBRID_KEM_DK_SIZE);
  dk.set(xResult.sk);
  dk.set(mlResult.dk, _X25519_SK);

  return { ek, dk };
}

/**
 * Encapsulate: produce hybrid ciphertext and combined shared secret.
 *
 * @param {Uint8Array} ek - 1,216-byte hybrid encapsulation key
 * @param {Uint8Array} [randomnessIn] - 64 bytes (32B X25519 ephemeral + 32B ML-KEM), or null
 * @returns {{ ct: Uint8Array, ss: Uint8Array }} ct: 1,120 bytes, ss: 32 bytes
 */
function hybridKemEncaps(ek, randomnessIn) {
  if (!(ek instanceof Uint8Array) || ek.length !== HYBRID_KEM_EK_SIZE) {
    throw new Error(`Hybrid KEM ek must be ${HYBRID_KEM_EK_SIZE} bytes, got ${ek ? ek.length : 0}`);
  }

  const rnd = randomnessIn || randomBytes(64);
  if (rnd.length !== 64) {
    throw new Error(`Randomness must be 64 bytes, got ${rnd.length}`);
  }

  const xPk = ek.subarray(0, _X25519_PK);
  const mlEk = ek.subarray(_X25519_PK);

  // X25519 ephemeral key exchange
  const eph = x25519Keygen(rnd.subarray(0, 32));
  const xSs = x25519(eph.sk, xPk);

  // ML-KEM encapsulation
  const mlResult = mlKemEncaps(mlEk, rnd.subarray(32, 64));

  // Combine shared secrets with ciphertext binding
  const ct = new Uint8Array(HYBRID_KEM_CT_SIZE);
  ct.set(eph.pk);
  ct.set(mlResult.ct, _X25519_PK);

  const ss = _combineSecrets(xSs, mlResult.ss, eph.pk, mlResult.ct);

  return { ct, ss };
}

/**
 * Decapsulate: recover combined shared secret from hybrid ciphertext.
 *
 * @param {Uint8Array} dk - 2,432-byte hybrid decapsulation key
 * @param {Uint8Array} ct - 1,120-byte hybrid ciphertext
 * @returns {Uint8Array} 32-byte combined shared secret
 */
function hybridKemDecaps(dk, ct) {
  if (!(dk instanceof Uint8Array) || dk.length !== HYBRID_KEM_DK_SIZE) {
    throw new Error(`Hybrid KEM dk must be ${HYBRID_KEM_DK_SIZE} bytes, got ${dk ? dk.length : 0}`);
  }
  if (!(ct instanceof Uint8Array) || ct.length !== HYBRID_KEM_CT_SIZE) {
    throw new Error(`Hybrid KEM ct must be ${HYBRID_KEM_CT_SIZE} bytes, got ${ct ? ct.length : 0}`);
  }

  const xSk = dk.subarray(0, _X25519_SK);
  const mlDk = dk.subarray(_X25519_SK);
  const ephPk = ct.subarray(0, _X25519_PK);
  const mlCt = ct.subarray(_X25519_PK);

  // X25519 shared secret recovery
  const xSs = x25519(xSk, ephPk);

  // ML-KEM decapsulation
  const mlSs = mlKemDecaps(mlDk, mlCt);

  // Combine shared secrets with ciphertext binding
  return _combineSecrets(xSs, mlSs, ephPk, mlCt);
}

module.exports = {
  hybridKemKeygen,
  hybridKemEncaps,
  hybridKemDecaps,
  HYBRID_KEM_EK_SIZE,
  HYBRID_KEM_DK_SIZE,
  HYBRID_KEM_CT_SIZE,
};
