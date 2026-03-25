// Copyright (c) 2026 Signer.io — MIT License

"use strict";

const { sha3_256, sha3_512, shake128, shake256, shake128Xof, shake256Xof } = require("./sha3");
const { sha256, sha512, hmacSha256, hmacSha512, hkdfExpand, hkdfExpandSha256, hkdfExtractSha256, pbkdf2Sha512, pbkdf2Sha512Async } = require("./sha2");
const { mlKeygen, mlSign, mlVerify, mlSignWithContext, mlVerifyWithContext, mlSignAsync, mlVerifyAsync } = require("./ml_dsa");
const { slhKeygen, slhSign, slhVerify, slhSignWithContext, slhVerifyWithContext, slhSignAsync, slhVerifyAsync } = require("./slh_dsa");
const { mlKemKeygen, mlKemEncaps, mlKemDecaps } = require("./ml_kem");
const { ed25519Keygen, ed25519Sign, ed25519Verify } = require("./ed25519");
const { x25519Keygen, x25519 } = require("./x25519");
const { hybridDsaKeygen, hybridDsaSign, hybridDsaVerify } = require("./hybrid_dsa");
const { hybridKemKeygen, hybridKemEncaps, hybridKemDecaps } = require("./hybrid_kem");
const { argon2id, blake2b } = require("./argon2");
const { aesGcmEncrypt, aesGcmDecrypt, aesGcmEncryptAsync, aesGcmDecryptAsync } = require("./aes_gcm");

module.exports = {
  // SHA-3 / Keccak
  sha3_256, sha3_512, shake128, shake256, shake128Xof, shake256Xof,

  // SHA-2 / HMAC / HKDF / PBKDF2
  sha256, sha512, hmacSha256, hmacSha512, hkdfExpand, hkdfExpandSha256, hkdfExtractSha256, pbkdf2Sha512, pbkdf2Sha512Async,

  // ML-DSA-65 (FIPS 204) — Post-quantum digital signature
  mlKeygen, mlSign, mlVerify, mlSignWithContext, mlVerifyWithContext, mlSignAsync, mlVerifyAsync,

  // SLH-DSA-SHAKE-128s (FIPS 205) — Post-quantum hash-based signature
  slhKeygen, slhSign, slhVerify, slhSignWithContext, slhVerifyWithContext, slhSignAsync, slhVerifyAsync,

  // ML-KEM-768 (FIPS 203) — Post-quantum key encapsulation
  mlKemKeygen, mlKemEncaps, mlKemDecaps,

  // Ed25519 (RFC 8032) — Classical digital signature
  ed25519Keygen, ed25519Sign, ed25519Verify,

  // X25519 (RFC 7748) — Classical key exchange
  x25519Keygen, x25519,

  // Hybrid Ed25519 + ML-DSA-65 — Classical + post-quantum signature
  hybridDsaKeygen, hybridDsaSign, hybridDsaVerify,

  // Hybrid X25519 + ML-KEM-768 — Classical + post-quantum KEM
  hybridKemKeygen, hybridKemEncaps, hybridKemDecaps,

  // Argon2id (RFC 9106) — Memory-hard KDF
  argon2id, blake2b,

  // AES-256-GCM (NIST SP 800-38D) — Symmetric authenticated encryption
  aesGcmEncrypt, aesGcmDecrypt,
  aesGcmEncryptAsync, aesGcmDecryptAsync,
};
