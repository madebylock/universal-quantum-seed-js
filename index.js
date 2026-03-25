// Copyright (c) 2026 Signer.io — MIT License

"use strict";

// Universal Quantum Seed — JavaScript Edition
//
// Pure JavaScript implementation of the Universal Quantum Seed system
// with post-quantum cryptography (ML-DSA-65, SLH-DSA-SHAKE-128s, ML-KEM-768).
//
// Zero dependencies. Browser + Node.js compatible.

const seed = require("./seed");
const crypto = require("./crypto");

module.exports = {
  // ── Seed Generation & Lookup ───────────────────────────
  generateWords: seed.generateWords,
  resolve: seed.resolve,
  search: seed.search,
  getLanguages: seed.getLanguages,
  verifyChecksum: seed.verifyChecksum,

  // ── Key Derivation ─────────────────────────────────────
  getSeed: seed.getSeed,
  getSeedAsync: seed.getSeedAsync,
  getProfile: seed.getProfile,
  getFingerprint: seed.getFingerprint,
  getEntropyBits: seed.getEntropyBits,

  // ── Post-Quantum Cryptography ──────────────────────────
  getQuantumSeed: seed.getQuantumSeed,
  generateQuantumKeypair: seed.generateQuantumKeypair,

  // ML-DSA-65 (FIPS 204) — Digital Signature
  mlKeygen: crypto.mlKeygen,
  mlSign: crypto.mlSign,
  mlVerify: crypto.mlVerify,
  mlSignWithContext: crypto.mlSignWithContext,
  mlVerifyWithContext: crypto.mlVerifyWithContext,
  mlSignAsync: crypto.mlSignAsync,
  mlVerifyAsync: crypto.mlVerifyAsync,

  // SLH-DSA-SHAKE-128s (FIPS 205) — Hash-Based Signature
  slhKeygen: crypto.slhKeygen,
  slhSign: crypto.slhSign,
  slhVerify: crypto.slhVerify,
  slhSignWithContext: crypto.slhSignWithContext,
  slhVerifyWithContext: crypto.slhVerifyWithContext,
  slhSignAsync: crypto.slhSignAsync,
  slhVerifyAsync: crypto.slhVerifyAsync,

  // ML-KEM-768 (FIPS 203) — Key Encapsulation
  mlKemKeygen: crypto.mlKemKeygen,
  mlKemEncaps: crypto.mlKemEncaps,
  mlKemDecaps: crypto.mlKemDecaps,

  // Ed25519 (RFC 8032) — Classical Digital Signature
  ed25519Keygen: crypto.ed25519Keygen,
  ed25519Sign: crypto.ed25519Sign,
  ed25519Verify: crypto.ed25519Verify,

  // X25519 (RFC 7748) — Classical Key Exchange
  x25519Keygen: crypto.x25519Keygen,
  x25519: crypto.x25519,

  // Hybrid Ed25519 + ML-DSA-65 — Classical + PQ Signature
  hybridDsaKeygen: crypto.hybridDsaKeygen,
  hybridDsaSign: crypto.hybridDsaSign,
  hybridDsaVerify: crypto.hybridDsaVerify,

  // Hybrid X25519 + ML-KEM-768 — Classical + PQ KEM
  hybridKemKeygen: crypto.hybridKemKeygen,
  hybridKemEncaps: crypto.hybridKemEncaps,
  hybridKemDecaps: crypto.hybridKemDecaps,

  // Argon2id (RFC 9106) — Memory-hard KDF
  argon2id: crypto.argon2id,
  blake2b: crypto.blake2b,

  // AES-256-GCM (NIST SP 800-38D) — Authenticated Encryption
  aesGcmEncrypt: crypto.aesGcmEncrypt,
  aesGcmDecrypt: crypto.aesGcmDecrypt,
  aesGcmEncryptAsync: crypto.aesGcmEncryptAsync,
  aesGcmDecryptAsync: crypto.aesGcmDecryptAsync,

  // ── Hash Functions ─────────────────────────────────────
  sha3_256: crypto.sha3_256,
  sha3_512: crypto.sha3_512,
  shake128: crypto.shake128,
  shake256: crypto.shake256,
  sha256: crypto.sha256,
  sha512: crypto.sha512,
  hmacSha256: crypto.hmacSha256,
  hmacSha512: crypto.hmacSha512,
  hkdfExpand: crypto.hkdfExpand,
  hkdfExpandSha256: crypto.hkdfExpandSha256,
  hkdfExtractSha256: crypto.hkdfExtractSha256,
  pbkdf2Sha512: crypto.pbkdf2Sha512,
  pbkdf2Sha512Async: crypto.pbkdf2Sha512Async,

  // ── Entropy & Testing ──────────────────────────────────
  MouseEntropy: seed.MouseEntropy,
  verifyRandomness: seed.verifyRandomness,
  kdfInfo: seed.kdfInfo,

  // ── Constants ──────────────────────────────────────────
  VERSION: seed.VERSION,
  DARK_VISUALS: seed.DARK_VISUALS,
  BASE_WORDS: seed.BASE_WORDS,
};
