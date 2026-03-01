// Copyright (c) 2026 Signer.io — MIT License

"use strict";

// AES-256-GCM authenticated encryption (NIST SP 800-38D).
// Pure JavaScript fallback. When Node.js crypto is available, uses native
// OpenSSL AES-GCM (constant-time, hardware-accelerated via AES-NI).
//
// Sizes:
//   Key:   32 bytes (AES-256)
//   Nonce: 12 bytes (96-bit, recommended per NIST SP 800-38D)
//   Tag:   16 bytes (128-bit, appended to ciphertext)
//
// References:
//   - NIST SP 800-38D: Galois/Counter Mode of Operation (GCM)
//   - FIPS 197: Advanced Encryption Standard (AES)

const { toBytes } = require("./utils");

// --- Native Node.js crypto fast path ---

let _nativeEncrypt = null;
let _nativeDecrypt = null;

try {
  const nodeCrypto = require("crypto");
  _nativeEncrypt = function(key, nonce, plaintext, aad) {
    const cipher = nodeCrypto.createCipheriv("aes-256-gcm", key, nonce);
    if (aad && aad.length > 0) cipher.setAAD(aad);
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const result = new Uint8Array(ct.length + 16);
    result.set(ct, 0);
    result.set(tag, ct.length);
    return result;
  };
  _nativeDecrypt = function(key, nonce, ciphertextWithTag, aad) {
    const ct = ciphertextWithTag.slice(0, ciphertextWithTag.length - 16);
    const tag = ciphertextWithTag.slice(ciphertextWithTag.length - 16);
    const decipher = nodeCrypto.createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAuthTag(tag);
    if (aad && aad.length > 0) decipher.setAAD(aad);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
    return new Uint8Array(plain);
  };
} catch (_) {
  // Native crypto not available — pure JS fallback (e.g. browser)
}

// --- AES S-Box ---

const SBOX = new Uint8Array([
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]);

const RCON = new Uint8Array([0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]);

// --- AES-256 internals ---

function xtime(a) {
  return ((a << 1) ^ (((a >>> 7) & 1) * 0x1b)) & 0xff;
}

function keyExpansion(key) {
  const w = new Uint8Array(240);
  w.set(key);
  for (let i = 8; i < 60; i++) {
    let t0 = w[(i - 1) * 4], t1 = w[(i - 1) * 4 + 1];
    let t2 = w[(i - 1) * 4 + 2], t3 = w[(i - 1) * 4 + 3];
    if (i % 8 === 0) {
      const tmp = t0;
      t0 = SBOX[t1] ^ RCON[i / 8 - 1];
      t1 = SBOX[t2]; t2 = SBOX[t3]; t3 = SBOX[tmp];
    } else if (i % 8 === 4) {
      t0 = SBOX[t0]; t1 = SBOX[t1]; t2 = SBOX[t2]; t3 = SBOX[t3];
    }
    const base = (i - 8) * 4;
    w[i * 4]     = w[base]     ^ t0;
    w[i * 4 + 1] = w[base + 1] ^ t1;
    w[i * 4 + 2] = w[base + 2] ^ t2;
    w[i * 4 + 3] = w[base + 3] ^ t3;
  }
  return w;
}

function aesBlock(s, rk) {
  // AddRoundKey(0)
  for (let i = 0; i < 16; i++) s[i] ^= rk[i];
  for (let r = 1; r <= 14; r++) {
    // SubBytes
    for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    // ShiftRows
    let t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
    // MixColumns (skip on last round)
    if (r < 14) {
      for (let c = 0; c < 16; c += 4) {
        const a0 = s[c], a1 = s[c + 1], a2 = s[c + 2], a3 = s[c + 3];
        s[c]     = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
        s[c + 1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
        s[c + 2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
        s[c + 3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
      }
    }
    // AddRoundKey
    const off = r * 16;
    for (let i = 0; i < 16; i++) s[i] ^= rk[off + i];
  }
}

// --- GCM internals ---

function incCtr(ctr) {
  for (let i = 15; i >= 12; i--) {
    ctr[i] = (ctr[i] + 1) & 0xff;
    if (ctr[i] !== 0) break;
  }
}

function ghashMul(X, Y) {
  const V = new Uint8Array(16);
  V.set(Y);
  const Z = new Uint8Array(16);
  for (let i = 0; i < 128; i++) {
    if ((X[i >>> 3] >>> (7 - (i & 7))) & 1) {
      for (let j = 0; j < 16; j++) Z[j] ^= V[j];
    }
    const lsb = V[15] & 1;
    for (let j = 15; j > 0; j--) V[j] = (V[j] >>> 1) | ((V[j - 1] & 1) << 7);
    V[0] >>>= 1;
    if (lsb) V[0] ^= 0xe1;
  }
  return Z;
}

function ghash(H, data) {
  let Y = new Uint8Array(16);
  for (let off = 0; off < data.length; off += 16) {
    const end = Math.min(16, data.length - off);
    for (let i = 0; i < end; i++) Y[i] ^= data[off + i];
    Y = ghashMul(Y, H);
  }
  return Y;
}

function pad16(len) {
  const r = len % 16;
  return r === 0 ? 0 : 16 - r;
}

function buildGhashInput(aad, ct) {
  const aadPad = pad16(aad.length);
  const ctPad = pad16(ct.length);
  const input = new Uint8Array(aad.length + aadPad + ct.length + ctPad + 16);
  input.set(aad, 0);
  input.set(ct, aad.length + aadPad);
  // Length block: len_AAD (64-bit) || len_CT (64-bit), big-endian, in bits
  const lenOff = input.length - 16;
  const aadBits = aad.length * 8;
  const ctBits = ct.length * 8;
  // AAD length (upper 8 bytes — only lower 32 bits used for practical sizes)
  input[lenOff + 4] = (aadBits >>> 24) & 0xff;
  input[lenOff + 5] = (aadBits >>> 16) & 0xff;
  input[lenOff + 6] = (aadBits >>> 8)  & 0xff;
  input[lenOff + 7] =  aadBits         & 0xff;
  // CT length (lower 8 bytes)
  input[lenOff + 12] = (ctBits >>> 24) & 0xff;
  input[lenOff + 13] = (ctBits >>> 16) & 0xff;
  input[lenOff + 14] = (ctBits >>> 8)  & 0xff;
  input[lenOff + 15] =  ctBits         & 0xff;
  return input;
}

// --- Public API ---

/**
 * Encrypt with AES-256-GCM.
 *
 * @param {Uint8Array} key - 32-byte AES-256 key.
 * @param {Uint8Array} nonce - 12-byte nonce (must never be reused with the same key).
 * @param {Uint8Array|string} plaintext - Data to encrypt.
 * @param {Uint8Array} [aad] - Additional authenticated data (optional).
 * @returns {Uint8Array} ciphertext || tag (16 bytes appended).
 */
function aesGcmEncrypt(key, nonce, plaintext, aad) {
  key = toBytes(key);
  nonce = toBytes(nonce);
  plaintext = toBytes(plaintext);
  aad = aad ? toBytes(aad) : new Uint8Array(0);

  if (key.length !== 32) throw new Error("Key must be 32 bytes, got " + key.length);
  if (nonce.length !== 12) throw new Error("Nonce must be 12 bytes, got " + nonce.length);

  if (_nativeEncrypt) return _nativeEncrypt(key, nonce, plaintext, aad);

  // Pure-JS fallback
  const rk = keyExpansion(key);

  // H = AES_K(0^128)
  const H = new Uint8Array(16);
  aesBlock(H, rk);

  // J0 = nonce || 0x00000001
  const J0 = new Uint8Array(16);
  J0.set(nonce);
  J0[15] = 1;

  // Encrypt with AES-CTR starting at J0+1
  const ct = new Uint8Array(plaintext.length);
  const ctr = new Uint8Array(J0);
  for (let off = 0; off < plaintext.length; off += 16) {
    incCtr(ctr);
    const ks = new Uint8Array(ctr);
    aesBlock(ks, rk);
    const end = Math.min(16, plaintext.length - off);
    for (let i = 0; i < end; i++) ct[off + i] = plaintext[off + i] ^ ks[i];
  }

  // Compute tag
  const ghashInput = buildGhashInput(aad, ct);
  const tag = ghash(H, ghashInput);
  const encJ0 = new Uint8Array(J0);
  aesBlock(encJ0, rk);
  for (let i = 0; i < 16; i++) tag[i] ^= encJ0[i];

  // Return ct || tag
  const result = new Uint8Array(ct.length + 16);
  result.set(ct, 0);
  result.set(tag, ct.length);
  return result;
}

/**
 * Decrypt with AES-256-GCM.
 *
 * @param {Uint8Array} key - 32-byte AES-256 key.
 * @param {Uint8Array} nonce - 12-byte nonce.
 * @param {Uint8Array} ciphertextWithTag - Ciphertext with 16-byte tag appended.
 * @param {Uint8Array} [aad] - Additional authenticated data (optional).
 * @returns {Uint8Array} Decrypted plaintext.
 * @throws {Error} If the authentication tag does not verify.
 */
function aesGcmDecrypt(key, nonce, ciphertextWithTag, aad) {
  key = toBytes(key);
  nonce = toBytes(nonce);
  ciphertextWithTag = toBytes(ciphertextWithTag);
  aad = aad ? toBytes(aad) : new Uint8Array(0);

  if (key.length !== 32) throw new Error("Key must be 32 bytes, got " + key.length);
  if (nonce.length !== 12) throw new Error("Nonce must be 12 bytes, got " + nonce.length);
  if (ciphertextWithTag.length < 16) throw new Error("Ciphertext too short (must include 16-byte tag)");

  if (_nativeDecrypt) return _nativeDecrypt(key, nonce, ciphertextWithTag, aad);

  // Pure-JS fallback
  const ct = ciphertextWithTag.slice(0, ciphertextWithTag.length - 16);
  const receivedTag = ciphertextWithTag.slice(ciphertextWithTag.length - 16);

  const rk = keyExpansion(key);

  // H = AES_K(0^128)
  const H = new Uint8Array(16);
  aesBlock(H, rk);

  // J0 = nonce || 0x00000001
  const J0 = new Uint8Array(16);
  J0.set(nonce);
  J0[15] = 1;

  // Verify tag
  const ghashInput = buildGhashInput(aad, ct);
  const computedTag = ghash(H, ghashInput);
  const encJ0 = new Uint8Array(J0);
  aesBlock(encJ0, rk);
  for (let i = 0; i < 16; i++) computedTag[i] ^= encJ0[i];

  // Constant-time tag comparison
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= computedTag[i] ^ receivedTag[i];
  if (diff !== 0) throw new Error("AES-GCM: authentication tag mismatch");

  // Decrypt
  const plaintext = new Uint8Array(ct.length);
  const ctr = new Uint8Array(J0);
  for (let off = 0; off < ct.length; off += 16) {
    incCtr(ctr);
    const ks = new Uint8Array(ctr);
    aesBlock(ks, rk);
    const end = Math.min(16, ct.length - off);
    for (let i = 0; i < end; i++) plaintext[off + i] = ct[off + i] ^ ks[i];
  }

  return plaintext;
}

module.exports = { aesGcmEncrypt, aesGcmDecrypt };
