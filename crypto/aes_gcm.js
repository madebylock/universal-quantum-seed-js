// Copyright (c) 2026 Lock.com — PolyForm Shield License 1.0.0

"use strict";

// AES-256-GCM authenticated encryption (NIST SP 800-38D).
//
// Two implementations live in this module:
//   1. Native OpenSSL AES-GCM through Node.js crypto, taken only when the
//      surrounding module system can resolve "crypto". The browser bundles
//      register their own require that never resolves Node built-ins, so a
//      bundle always runs implementation 2, in Node.js as well as in browsers.
//   2. A constant-time pure JavaScript implementation. This is the production
//      path for every browser context without crypto.subtle, which includes
//      plain http://<LAN address> origins (SubtleCrypto exists only in secure
//      contexts), so the web app encrypts every WebSocket frame with it there.
//      AES is bitsliced in the BearSSL aes_ct layout with the Boyar-Peralta
//      S-box circuit, so no memory access is indexed by a key or state byte;
//      GHASH folds every state bit into a mask, so no branch depends on the
//      key, the hash subkey or the data.
//
// Sizes:
//   Key:   32 bytes (AES-256)
//   Nonce: 12 bytes (96-bit, recommended per NIST SP 800-38D)
//   Tag:   16 bytes (128-bit, appended to ciphertext)
//
// References:
//   - NIST SP 800-38D: Galois/Counter Mode of Operation (GCM)
//   - FIPS 197: Advanced Encryption Standard (AES)
//   - BearSSL aes_ct.c and aes_ct_enc.c (bitslice layout, orthogonalization,
//     round functions and key schedule ported below)
//   - Boyar and Peralta, "A depth-16 circuit for the AES S-box" (the
//     113-gate S-box circuit)

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
  // Native crypto not available: pure JS constant-time path (browsers, bundles)
}

// --- Bitsliced AES-256 (constant time) ---
//
// The bitslice layout, orthogonalization, ShiftRows, MixColumns and key
// schedule below are ported from BearSSL (src/symcipher/aes_ct.c and
// aes_ct_enc.c):
//
//   Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
//
//   Permission is hereby granted, free of charge, to any person obtaining
//   a copy of this software and associated documentation files (the
//   "Software"), to deal in the Software without restriction, including
//   without limitation the rights to use, copy, modify, merge, publish,
//   distribute, sublicense, and/or sell copies of the Software, and to
//   permit persons to whom the Software is furnished to do so, subject to
//   the following conditions:
//
//   The above copyright notice and this permission notice shall be
//   included in all copies or substantial portions of the Software.
//
//   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
//   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
//   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
//   LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
//   OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
//   WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// State layout: two 16-byte blocks are held in eight 32-bit words q[0..7].
// Before orthogonalization q[0], q[2], q[4], q[6] are the four little-endian
// words of block 0 and q[1], q[3], q[5], q[7] those of block 1. After it,
// word q[b] holds bit b of all 32 state bytes, with the bit for byte
// (row r, column c) of block k at position 8 * r + 2 * c + k. ShiftRows is
// then a rotation inside each 8-bit group, MixColumns a fixed pattern of
// word rotations and XORs, and SubBytes a boolean circuit evaluated on the
// eight words at once. Every step is a fixed sequence of AND, OR, XOR and
// shift operations whose operands never select an address or a branch.

// Round constants, indexed only by the public round counter.
const RCON = new Uint8Array([0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]);

function swapN(q, i, j, cl, ch, s) {
  const a = q[i], b = q[j];
  q[i] = (a & cl) | ((b & cl) << s);
  q[j] = ((a & ch) >>> s) | (b & ch);
}

function ortho(q) {
  // Bit-matrix transpose between the byte layout and the bitsliced layout.
  // The transform is an involution: applying it twice restores the input.
  swapN(q, 0, 1, 0x55555555, 0xAAAAAAAA, 1);
  swapN(q, 2, 3, 0x55555555, 0xAAAAAAAA, 1);
  swapN(q, 4, 5, 0x55555555, 0xAAAAAAAA, 1);
  swapN(q, 6, 7, 0x55555555, 0xAAAAAAAA, 1);

  swapN(q, 0, 2, 0x33333333, 0xCCCCCCCC, 2);
  swapN(q, 1, 3, 0x33333333, 0xCCCCCCCC, 2);
  swapN(q, 4, 6, 0x33333333, 0xCCCCCCCC, 2);
  swapN(q, 5, 7, 0x33333333, 0xCCCCCCCC, 2);

  swapN(q, 0, 4, 0x0F0F0F0F, 0xF0F0F0F0, 4);
  swapN(q, 1, 5, 0x0F0F0F0F, 0xF0F0F0F0, 4);
  swapN(q, 2, 6, 0x0F0F0F0F, 0xF0F0F0F0, 4);
  swapN(q, 3, 7, 0x0F0F0F0F, 0xF0F0F0F0, 4);
}

function bitsliceSbox(q) {
  // SubBytes on all 32 state bytes at once: the Boyar-Peralta circuit for the
  // AES S-box (113 gates) evaluated bitwise over the eight state words.
  // Inputs x0..x7 and outputs s0..s7 are numbered from the high bit down.
  const x0 = q[7], x1 = q[6], x2 = q[5], x3 = q[4];
  const x4 = q[3], x5 = q[2], x6 = q[1], x7 = q[0];

  // Top linear transformation.
  const y14 = x3 ^ x5;
  const y13 = x0 ^ x6;
  const y9 = x0 ^ x3;
  const y8 = x0 ^ x5;
  const t0 = x1 ^ x2;
  const y1 = t0 ^ x7;
  const y4 = y1 ^ x3;
  const y12 = y13 ^ y14;
  const y2 = y1 ^ x0;
  const y5 = y1 ^ x6;
  const y3 = y5 ^ y8;
  const t1 = x4 ^ y12;
  const y15 = t1 ^ x5;
  const y20 = t1 ^ x1;
  const y6 = y15 ^ x7;
  const y10 = y15 ^ t0;
  const y11 = y20 ^ y9;
  const y7 = x7 ^ y11;
  const y17 = y10 ^ y11;
  const y19 = y10 ^ y8;
  const y16 = t0 ^ y11;
  const y21 = y13 ^ y16;
  const y18 = x0 ^ y16;

  // Non-linear section.
  const t2 = y12 & y15;
  const t3 = y3 & y6;
  const t4 = t3 ^ t2;
  const t5 = y4 & x7;
  const t6 = t5 ^ t2;
  const t7 = y13 & y16;
  const t8 = y5 & y1;
  const t9 = t8 ^ t7;
  const t10 = y2 & y7;
  const t11 = t10 ^ t7;
  const t12 = y9 & y11;
  const t13 = y14 & y17;
  const t14 = t13 ^ t12;
  const t15 = y8 & y10;
  const t16 = t15 ^ t12;
  const t17 = t4 ^ t14;
  const t18 = t6 ^ t16;
  const t19 = t9 ^ t14;
  const t20 = t11 ^ t16;
  const t21 = t17 ^ y20;
  const t22 = t18 ^ y19;
  const t23 = t19 ^ y21;
  const t24 = t20 ^ y18;

  const t25 = t21 ^ t22;
  const t26 = t21 & t23;
  const t27 = t24 ^ t26;
  const t28 = t25 & t27;
  const t29 = t28 ^ t22;
  const t30 = t23 ^ t24;
  const t31 = t22 ^ t26;
  const t32 = t31 & t30;
  const t33 = t32 ^ t24;
  const t34 = t23 ^ t33;
  const t35 = t27 ^ t33;
  const t36 = t24 & t35;
  const t37 = t36 ^ t34;
  const t38 = t27 ^ t36;
  const t39 = t29 & t38;
  const t40 = t25 ^ t39;

  const t41 = t40 ^ t37;
  const t42 = t29 ^ t33;
  const t43 = t29 ^ t40;
  const t44 = t33 ^ t37;
  const t45 = t42 ^ t41;
  const z0 = t44 & y15;
  const z1 = t37 & y6;
  const z2 = t33 & x7;
  const z3 = t43 & y16;
  const z4 = t40 & y1;
  const z5 = t29 & y7;
  const z6 = t42 & y11;
  const z7 = t45 & y17;
  const z8 = t41 & y10;
  const z9 = t44 & y12;
  const z10 = t37 & y3;
  const z11 = t33 & y4;
  const z12 = t43 & y13;
  const z13 = t40 & y5;
  const z14 = t29 & y2;
  const z15 = t42 & y9;
  const z16 = t45 & y14;
  const z17 = t41 & y8;

  // Bottom linear transformation.
  const t46 = z15 ^ z16;
  const t47 = z10 ^ z11;
  const t48 = z5 ^ z13;
  const t49 = z9 ^ z10;
  const t50 = z2 ^ z12;
  const t51 = z2 ^ z5;
  const t52 = z7 ^ z8;
  const t53 = z0 ^ z3;
  const t54 = z6 ^ z7;
  const t55 = z16 ^ z17;
  const t56 = z12 ^ t48;
  const t57 = t50 ^ t53;
  const t58 = z4 ^ t46;
  const t59 = z3 ^ t54;
  const t60 = t46 ^ t57;
  const t61 = z14 ^ t57;
  const t62 = t52 ^ t58;
  const t63 = t49 ^ t58;
  const t64 = z4 ^ t59;
  const t65 = t61 ^ t62;
  const t66 = z1 ^ t63;
  const s0 = t59 ^ t63;
  const s6 = t56 ^ ~t62;
  const s7 = t48 ^ ~t60;
  const t67 = t64 ^ t65;
  const s3 = t53 ^ t66;
  const s4 = t51 ^ t66;
  const s5 = t47 ^ t65;
  const s1 = t64 ^ ~s3;
  const s2 = t55 ^ ~t67;

  q[7] = s0;
  q[6] = s1;
  q[5] = s2;
  q[4] = s3;
  q[3] = s4;
  q[2] = s5;
  q[1] = s6;
  q[0] = s7;
}

function shiftRows(q) {
  for (let i = 0; i < 8; i++) {
    const x = q[i];
    q[i] = (x & 0x000000FF)
      | ((x & 0x0000FC00) >>> 2) | ((x & 0x00000300) << 6)
      | ((x & 0x00F00000) >>> 4) | ((x & 0x000F0000) << 4)
      | ((x & 0xC0000000) >>> 6) | ((x & 0x3F000000) << 2);
  }
}

function rotr8(x) {
  return (x >>> 8) | (x << 24);
}

function rotr16(x) {
  return (x >>> 16) | (x << 16);
}

function mixColumns(q) {
  const q0 = q[0], q1 = q[1], q2 = q[2], q3 = q[3];
  const q4 = q[4], q5 = q[5], q6 = q[6], q7 = q[7];
  const r0 = rotr8(q0), r1 = rotr8(q1), r2 = rotr8(q2), r3 = rotr8(q3);
  const r4 = rotr8(q4), r5 = rotr8(q5), r6 = rotr8(q6), r7 = rotr8(q7);

  q[0] = q7 ^ r7 ^ r0 ^ rotr16(q0 ^ r0);
  q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ rotr16(q1 ^ r1);
  q[2] = q1 ^ r1 ^ r2 ^ rotr16(q2 ^ r2);
  q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ rotr16(q3 ^ r3);
  q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ rotr16(q4 ^ r4);
  q[5] = q4 ^ r4 ^ r5 ^ rotr16(q5 ^ r5);
  q[6] = q5 ^ r5 ^ r6 ^ rotr16(q6 ^ r6);
  q[7] = q6 ^ r6 ^ r7 ^ rotr16(q7 ^ r7);
}

function addRoundKey(q, skey, off) {
  for (let i = 0; i < 8; i++) q[i] ^= skey[off + i];
}

function aesEncryptPair(skey, q) {
  // AES-256 (14 rounds) on the two orthogonalized blocks held in q.
  addRoundKey(q, skey, 0);
  for (let r = 1; r < 14; r++) {
    bitsliceSbox(q);
    shiftRows(q);
    mixColumns(q);
    addRoundKey(q, skey, r << 3);
  }
  bitsliceSbox(q);
  shiftRows(q);
  addRoundKey(q, skey, 14 << 3);
}

function le32(b, off) {
  return b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24);
}

function storeLe32(out, off, x) {
  out[off] = x & 0xff;
  out[off + 1] = (x >>> 8) & 0xff;
  out[off + 2] = (x >>> 16) & 0xff;
  out[off + 3] = (x >>> 24) & 0xff;
}

function loadPair(q, a, aOff, b, bOff) {
  // Load block 0 from a[aOff..] and block 1 from b[bOff..] and orthogonalize.
  q[0] = le32(a, aOff);
  q[1] = le32(b, bOff);
  q[2] = le32(a, aOff + 4);
  q[3] = le32(b, bOff + 4);
  q[4] = le32(a, aOff + 8);
  q[5] = le32(b, bOff + 8);
  q[6] = le32(a, aOff + 12);
  q[7] = le32(b, bOff + 12);
  ortho(q);
}

function storePair(q, out) {
  // Undo the orthogonalization and write block 0 to out[0..15], block 1 to
  // out[16..31].
  ortho(q);
  storeLe32(out, 0, q[0]);
  storeLe32(out, 4, q[2]);
  storeLe32(out, 8, q[4]);
  storeLe32(out, 12, q[6]);
  storeLe32(out, 16, q[1]);
  storeLe32(out, 20, q[3]);
  storeLe32(out, 24, q[5]);
  storeLe32(out, 28, q[7]);
}

// AES-256 key schedule (FIPS 197 section 5.2). SubWord runs the key bytes
// through the same bitsliced S-box circuit as the rounds, so the schedule
// performs no lookup indexed by key material. The round keys are stored
// orthogonalized, ready for addRoundKey.

const _swq = new Int32Array(8);

function subWord(x) {
  const q = _swq;
  for (let i = 0; i < 8; i++) q[i] = x;
  ortho(q);
  bitsliceSbox(q);
  ortho(q);
  const r = q[0];
  q.fill(0);
  return r;
}

function keyExpansion(key) {
  const w = new Int32Array(60);
  for (let i = 0; i < 8; i++) w[i] = le32(key, i << 2);
  let tmp = w[7];
  for (let i = 8, j = 0, k = 0; i < 60; i++) {
    if (j === 0) {
      tmp = (tmp << 24) | (tmp >>> 8);
      tmp = subWord(tmp) ^ RCON[k];
    } else if (j === 4) {
      tmp = subWord(tmp);
    }
    tmp ^= w[i - 8];
    w[i] = tmp;
    if (++j === 8) {
      j = 0;
      k++;
    }
  }
  const skey = new Int32Array(120);
  const q = new Int32Array(8);
  for (let r = 0; r < 15; r++) {
    for (let c = 0; c < 4; c++) {
      q[c << 1] = w[(r << 2) + c];
      q[(c << 1) + 1] = w[(r << 2) + c];
    }
    ortho(q);
    skey.set(q, r << 3);
  }
  w.fill(0);
  q.fill(0);
  return skey;
}

// --- GCM internals ---

// NIST SP 800-38D maximum: 2^39 - 256 bits = (2^36 - 32) bytes
// NOTE: Must use Math.pow — JS bitwise shifts truncate to 32 bits.
const MAX_PLAINTEXT_BYTES = Math.pow(2, 36) - 32;
// NIST SP 800-38D §5.2.1.1: AAD <= 2^64 bits = 2^61 bytes - 1.
// JS Number.MAX_SAFE_INTEGER (2^53 - 1) is lower than the spec cap, so any
// AAD length JS can represent in a Uint8Array is already in-spec — but we
// still bound it explicitly to catch caller mistakes and to fail loudly if
// a future buffer-like type lifts the addressable size.
const MAX_AAD_BYTES = Number.MAX_SAFE_INTEGER;

function incCtr(ctr) {
  for (let i = 15; i >= 12; i--) {
    ctr[i] = (ctr[i] + 1) & 0xff;
    if (ctr[i] !== 0) return;
  }
  throw new Error(
    "AES-GCM: 32-bit counter exhausted (2^32 blocks). " +
    "Plaintext exceeds the NIST SP 800-38D maximum (~64 GB)."
  );
}

function wipeBuf(buf) {
  if (buf && typeof buf.fill === "function") buf.fill(0);
}

// Pre-allocated work buffers for GCM — eliminates thousands of
// per-block allocations that overwhelm GC in browsers
// without crypto.subtle (non-secure contexts like custom domains).
const _ghO = new Uint8Array(16);   // ghashMul output
const _q   = new Int32Array(8);    // bitsliced state (two blocks)
const _ks  = new Uint8Array(32);   // CTR input / keystream, two blocks
const _zero = new Uint8Array(16);

function ghashMul(Y, H) {
  // Multiply Y * H in GF(2^128) (SP 800-38D section 6.3), result written to
  // _ghO. Caller must copy _ghO before the next ghashMul call.
  // Bit-serial over the 128 bits of Y with the running multiple V held in
  // four 32-bit words. The bit of Y and the reduction feedback bit of V both
  // select through masks, never through a branch, so the sequence of
  // operations does not depend on Y, H or the data being hashed.
  let v0 = (H[0] << 24) | (H[1] << 16) | (H[2] << 8) | H[3];
  let v1 = (H[4] << 24) | (H[5] << 16) | (H[6] << 8) | H[7];
  let v2 = (H[8] << 24) | (H[9] << 16) | (H[10] << 8) | H[11];
  let v3 = (H[12] << 24) | (H[13] << 16) | (H[14] << 8) | H[15];
  let z0 = 0, z1 = 0, z2 = 0, z3 = 0;
  for (let i = 0; i < 128; i++) {
    const m = -((Y[i >>> 3] >>> (7 - (i & 7))) & 1);
    z0 ^= v0 & m;
    z1 ^= v1 & m;
    z2 ^= v2 & m;
    z3 ^= v3 & m;
    const f = -(v3 & 1);
    v3 = (v3 >>> 1) | (v2 << 31);
    v2 = (v2 >>> 1) | (v1 << 31);
    v1 = (v1 >>> 1) | (v0 << 31);
    v0 = (v0 >>> 1) ^ (0xe1000000 & f);
  }
  storeBe32(_ghO, 0, z0);
  storeBe32(_ghO, 4, z1);
  storeBe32(_ghO, 8, z2);
  storeBe32(_ghO, 12, z3);
}

function storeBe32(out, off, x) {
  out[off] = (x >>> 24) & 0xff;
  out[off + 1] = (x >>> 16) & 0xff;
  out[off + 2] = (x >>> 8) & 0xff;
  out[off + 3] = x & 0xff;
}

function ghashBlock(Y, H) {
  // In-place: Y = ghashMul(Y, H)
  ghashMul(Y, H);
  Y.set(_ghO);
}

function ghashUpdate(Y, H, data) {
  // Process data (with implicit zero-padding to 16-byte boundary)
  for (let off = 0; off < data.length; off += 16) {
    const end = Math.min(16, data.length - off);
    for (let i = 0; i < end; i++) Y[i] ^= data[off + i];
    ghashBlock(Y, H);
  }
}

function _xorGhashLength64(Y, offset, byteLen) {
  const bits = byteLen * 8;
  const hi = Math.floor(bits / 0x100000000);
  const lo = bits >>> 0;
  Y[offset]     ^= (hi >>> 24) & 0xff;
  Y[offset + 1] ^= (hi >>> 16) & 0xff;
  Y[offset + 2] ^= (hi >>> 8)  & 0xff;
  Y[offset + 3] ^=  hi         & 0xff;
  Y[offset + 4] ^= (lo >>> 24) & 0xff;
  Y[offset + 5] ^= (lo >>> 16) & 0xff;
  Y[offset + 6] ^= (lo >>> 8)  & 0xff;
  Y[offset + 7] ^=  lo         & 0xff;
}

function ghashFinalize(Y, H, aadLen, ctLen) {
  // Process the length block: len_AAD (64-bit) || len_CT (64-bit), in bits
  _xorGhashLength64(Y, 0, aadLen);
  _xorGhashLength64(Y, 8, ctLen);
  ghashBlock(Y, H);
}

function deriveHashSubkeyAndTagMask(skey, J0, H, ekJ0) {
  // One bitsliced pass yields H = E_K(0^128) (block 0) and E_K(J0) (block 1).
  loadPair(_q, _zero, 0, J0, 0);
  aesEncryptPair(skey, _q);
  storePair(_q, _ks);
  H.set(_ks.subarray(0, 16));
  ekJ0.set(_ks.subarray(16, 32));
}

function aesCtrXor(skey, ctr, src, dst) {
  // dst = src XOR AES-CTR keystream, two counter blocks per bitsliced pass.
  // incCtr runs once per consumed 16-byte block, exactly as many times as
  // there are blocks, so the NIST counter-exhaustion check is unchanged.
  const n = src.length;
  for (let off = 0; off < n; off += 32) {
    incCtr(ctr);
    _ks.set(ctr, 0);
    if (off + 16 < n) incCtr(ctr);
    _ks.set(ctr, 16);
    loadPair(_q, _ks, 0, _ks, 16);
    aesEncryptPair(skey, _q);
    storePair(_q, _ks);
    const end = Math.min(32, n - off);
    for (let i = 0; i < end; i++) dst[off + i] = src[off + i] ^ _ks[i];
  }
}

function wipeWorkBuffers() {
  wipeBuf(_q);
  wipeBuf(_ks);
  wipeBuf(_ghO);
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
  if (plaintext.length > MAX_PLAINTEXT_BYTES) {
    throw new Error("Plaintext (" + plaintext.length + " bytes) exceeds NIST SP 800-38D maximum");
  }
  if (aad.length > MAX_AAD_BYTES) {
    throw new Error("AAD (" + aad.length + " bytes) exceeds safe integer bound");
  }

  if (_nativeEncrypt) return _nativeEncrypt(key, nonce, plaintext, aad);

  // Pure-JS constant-time path
  const skey = keyExpansion(key);
  const H = new Uint8Array(16);
  const ekJ0 = new Uint8Array(16);

  try {
    // J0 = nonce || 0x00000001
    const J0 = new Uint8Array(16);
    J0.set(nonce);
    J0[15] = 1;

    deriveHashSubkeyAndTagMask(skey, J0, H, ekJ0);

    // Encrypt with AES-CTR starting at J0+1
    const ct = new Uint8Array(plaintext.length);
    const ctr = new Uint8Array(J0);
    aesCtrXor(skey, ctr, plaintext, ct);

    // Compute GHASH tag (streaming — no buildGhashInput allocation)
    const tag = new Uint8Array(16);
    ghashUpdate(tag, H, aad);
    ghashUpdate(tag, H, ct);
    ghashFinalize(tag, H, aad.length, ct.length);
    for (let i = 0; i < 16; i++) tag[i] ^= ekJ0[i];

    // Return ct || tag
    const result = new Uint8Array(ct.length + 16);
    result.set(ct, 0);
    result.set(tag, ct.length);
    return result;
  } finally {
    wipeBuf(skey);
    wipeBuf(H);
    wipeBuf(ekJ0);
    wipeWorkBuffers();
  }
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

  if (ciphertextWithTag.length - 16 > MAX_PLAINTEXT_BYTES) {
    throw new Error("Ciphertext payload (" + (ciphertextWithTag.length - 16) + " bytes) exceeds NIST SP 800-38D maximum");
  }
  if (aad.length > MAX_AAD_BYTES) {
    throw new Error("AAD (" + aad.length + " bytes) exceeds safe integer bound");
  }

  if (_nativeDecrypt) return _nativeDecrypt(key, nonce, ciphertextWithTag, aad);

  // Pure-JS constant-time path; subarray views avoid copying data
  const ctLen = ciphertextWithTag.length - 16;
  const ct = ciphertextWithTag.subarray(0, ctLen);
  const receivedTag = ciphertextWithTag.subarray(ctLen);

  const skey = keyExpansion(key);
  const H = new Uint8Array(16);
  const ekJ0 = new Uint8Array(16);

  try {
    // J0 = nonce || 0x00000001
    const J0 = new Uint8Array(16);
    J0.set(nonce);
    J0[15] = 1;

    deriveHashSubkeyAndTagMask(skey, J0, H, ekJ0);

    // Verify tag (streaming GHASH — no buildGhashInput allocation)
    const computedTag = new Uint8Array(16);
    ghashUpdate(computedTag, H, aad);
    ghashUpdate(computedTag, H, ct);
    ghashFinalize(computedTag, H, aad.length, ct.length);
    for (let i = 0; i < 16; i++) computedTag[i] ^= ekJ0[i];

    // Constant-time tag comparison
    let diff = 0;
    for (let i = 0; i < 16; i++) diff |= computedTag[i] ^ receivedTag[i];
    if (diff !== 0) throw new Error("AES-GCM: authentication tag mismatch");

    // Decrypt
    const plaintext = new Uint8Array(ct.length);
    const ctr = new Uint8Array(J0);
    aesCtrXor(skey, ctr, ct, plaintext);

    return plaintext;
  } finally {
    wipeBuf(skey);
    wipeBuf(H);
    wipeBuf(ekJ0);
    wipeWorkBuffers();
  }
}

// Track elapsed time since last GC yield.  Yielding on every operation
// adds ~1-4ms per call which makes page switches laggy.  Instead, yield
// every ~50ms — enough for GC to run (~20 windows/s) without adding
// noticeable latency to individual operations.
var _lastYieldTime = 0;
var _GC_YIELD_INTERVAL = 50; // ms

function _maybeYield(result) {
  var now = Date.now();
  if (now - _lastYieldTime >= _GC_YIELD_INTERVAL) {
    _lastYieldTime = now;
    return new Promise(function(r) { setTimeout(function() { r(result); }, 0); });
  }
  return Promise.resolve(result);
}

/**
 * Async AES-256-GCM encrypt with periodic main-thread yield.
 *
 * Identical to aesGcmEncrypt but periodically yields the main thread
 * to give the browser a macrotask boundary for garbage collection.
 * Without this, back-to-back pure-JS encrypt/decrypt calls starve the
 * GC and processed buffers accumulate in the tenured heap indefinitely
 * (observed as multi-GB memory growth in Firefox when crypto.subtle
 * is unavailable).
 */
function aesGcmEncryptAsync(key, nonce, plaintext, aad) {
  try { var result = aesGcmEncrypt(key, nonce, plaintext, aad); }
  catch (e) { return Promise.reject(e); }
  return _maybeYield(result);
}

/**
 * Async AES-256-GCM decrypt with periodic main-thread yield.
 * See aesGcmEncryptAsync for rationale.
 */
function aesGcmDecryptAsync(key, nonce, ciphertextWithTag, aad) {
  try { var result = aesGcmDecrypt(key, nonce, ciphertextWithTag, aad); }
  catch (e) { return Promise.reject(e); }
  return _maybeYield(result);
}

/**
 * Test hook: SubBytes over 32 bytes (two blocks) through the bitsliced
 * S-box circuit. Lets a test compare the circuit with the FIPS 197 table
 * without any table living in this module.
 */
function _subBytesForTest(input) {
  input = toBytes(input);
  if (input.length !== 32) throw new Error("_subBytesForTest expects 32 bytes");
  const q = new Int32Array(8);
  loadPair(q, input, 0, input, 16);
  bitsliceSbox(q);
  const out = new Uint8Array(32);
  storePair(q, out);
  return out;
}

module.exports = {
  aesGcmEncrypt, aesGcmDecrypt, aesGcmEncryptAsync, aesGcmDecryptAsync,
  _subBytesForTest,
};
