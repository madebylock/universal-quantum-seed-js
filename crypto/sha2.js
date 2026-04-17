// Copyright (c) 2026 Lock.com — MIT License

"use strict";

// SHA-256, SHA-512, HMAC, HKDF-Expand, PBKDF2-SHA512.
// Pure JavaScript fallback. SHA-512 uses BigInt for 64-bit words.
// When Node.js crypto is available, uses native OpenSSL (constant-time, much faster).

const { toBytes, zeroize } = require("./utils");

// --- Native Node.js crypto fast paths (SHA-256, SHA-512, HMAC, PBKDF2 via OpenSSL) ---

let _nativeSha256 = null;
let _nativeSha512 = null;
let _nativeHmacSha256 = null;
let _nativeHmacSha512 = null;
let _nativePbkdf2 = null;

try {
  const nodeCrypto = require("crypto");
  _nativeSha256 = (data) => new Uint8Array(nodeCrypto.createHash("sha256").update(data).digest());
  _nativeSha512 = (data) => new Uint8Array(nodeCrypto.createHash("sha512").update(data).digest());
  _nativeHmacSha256 = (key, data) => new Uint8Array(
    nodeCrypto.createHmac("sha256", Buffer.from(key)).update(data).digest()
  );
  _nativeHmacSha512 = (key, data) => new Uint8Array(
    nodeCrypto.createHmac("sha512", Buffer.from(key)).update(data).digest()
  );
  if (typeof nodeCrypto.pbkdf2Sync === "function") {
    _nativePbkdf2 = (password, salt, iterations, dkLen) => {
      return new Uint8Array(nodeCrypto.pbkdf2Sync(
        Buffer.from(password),
        Buffer.from(salt),
        iterations,
        dkLen,
        "sha512"
      ));
    };
  }
} catch (_) {
  // Native crypto not available — pure JS fallback (e.g. browser)
}

// --- SHA-256 ---

const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr32(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }

function sha256(data) {
  const bytes = toBytes(data);
  if (_nativeSha256) return _nativeSha256(bytes);

  // Pre-processing: padding
  const bitLen = bytes.length * 8;
  const padLen = (55 - bytes.length % 64 + 64) % 64 + 1;
  const msg = new Uint8Array(bytes.length + padLen + 8);
  msg.set(bytes);
  msg[bytes.length] = 0x80;
  // Big-endian 64-bit length at end
  const dv = new DataView(msg.buffer);
  dv.setUint32(msg.length - 4, bitLen >>> 0, false);
  // For lengths > 2^32 bits (won't happen in practice but correct):
  dv.setUint32(msg.length - 8, Math.floor(bitLen / 0x100000000) >>> 0, false);

  // Initial hash values
  let h0 = 0x6a09e667 >>> 0, h1 = 0xbb67ae85 >>> 0, h2 = 0x3c6ef372 >>> 0, h3 = 0xa54ff53a >>> 0;
  let h4 = 0x510e527f >>> 0, h5 = 0x9b05688c >>> 0, h6 = 0x1f83d9ab >>> 0, h7 = 0x5be0cd19 >>> 0;

  const w = new Uint32Array(64);

  for (let offset = 0; offset < msg.length; offset += 64) {
    // Load 16 words (big-endian)
    for (let i = 0; i < 16; i++) {
      w[i] = dv.getUint32(offset + i * 4, false);
    }
    // Extend to 64 words
    for (let i = 16; i < 64; i++) {
      const s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

    for (let i = 0; i < 64; i++) {
      const S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
      const ch = (e & f) ^ ((~e >>> 0) & g);
      const temp1 = (h + S1 + ch + K256[i] + w[i]) >>> 0;
      const S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }

  const result = new Uint8Array(32);
  const rdv = new DataView(result.buffer);
  rdv.setUint32(0, h0, false); rdv.setUint32(4, h1, false);
  rdv.setUint32(8, h2, false); rdv.setUint32(12, h3, false);
  rdv.setUint32(16, h4, false); rdv.setUint32(20, h5, false);
  rdv.setUint32(24, h6, false); rdv.setUint32(28, h7, false);
  return result;
}

// --- SHA-512 (BigInt, 64-bit words) ---

const MASK64 = 0xffffffffffffffffn;

const K512 = [
  0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
  0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
  0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
  0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
  0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
  0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
  0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
  0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
  0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
  0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
  0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
  0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
  0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
  0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
  0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
  0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
  0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
  0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
  0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n,
];

function rotr64(x, n) {
  return ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK64;
}

function sha512(data) {
  const bytes = toBytes(data);
  if (_nativeSha512) return _nativeSha512(bytes);

  // Pre-processing: padding
  const bitLen = BigInt(bytes.length) * 8n;
  const padLen = (111 - bytes.length % 128 + 128) % 128 + 1;
  const msg = new Uint8Array(bytes.length + padLen + 16);
  msg.set(bytes);
  msg[bytes.length] = 0x80;
  // Big-endian 128-bit length at end (only low 64 bits used)
  const dv = new DataView(msg.buffer);
  const lenHigh = bitLen >> 64n;
  const lenLow = bitLen & MASK64;
  dv.setUint32(msg.length - 8, Number((lenLow >> 32n) & 0xffffffffn), false);
  dv.setUint32(msg.length - 4, Number(lenLow & 0xffffffffn), false);
  dv.setUint32(msg.length - 16, Number((lenHigh >> 32n) & 0xffffffffn), false);
  dv.setUint32(msg.length - 12, Number(lenHigh & 0xffffffffn), false);

  // Initial hash values
  let h0 = 0x6a09e667f3bcc908n, h1 = 0xbb67ae8584caa73bn;
  let h2 = 0x3c6ef372fe94f82bn, h3 = 0xa54ff53a5f1d36f1n;
  let h4 = 0x510e527fade682d1n, h5 = 0x9b05688c2b3e6c1fn;
  let h6 = 0x1f83d9abfb41bd6bn, h7 = 0x5be0cd19137e2179n;

  const w = new Array(80);

  for (let offset = 0; offset < msg.length; offset += 128) {
    // Load 16 words (big-endian, 64-bit)
    for (let i = 0; i < 16; i++) {
      const hi = BigInt(dv.getUint32(offset + i * 8, false));
      const lo = BigInt(dv.getUint32(offset + i * 8 + 4, false));
      w[i] = ((hi << 32n) | lo) & MASK64;
    }
    // Extend to 80 words
    for (let i = 16; i < 80; i++) {
      const s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7n);
      const s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6n);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK64;
    }

    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

    for (let i = 0; i < 80; i++) {
      const S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
      const ch = (e & f) ^ ((~e & MASK64) & g);
      const temp1 = (h + S1 + ch + K512[i] + w[i]) & MASK64;
      const S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) & MASK64;

      h = g; g = f; f = e; e = (d + temp1) & MASK64;
      d = c; c = b; b = a; a = (temp1 + temp2) & MASK64;
    }

    h0 = (h0 + a) & MASK64; h1 = (h1 + b) & MASK64;
    h2 = (h2 + c) & MASK64; h3 = (h3 + d) & MASK64;
    h4 = (h4 + e) & MASK64; h5 = (h5 + f) & MASK64;
    h6 = (h6 + g) & MASK64; h7 = (h7 + h) & MASK64;
  }

  const result = new Uint8Array(64);
  for (let i = 0; i < 8; i++) {
    const val = [h0, h1, h2, h3, h4, h5, h6, h7][i];
    for (let j = 0; j < 8; j++) {
      result[i * 8 + j] = Number((val >> BigInt((7 - j) * 8)) & 0xffn);
    }
  }
  return result;
}

// --- HMAC ---

function hmacSha256(key, data) {
  key = toBytes(key);
  data = toBytes(data);
  if (_nativeHmacSha256) return _nativeHmacSha256(key, data);

  const blockSize = 64;
  if (key.length > blockSize) key = sha256(key);
  const paddedKey = new Uint8Array(blockSize);
  paddedKey.set(key);

  const ipad = new Uint8Array(blockSize);
  const opad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    ipad[i] = paddedKey[i] ^ 0x36;
    opad[i] = paddedKey[i] ^ 0x5c;
  }

  const inner = new Uint8Array(blockSize + data.length);
  inner.set(ipad);
  inner.set(data, blockSize);
  const innerHash = sha256(inner);

  const outer = new Uint8Array(blockSize + 32);
  outer.set(opad);
  outer.set(innerHash, blockSize);
  const result = sha256(outer);
  zeroize(paddedKey); zeroize(ipad); zeroize(opad);
  zeroize(inner); zeroize(innerHash); zeroize(outer);
  return result;
}

function hmacSha512(key, data) {
  key = toBytes(key);
  data = toBytes(data);
  if (_nativeHmacSha512) return _nativeHmacSha512(key, data);

  const blockSize = 128;
  if (key.length > blockSize) key = sha512(key);
  const paddedKey = new Uint8Array(blockSize);
  paddedKey.set(key);

  const ipad = new Uint8Array(blockSize);
  const opad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    ipad[i] = paddedKey[i] ^ 0x36;
    opad[i] = paddedKey[i] ^ 0x5c;
  }

  const inner = new Uint8Array(blockSize + data.length);
  inner.set(ipad);
  inner.set(data, blockSize);
  const innerHash = sha512(inner);

  const outer = new Uint8Array(blockSize + 64);
  outer.set(opad);
  outer.set(innerHash, blockSize);
  const result = sha512(outer);
  zeroize(paddedKey); zeroize(ipad); zeroize(opad);
  zeroize(inner); zeroize(innerHash); zeroize(outer);
  return result;
}

// --- HKDF-Expand (RFC 5869, SHA-512) ---

function hkdfExpand(prk, info, length) {
  prk = toBytes(prk);
  info = info == null ? new Uint8Array(0) : toBytes(info);

  const hashLen = 64; // SHA-512
  if (length > 255 * hashLen) throw new Error("HKDF-Expand length exceeds 255 * HashLen");
  const n = Math.ceil(length / hashLen);
  const output = new Uint8Array(n * hashLen);
  let prev = new Uint8Array(0);

  for (let i = 1; i <= n; i++) {
    const input = new Uint8Array(prev.length + info.length + 1);
    input.set(prev);
    input.set(info, prev.length);
    input[input.length - 1] = i;
    prev = hmacSha512(prk, input);
    output.set(prev, (i - 1) * hashLen);
  }

  return output.subarray(0, length);
}

// --- HKDF-Extract (RFC 5869, SHA-256) ---

function hkdfExtractSha256(salt, ikm) {
  const ikmBytes = toBytes(ikm);
  let saltBytes = salt == null ? new Uint8Array(0) : toBytes(salt);
  if (saltBytes.length === 0) saltBytes = new Uint8Array(32); // RFC 5869: empty salt → HashLen zeros
  return hmacSha256(saltBytes, ikmBytes);
}

// --- HKDF-Expand (SHA-256 variant, for AES key derivation) ---

function hkdfExpandSha256(prk, info, length) {
  prk = toBytes(prk);
  info = info == null ? new Uint8Array(0) : toBytes(info);

  const hashLen = 32; // SHA-256
  if (length > 255 * hashLen) throw new Error("HKDF-Expand length exceeds 255 * HashLen");
  const n = Math.ceil(length / hashLen);
  const output = new Uint8Array(n * hashLen);
  let prev = new Uint8Array(0);

  for (let i = 1; i <= n; i++) {
    const input = new Uint8Array(prev.length + info.length + 1);
    input.set(prev);
    input.set(info, prev.length);
    input[input.length - 1] = i;
    prev = hmacSha256(prk, input);
    output.set(prev, (i - 1) * hashLen);
  }

  return output.subarray(0, length);
}

// --- PBKDF2-SHA512 ---

function pbkdf2Sha512(password, salt, iterations, dkLen) {
  password = toBytes(password);
  salt = toBytes(salt);

  if (!Number.isInteger(iterations) || iterations < 1) {
    throw new Error("pbkdf2: iterations must be a positive integer, got " + iterations);
  }
  if (!Number.isInteger(dkLen) || dkLen < 1) {
    throw new Error("pbkdf2: dkLen must be a positive integer, got " + dkLen);
  }

  if (_nativePbkdf2) return _nativePbkdf2(password, salt, iterations, dkLen);

  const hashLen = 64;
  const numBlocks = Math.ceil(dkLen / hashLen);
  const output = new Uint8Array(numBlocks * hashLen);

  for (let block = 1; block <= numBlocks; block++) {
    // U_1 = HMAC(password, salt || INT_32_BE(block))
    const saltBlock = new Uint8Array(salt.length + 4);
    saltBlock.set(salt);
    saltBlock[salt.length] = (block >> 24) & 0xff;
    saltBlock[salt.length + 1] = (block >> 16) & 0xff;
    saltBlock[salt.length + 2] = (block >> 8) & 0xff;
    saltBlock[salt.length + 3] = block & 0xff;

    let u = hmacSha512(password, saltBlock);
    const result = new Uint8Array(u);

    for (let i = 1; i < iterations; i++) {
      u = hmacSha512(password, u);
      for (let j = 0; j < hashLen; j++) {
        result[j] ^= u[j];
      }
    }

    output.set(result, (block - 1) * hashLen);
  }

  return output.subarray(0, dkLen);
}

// --- Async PBKDF2-SHA512 (WebCrypto fast path for browsers) ---

async function pbkdf2Sha512Async(password, salt, iterations, dkLen) {
  password = toBytes(password);
  salt = toBytes(salt);

  // WebCrypto fast path (browsers and modern Node.js)
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.subtle) {
    try {
      const keyMaterial = await globalThis.crypto.subtle.importKey(
        "raw", password, "PBKDF2", false, ["deriveBits"]
      );
      const bits = await globalThis.crypto.subtle.deriveBits(
        { name: "PBKDF2", salt, iterations, hash: "SHA-512" },
        keyMaterial,
        dkLen * 8
      );
      return new Uint8Array(bits);
    } catch (_) {
      // WebCrypto PBKDF2 not supported — fall through
    }
  }

  // Sync fallback (Node native or pure JS)
  return pbkdf2Sha512(password, salt, iterations, dkLen);
}

module.exports = {
  sha256,
  sha512,
  hmacSha256,
  hmacSha512,
  hkdfExpand,
  hkdfExtractSha256,
  hkdfExpandSha256,
  pbkdf2Sha512,
  pbkdf2Sha512Async,
};
