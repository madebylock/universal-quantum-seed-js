// Copyright (c) 2026 Lock.com — MIT License

"use strict";

// Keccak-f[1600] sponge construction — SHA3-256, SHA3-512, SHAKE-128, SHAKE-256.
// Pure JavaScript, uses BigInt for 64-bit lane arithmetic.
// Falls back to pure JS when Node.js native crypto is unavailable (e.g. browser).

const { toBytes } = require("./utils");

// --- Round constants (24 rounds) ---

const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

const MASK64 = 0xffffffffffffffffn;

// Rotation offsets for rho step
const ROT = [
   0,  1, 62, 28, 27,
  36, 44,  6, 55, 20,
   3, 10, 43, 25, 39,
  41, 45, 15, 21,  8,
  18,  2, 61, 56, 14,
];

// pi step permutation: state[PI[i]] = old_state[i]
const PI = [
   0, 10, 20,  5, 15,
  16,  1, 11, 21,  6,
   7, 17,  2, 12, 22,
  23,  8, 18,  3, 13,
  14, 24,  9, 19,  4,
];

function rotl64(x, n) {
  return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK64;
}

// Keccak-f[1600] permutation (24 rounds) on 25 BigInt lanes
function keccakF(state) {
  const c = new Array(5);
  const d = new Array(5);
  const t = new Array(25);

  for (let round = 0; round < 24; round++) {
    // Theta
    for (let x = 0; x < 5; x++) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (let x = 0; x < 5; x++) {
      d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
    }
    for (let i = 0; i < 25; i++) {
      state[i] = (state[i] ^ d[i % 5]) & MASK64;
    }

    // Rho + Pi
    for (let i = 0; i < 25; i++) {
      t[PI[i]] = rotl64(state[i], ROT[i]);
    }

    // Chi
    for (let y = 0; y < 25; y += 5) {
      for (let x = 0; x < 5; x++) {
        state[y + x] = (t[y + x] ^ ((~t[y + (x + 1) % 5] & MASK64) & t[y + (x + 2) % 5])) & MASK64;
      }
    }

    // Iota
    state[0] = (state[0] ^ RC[round]) & MASK64;
  }
}

// Load bytes into 25 BigInt lanes (little-endian)
function bytesToLanes(bytes, offset, count) {
  const lanes = new Array(25).fill(0n);
  const end = Math.min(offset + count, bytes.length);
  for (let i = offset; i < end; i++) {
    const laneIdx = Math.floor((i - offset) / 8);
    const byteIdx = (i - offset) % 8;
    lanes[laneIdx] |= BigInt(bytes[i]) << BigInt(byteIdx * 8);
  }
  return lanes;
}

// Extract bytes from lanes (little-endian)
function lanesToBytes(lanes, count) {
  const out = new Uint8Array(count);
  for (let i = 0; i < count; i++) {
    const laneIdx = Math.floor(i / 8);
    const byteIdx = i % 8;
    out[i] = Number((lanes[laneIdx] >> BigInt(byteIdx * 8)) & 0xffn);
  }
  return out;
}

// Core Keccak sponge: absorb + squeeze
function keccakSponge(rate, data, outputLen, suffix) {
  const rateBytes = rate / 8;
  const state = new Array(25).fill(0n);

  // Pad: append suffix byte, then 0x00..., then set last byte's high bit
  const padded = new Uint8Array(data.length + rateBytes);
  padded.set(data instanceof Uint8Array ? data : new Uint8Array(data));
  let pos = data.length;

  // Absorb full blocks
  let offset = 0;
  while (offset + rateBytes <= pos) {
    const block = bytesToLanes(padded, offset, rateBytes);
    for (let i = 0; i < Math.floor(rateBytes / 8); i++) {
      state[i] ^= block[i];
    }
    keccakF(state);
    offset += rateBytes;
  }

  // Final block with padding
  const lastBlock = new Uint8Array(rateBytes);
  const remaining = pos - offset;
  for (let i = 0; i < remaining; i++) {
    lastBlock[i] = padded[offset + i];
  }
  lastBlock[remaining] = suffix;
  lastBlock[rateBytes - 1] |= 0x80;

  const block = bytesToLanes(lastBlock, 0, rateBytes);
  for (let i = 0; i < Math.floor(rateBytes / 8); i++) {
    state[i] ^= block[i];
  }
  keccakF(state);

  // Squeeze
  const output = new Uint8Array(outputLen);
  let outputOffset = 0;
  while (outputOffset < outputLen) {
    const toExtract = Math.min(rateBytes, outputLen - outputOffset);
    const extracted = lanesToBytes(state, toExtract);
    output.set(extracted, outputOffset);
    outputOffset += toExtract;
    if (outputOffset < outputLen) {
      keccakF(state);
    }
  }

  return output;
}

// --- Native Node.js crypto fast path (SHAKE/SHA3 via OpenSSL) ---
// Falls back to pure JS BigInt Keccak when unavailable (e.g. browser).

let _nativeSha3_256 = null;
let _nativeSha3_512 = null;
let _nativeShake128 = null;
let _nativeShake256 = null;

try {
  const nodeCrypto = require("crypto");
  // Probe: shake256 requires the outputLength option (Node >= 12.8)
  const probe = nodeCrypto.createHash("shake256", { outputLength: 1 });
  probe.update(Buffer.alloc(1));
  probe.digest();

  _nativeShake256 = (data, outputLen) => {
    const h = nodeCrypto.createHash("shake256", { outputLength: outputLen });
    h.update(data);
    return new Uint8Array(h.digest());
  };
  _nativeShake128 = (data, outputLen) => {
    const h = nodeCrypto.createHash("shake128", { outputLength: outputLen });
    h.update(data);
    return new Uint8Array(h.digest());
  };
  _nativeSha3_256 = (data) => {
    const h = nodeCrypto.createHash("sha3-256");
    h.update(data);
    return new Uint8Array(h.digest());
  };
  _nativeSha3_512 = (data) => {
    const h = nodeCrypto.createHash("sha3-512");
    h.update(data);
    return new Uint8Array(h.digest());
  };
} catch (_) {
  // Native SHA3/SHAKE not available — pure JS fallback
}

// --- Public API ---

function sha3_256(data) {
  const bytes = toBytes(data);
  if (_nativeSha3_256) return _nativeSha3_256(bytes);
  return keccakSponge(1088, bytes, 32, 0x06);
}

function sha3_512(data) {
  const bytes = toBytes(data);
  if (_nativeSha3_512) return _nativeSha3_512(bytes);
  return keccakSponge(576, bytes, 64, 0x06);
}

function shake128(data, outputLen) {
  const bytes = toBytes(data);
  if (_nativeShake128) return _nativeShake128(bytes, outputLen);
  return keccakSponge(1344, bytes, outputLen, 0x1f);
}

function shake256(data, outputLen) {
  const bytes = toBytes(data);
  if (_nativeShake256) return _nativeShake256(bytes, outputLen);
  return keccakSponge(1088, bytes, outputLen, 0x1f);
}

// Streaming SHAKE for XOF (extendable output function) — absorb once, squeeze incrementally
class ShakeXof {
  constructor(rate, suffix) {
    this._rate = rate;
    this._rateBytes = rate / 8;
    this._suffix = suffix;
    this._state = new Array(25).fill(0n);
    this._buffer = new Uint8Array(0);
    this._absorbed = false;
    this._squeezeOffset = 0;
  }

  absorb(data) {
    if (this._absorbed) throw new Error("Already finalized");
    const bytes = toBytes(data);
    const combined = new Uint8Array(this._buffer.length + bytes.length);
    combined.set(this._buffer);
    combined.set(bytes, this._buffer.length);
    this._buffer = combined;
    return this;
  }

  _finalize() {
    if (this._absorbed) return;
    this._absorbed = true;

    const rateBytes = this._rateBytes;
    const data = this._buffer;
    let offset = 0;

    // Absorb full blocks
    while (offset + rateBytes <= data.length) {
      const block = bytesToLanes(data, offset, rateBytes);
      for (let i = 0; i < Math.floor(rateBytes / 8); i++) {
        this._state[i] ^= block[i];
      }
      keccakF(this._state);
      offset += rateBytes;
    }

    // Pad final block
    const lastBlock = new Uint8Array(rateBytes);
    const remaining = data.length - offset;
    for (let i = 0; i < remaining; i++) {
      lastBlock[i] = data[offset + i];
    }
    lastBlock[remaining] = this._suffix;
    lastBlock[rateBytes - 1] |= 0x80;

    const block = bytesToLanes(lastBlock, 0, rateBytes);
    for (let i = 0; i < Math.floor(rateBytes / 8); i++) {
      this._state[i] ^= block[i];
    }
    keccakF(this._state);

    this._squeezeBuffer = lanesToBytes(this._state, rateBytes);
    this._squeezeOffset = 0;
    this._buffer = null;
  }

  squeeze(outputLen) {
    this._finalize();
    const output = new Uint8Array(outputLen);
    let written = 0;
    const rateBytes = this._rateBytes;

    while (written < outputLen) {
      if (this._squeezeOffset >= rateBytes) {
        keccakF(this._state);
        this._squeezeBuffer = lanesToBytes(this._state, rateBytes);
        this._squeezeOffset = 0;
      }
      const available = rateBytes - this._squeezeOffset;
      const toTake = Math.min(available, outputLen - written);
      output.set(this._squeezeBuffer.subarray(this._squeezeOffset, this._squeezeOffset + toTake), written);
      this._squeezeOffset += toTake;
      written += toTake;
    }
    return output;
  }
}

// Native-aware XOF wrapper: uses OpenSSL SHAKE when available, otherwise pure JS sponge.
// The native path re-hashes with doubling strategy (O(n log n) per squeeze) which is
// still fast since OpenSSL is C-level. The pure JS path streams properly (O(n)).
class ShakeXofNative {
  constructor(nativeFn) {
    this._fn = nativeFn;
    this._parts = [];
    this._input = null;
    this._cache = null;
    this._offset = 0;
  }

  absorb(data) {
    if (this._cache !== null) throw new Error("Already finalized");
    const bytes = toBytes(data);
    this._parts.push(new Uint8Array(bytes)); // defensive copy — caller may mutate input
    return this;
  }

  squeeze(n) {
    const end = this._offset + n;
    if (this._cache === null || this._cache.length < end) {
      // Combine input parts on first squeeze
      if (this._input === null) {
        let total = 0;
        for (let i = 0; i < this._parts.length; i++) total += this._parts[i].length;
        this._input = new Uint8Array(total);
        let off = 0;
        for (let i = 0; i < this._parts.length; i++) {
          this._input.set(this._parts[i], off);
          off += this._parts[i].length;
        }
        this._parts = null;
      }
      // Re-hash with doubled output to amortize (O(n log n) total)
      const newLen = Math.max(end, this._cache ? this._cache.length * 2 : 1024);
      this._cache = this._fn(this._input, newLen);
    }
    const result = new Uint8Array(n);
    for (let i = 0; i < n; i++) result[i] = this._cache[this._offset + i];
    this._offset = end;
    return result;
  }
}

function shake128Xof() {
  if (_nativeShake128) return new ShakeXofNative(_nativeShake128);
  return new ShakeXof(1344, 0x1f);
}

function shake256Xof() {
  if (_nativeShake256) return new ShakeXofNative(_nativeShake256);
  return new ShakeXof(1088, 0x1f);
}

module.exports = {
  sha3_256,
  sha3_512,
  shake128,
  shake256,
  shake128Xof,
  shake256Xof,
};
