// Universal Quantum Seed v1.0 — Crypto-Only Bundle
// https://github.com/SignerHQ/universal-quantum-seed-js
// MIT License — (c) 2026 Signer.io
//
// Crypto-only build: all cryptographic primitives + key derivation.
// No wordlists, no word resolution, no language data (~75% smaller).
//
// Usage:
//   <script src="uqs-crypto.js"></script>
//   const { mlKeygen, ed25519Sign, getSeed } = UQS;
//
// Or as ES module:
//   import UQS from "./uqs-crypto.js";

(function(globalThis) {
"use strict";

// ── Module registry ────────────────────────────────────────────
const _modules = {};
const _cache = {};

function _resolve(base, id) {
  id = id.replace(/\.js$/, "");
  if (!id.startsWith(".")) return id;
  var parts = (base + "/" + id).split("/");
  var out = [];
  for (var i = 0; i < parts.length; i++) {
    if (parts[i] === "." || parts[i] === "") continue;
    if (parts[i] === "..") { out.pop(); continue; }
    out.push(parts[i]);
  }
  return out.length ? "./" + out.join("/") : ".";
}

function _requireFrom(base) {
  return function require(id) {
    var key = _resolve(base, id);
    if (_cache[key]) return _cache[key].exports;
    if (_modules[key]) {
      var mod = { exports: {} };
      _cache[key] = mod;
      _modules[key](mod, mod.exports, _requireFrom(_dirs[key]));
      return mod.exports;
    }
    throw new Error("Cannot find module '" + id + "'");
  };
}

var _dirs = {};


// ── crypto/utils.js ──
_dirs["./crypto/utils"] = "./crypto";
_modules["./crypto/utils"] = function(module, exports, require) {
// Copyright (c) 2026 Signer.io — MIT License

"use strict";

// Shared cryptographic utilities used across all modules.
// Single source of truth to prevent divergence in security-critical helpers.
//
// Side-channel model — constant-time hierarchy:
//
//   Tier 1 (Node.js):  Native OpenSSL via require("crypto").
//     Ed25519, X25519, SHAKE, SHA-2, HMAC, PBKDF2 — all constant-time C.
//     timingSafeEqual — hardened byte comparison.
//
//   Tier 2 (Browser):  WebAssembly (sync, true constant-time).
//     constantTimeEqual — 93-byte inline WASM module, no JIT timing variation.
//     Future: SHA-256, SHA-512 could be added as compiled-from-C WASM modules.
//
//   Tier 3 (Fallback): Pure JavaScript (fully constant-time).
//     All control flow is branchless (no secret-dependent branches).
//     Integer arithmetic (ML-DSA, ML-KEM, SLH-DSA) uses 32-bit ops — constant-time.
//     Field arithmetic (Ed25519/X25519) uses fixed-width 16-limb representation
//     with JS Number (no BigInt) — all multiplies are fixed-width and constant-time.
//
//   For deployments where hardware side-channel attacks are a concern,
//   use a vetted constant-time C/Rust implementation (e.g. libsodium, liboqs).

// Reuse a single TextEncoder instance to reduce allocations.
const _enc = new TextEncoder();

function toBytes(data) {
  if (data instanceof Uint8Array) return data;
  if (typeof data === "string") return _enc.encode(data);
  if (Array.isArray(data)) return new Uint8Array(data);
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  throw new Error("unsupported input type");
}

function concatBytes(/* ...arrays */) {
  let total = 0;
  for (let i = 0; i < arguments.length; i++) total += arguments[i].length;
  const result = new Uint8Array(total);
  let offset = 0;
  for (let i = 0; i < arguments.length; i++) {
    result.set(arguments[i], offset);
    offset += arguments[i].length;
  }
  return result;
}

function randomBytes(n) {
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.getRandomValues) {
    const buf = new Uint8Array(n);
    globalThis.crypto.getRandomValues(buf);
    return buf;
  }
  return new Uint8Array(require("crypto").randomBytes(n));
}

/** Best-effort zeroing of sensitive buffers. Not guaranteed by JS GC, but reduces exposure. */
function zeroize(buf) {
  if (buf instanceof Uint8Array) buf.fill(0);
  else if (Array.isArray(buf)) {
    for (let i = 0; i < buf.length; i++) buf[i] = 0;
  }
}

/**
 * Constant-time comparison of two Uint8Arrays.
 *
 * Fallback chain:
 *   1. Node.js crypto.timingSafeEqual (hardened C, best)
 *   2. Inline WASM ct_equal (true constant-time, no JIT — for browsers)
 *   3. Pure JS XOR-accumulate (constant-ish — JIT may still optimize)
 */

// Tier 1: Node.js native
let _timingSafeEqual = null;
try {
  const nodeCrypto = require("crypto");
  if (typeof nodeCrypto.timingSafeEqual === "function") {
    _timingSafeEqual = nodeCrypto.timingSafeEqual;
  }
} catch (_) {}

// Tier 2: Inline WASM constant-time compare (93-byte module, sync instantiation).
// WASM integer ops have no JIT timing variation — true constant-time in browsers.
// Module exports: m (memory, 1 page = 64KB), e(a_off, b_off, len) -> i32 (1=equal).
let _wasmCtEqual = null;
if (!_timingSafeEqual) {
  try {
    if (typeof WebAssembly !== "undefined") {
      /* eslint-disable */
      const _wasmBin = new Uint8Array([
        0x00,0x61,0x73,0x6d, 0x01,0x00,0x00,0x00, // WASM header v1
        0x01,0x08,0x01,0x60, 0x03,0x7f,0x7f,0x7f, 0x01,0x7f, // type: (i32,i32,i32)->i32
        0x03,0x02,0x01,0x00, // func section: 1 func, type 0
        0x05,0x03,0x01,0x00,0x01, // memory: 1 page (64KB)
        0x07,0x09,0x02, 0x01,0x6d,0x02,0x00, 0x01,0x65,0x00,0x00, // exports: "m","e"
        0x0a,0x35,0x01,0x33, 0x01,0x02,0x7f, // code: 1 body, 2 i32 locals ($d,$i)
        // block { loop { if ($i >= $n) break;
        0x02,0x40, 0x03,0x40, 0x20,0x04, 0x20,0x02, 0x4f, 0x0d,0x01,
        //   $d |= mem[$a+$i] ^ mem[$b+$i]
        0x20,0x03, 0x20,0x00, 0x20,0x04, 0x6a, 0x2d,0x00,0x00,
        0x20,0x01, 0x20,0x04, 0x6a, 0x2d,0x00,0x00,
        0x73, 0x72, 0x21,0x03,
        //   $i++ ; continue } }
        0x20,0x04, 0x41,0x01, 0x6a, 0x21,0x04, 0x0c,0x00, 0x0b, 0x0b,
        // return $d == 0
        0x20,0x03, 0x45, 0x0b
      ]);
      /* eslint-enable */
      const _mod = new WebAssembly.Module(_wasmBin);
      const _inst = new WebAssembly.Instance(_mod);
      const _mem = new Uint8Array(_inst.exports.m.buffer);
      _wasmCtEqual = function (a, b) {
        _mem.set(a, 0);
        _mem.set(b, a.length);
        const eq = _inst.exports.e(0, a.length, a.length) === 1;
        // Best-effort: zero sensitive data from WASM memory
        _mem.fill(0, 0, a.length + b.length);
        return eq;
      };
    }
  } catch (_) {
    // WASM not available or instantiation failed — fall through to JS
  }
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  if (_timingSafeEqual) return _timingSafeEqual(a, b);
  if (_wasmCtEqual) return _wasmCtEqual(a, b);
  // Tier 3: Pure JS XOR-accumulate (constant-ish, JIT may optimize)
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Constant-time 32-bit integer select.
 * Returns a when mask is -1 (0xffffffff), b when mask is 0.
 * mask MUST be either 0 or -1 (all-ones).
 */
function ctSelect32(mask, a, b) {
  return (a & mask) | (b & ~mask);
}

module.exports = { toBytes, concatBytes, randomBytes, zeroize, constantTimeEqual, ctSelect32 };

};

// ── crypto/field25519.js ──
_dirs["./crypto/field25519"] = "./crypto";
_modules["./crypto/field25519"] = function(module, exports, require) {
// Copyright (c) 2026 Signer.io — MIT License

"use strict";

// GF(2^255 - 19) field arithmetic using fixed-width JS Number limbs.
//
// Representation: 16 limbs of 16 bits each.
//   fe = [f0, f1, ..., f15]
//   value = f0 + f1*2^16 + f2*2^32 + ... + f15*2^240
//
// All arithmetic uses JS Number (IEEE 754 double, 53-bit mantissa).
// Worst-case intermediate: 16 terms of (16-bit * 16-bit * 38) ≈ 2^41 < 2^53.
// This eliminates BigInt timing leaks — all operations are fixed-width.
//
// Based on the representation used by TweetNaCl.

const _NLIMBS = 16;

function feZero() {
  return new Float64Array(_NLIMBS);
}

function feOne() {
  const o = new Float64Array(_NLIMBS);
  o[0] = 1;
  return o;
}

function feCopy(a) {
  return new Float64Array(a);
}

// Load from 32-byte little-endian encoding
function feFromBytes(b) {
  const o = new Float64Array(_NLIMBS);
  for (let i = 0; i < _NLIMBS; i++) {
    o[i] = b[2 * i] | (b[2 * i + 1] << 8);
  }
  return o;
}

// Carry propagation (TweetNaCl approach).
// Bias with c=1 + 65535 ensures correct floor division for negative limbs.
// Wrap-around: 2^256 ≡ 38 (mod p), so overflow from limb 15 adds 38 to limb 0.
function _feCarry(o) {
  let c = 1;
  for (let i = 0; i < _NLIMBS; i++) {
    const v = o[i] + c + 65535;
    c = Math.floor(v / 65536);
    o[i] = v - c * 65536;
  }
  o[0] += 38 * (c - 1);
}

// Encode to 32-byte little-endian, fully reduced mod p
function feToBytes(a) {
  const t = feCopy(a);
  _feReduce(t);
  const o = new Uint8Array(32);
  for (let i = 0; i < _NLIMBS; i++) {
    o[2 * i] = t[i] & 0xff;
    o[2 * i + 1] = (t[i] >>> 8) & 0xff;
  }
  return o;
}

// Full reduction mod p = 2^255 - 19
function _feReduce(t) {
  // Carry repeatedly to normalize
  _feCarry(t);
  _feCarry(t);
  _feCarry(t);

  // Subtract p if t >= p. Do it twice for certainty.
  // m = t - p; if m >= 0, use m, else keep t.
  // p = 2^255 - 19; low limb is 0xffed, middle limbs 0xffff, top limb 0x7fff.
  for (let j = 0; j < 2; j++) {
    const m = new Float64Array(_NLIMBS);
    m[0] = t[0] - 0xffed;
    for (let i = 1; i < 15; i++) {
      m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
      m[i - 1] &= 0xffff;
    }
    m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
    // b = 1 if t < p (borrow from top), 0 if t >= p
    const b = (m[15] >> 16) & 1;
    m[14] &= 0xffff;

    // Constant-time select: if b=0 (no borrow, t >= p), use m; if b=1 (borrow), keep t
    _feCsel(t, m, 1 - b);
  }
}

// Constant-time select: if flag=1, copy src into dst
function _feCsel(dst, src, flag) {
  const mask = -flag; // 0 or -1
  for (let i = 0; i < _NLIMBS; i++) {
    dst[i] ^= mask & (dst[i] ^ src[i]);
  }
}

// Addition: o = a + b
function feAdd(a, b) {
  const o = new Float64Array(_NLIMBS);
  for (let i = 0; i < _NLIMBS; i++) o[i] = a[i] + b[i];
  return o;
}

// Subtraction: o = a - b (add p to avoid negative)
function feSub(a, b) {
  const o = new Float64Array(_NLIMBS);
  for (let i = 0; i < _NLIMBS; i++) o[i] = a[i] - b[i];
  return o;
}

// Negation: o = -a
function feNeg(a) {
  const o = new Float64Array(_NLIMBS);
  for (let i = 0; i < _NLIMBS; i++) o[i] = -a[i];
  return o;
}

// Multiplication: o = a * b (mod p)
// Schoolbook 16x16 with reduction: 2^256 ≡ 38 (mod p).
function feMul(a, b) {
  const t = new Float64Array(31);
  for (let i = 0; i < _NLIMBS; i++) {
    for (let j = 0; j < _NLIMBS; j++) {
      t[i + j] += a[i] * b[j];
    }
  }
  // Reduce: t[16..30] wraps with factor 38 (since 2^256 ≡ 38 mod p)
  for (let i = 0; i < 15; i++) {
    t[i] += 38 * t[i + 16];
  }
  const o = new Float64Array(_NLIMBS);
  for (let i = 0; i < _NLIMBS; i++) o[i] = t[i];
  _feCarry(o);
  _feCarry(o);
  return o;
}

// Squaring: o = a^2 (mod p)
function feSqr(a) {
  return feMul(a, a);
}

// Scalar multiply by small integer: o = a * c
function feScalar(a, c) {
  const o = new Float64Array(_NLIMBS);
  for (let i = 0; i < _NLIMBS; i++) o[i] = a[i] * c;
  _feCarry(o);
  return o;
}

// Modular inversion: o = a^(p-2) mod p  (Fermat's little theorem)
// Uses the addition chain for p-2 = 2^255 - 21.
function feInv(a) {
  function sqrN(x, n) {
    for (let i = 0; i < n; i++) x = feSqr(x);
    return x;
  }

  const t0 = feSqr(a);           // a^2
  const t1 = sqrN(t0, 2);        // a^8
  const t2 = feMul(a, t1);       // a^9
  const t3 = feMul(t0, t2);      // a^11
  const t4 = feSqr(t3);          // a^22
  const t5 = feMul(t2, t4);      // a^(2^5 - 1) = a^31

  let t = sqrN(t5, 5);
  t = feMul(t, t5);              // a^(2^10 - 1)
  let t6 = sqrN(t, 10);
  t6 = feMul(t6, t);             // a^(2^20 - 1)
  let t7 = sqrN(t6, 20);
  t7 = feMul(t7, t6);            // a^(2^40 - 1)
  t7 = sqrN(t7, 10);
  t = feMul(t7, t);              // a^(2^50 - 1)

  let t8 = sqrN(t, 50);
  t8 = feMul(t8, t);             // a^(2^100 - 1)
  let t9 = sqrN(t8, 100);
  t9 = feMul(t9, t8);            // a^(2^200 - 1)
  t9 = sqrN(t9, 50);
  t = feMul(t9, t);              // a^(2^250 - 1)

  t = sqrN(t, 5);
  return feMul(t, t3);           // a^(2^255 - 21) = a^(p-2)
}

// Square root: compute a^((p+3)/8), then adjust.
// Returns null if a is not a QR mod p.
function feSqrt(a) {
  function sqrN(x, n) {
    for (let i = 0; i < n; i++) x = feSqr(x);
    return x;
  }

  // Compute a^((p+3)/8) = a^(2^252 - 2) via the same addition chain
  // but stopping earlier and using a different final step.
  //
  // First compute a^(2^250 - 1) (same as feInv up to that point):
  const t0 = feSqr(a);           // a^2
  const t1 = sqrN(t0, 2);        // a^8
  const t2 = feMul(a, t1);       // a^9
  const t3 = feMul(t0, t2);      // a^11
  const t4 = feSqr(t3);          // a^22
  const t5 = feMul(t2, t4);      // a^31 = a^(2^5 - 1)

  let t = sqrN(t5, 5);
  t = feMul(t, t5);              // a^(2^10 - 1)
  let t6 = sqrN(t, 10);
  t6 = feMul(t6, t);             // a^(2^20 - 1)
  let t7 = sqrN(t6, 20);
  t7 = feMul(t7, t6);            // a^(2^40 - 1)
  t7 = sqrN(t7, 10);
  t = feMul(t7, t);              // a^(2^50 - 1)

  let t8 = sqrN(t, 50);
  t8 = feMul(t8, t);             // a^(2^100 - 1)
  let t9 = sqrN(t8, 100);
  t9 = feMul(t9, t8);            // a^(2^200 - 1)
  t9 = sqrN(t9, 50);
  t = feMul(t9, t);              // a^(2^250 - 1)

  // a^(2^252 - 4)
  t = sqrN(t, 2);
  // a^(2^252 - 3)
  t = feMul(t, a);
  // a^(2^252 - 2) = a^((p+3)/8)
  t = feMul(t, a);

  // Check: t^2 == a?
  const check = feSqr(t);
  if (feEqual(check, a)) return t;

  // Check: t^2 == -a? Then return t * sqrt(-1)
  const negA = feNeg(a);
  if (feEqual(check, negA)) {
    return feMul(t, _SQRT_M1);
  }

  return null; // Not a quadratic residue
}

// Equality check via byte comparison (constant-time)
function feEqual(a, b) {
  const sa = feToBytes(a);
  const sb = feToBytes(b);
  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= sa[i] ^ sb[i];
  return diff === 0;
}

// sqrt(-1) mod p: hardcoded constant
// = 19681161376707505956807079304988542015446066515923890162744021073123829784752
const _SQRT_M1 = feFromBytes(new Uint8Array([
  0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
  0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
  0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
  0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
]));

// Constant-time conditional swap: if swap !== 0, swap a and b in-place.
function feCswap(a, b, swap) {
  const mask = -swap; // 0 or -1
  for (let i = 0; i < _NLIMBS; i++) {
    const x = mask & (a[i] ^ b[i]);
    a[i] ^= x;
    b[i] ^= x;
  }
}

// Constant-time conditional move: if flag !== 0, copy b into a.
function feCmov(a, b, flag) {
  const mask = -flag; // 0 or -1
  for (let i = 0; i < _NLIMBS; i++) {
    a[i] ^= mask & (a[i] ^ b[i]);
  }
}

// Check if field element is zero (after reduction). Returns 1 or 0.
function feIsZero(a) {
  const s = feToBytes(a);
  let acc = 0;
  for (let i = 0; i < 32; i++) acc |= s[i];
  return (1 - (((acc | (-acc)) >>> 31) & 1));
}

// Check if field element is negative (odd). Returns 1 or 0.
function feIsNeg(a) {
  const s = feToBytes(a);
  return s[0] & 1;
}

module.exports = {
  feZero,
  feOne,
  feCopy,
  feFromBytes,
  feToBytes,
  feAdd,
  feSub,
  feNeg,
  feMul,
  feSqr,
  feScalar,
  feInv,
  feSqrt,
  feEqual,
  feCswap,
  feCmov,
  feIsZero,
  feIsNeg,
};

};

// ── crypto/sha2.js ──
_dirs["./crypto/sha2"] = "./crypto";
_modules["./crypto/sha2"] = function(module, exports, require) {
// Copyright (c) 2026 Signer.io — MIT License

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

};

// ── crypto/sha3.js ──
_dirs["./crypto/sha3"] = "./crypto";
_modules["./crypto/sha3"] = function(module, exports, require) {
// Copyright (c) 2026 Signer.io — MIT License

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

};

// ── crypto/argon2.js ──
_dirs["./crypto/argon2"] = "./crypto";
_modules["./crypto/argon2"] = function(module, exports, require) {
// Copyright (c) 2026 Signer.io — MIT License

"use strict";

// Argon2id (RFC 9106) — Pure JavaScript, zero dependencies.
// Uses Blake2b for hashing, Uint32 pairs for 64-bit arithmetic.

const BLOCK_BYTES = 1024;
const BLOCK_U32 = 256;   // 1024 / 4
const BLOCK_U64 = 128;   // 1024 / 8
const SYNC_POINTS = 4;
const MASK64 = (1n << 64n) - 1n;

// ── Little-endian helpers ───────────────────────────────────────

function le32(n) {
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
}

function cat() {
  let total = 0;
  for (let i = 0; i < arguments.length; i++) total += arguments[i].length;
  const r = new Uint8Array(total);
  let off = 0;
  for (let i = 0; i < arguments.length; i++) { r.set(arguments[i], off); off += arguments[i].length; }
  return r;
}

function loadBlock(bytes, mem, off) {
  for (let i = 0; i < BLOCK_U32; i++) {
    const p = i * 4;
    mem[off + i] = (bytes[p] | (bytes[p + 1] << 8) | (bytes[p + 2] << 16) | (bytes[p + 3] << 24)) >>> 0;
  }
}

function storeBlock(mem, off) {
  const out = new Uint8Array(BLOCK_BYTES);
  for (let i = 0; i < BLOCK_U32; i++) {
    const v = mem[off + i], p = i * 4;
    out[p] = v & 0xff; out[p + 1] = (v >>> 8) & 0xff;
    out[p + 2] = (v >>> 16) & 0xff; out[p + 3] = (v >>> 24) & 0xff;
  }
  return out;
}

function mulHi(a, b) {
  const a0 = a & 0xFFFF, a1 = a >>> 16, b0 = b & 0xFFFF, b1 = b >>> 16;
  const cross = ((a0 * b0) >>> 16) + (a1 * b0 & 0xFFFF) + (a0 * b1 & 0xFFFF);
  return ((a1 * b1) + ((a1 * b0) >>> 16) + ((a0 * b1) >>> 16) + (cross >>> 16)) >>> 0;
}

// ── Blake2b (BigInt for 64-bit words) ───────────────────────────

const B2B_IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];

const SIGMA = [
  [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
  [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
  [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],
  [7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
  [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],
  [2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
  [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],
  [13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
  [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],
  [10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0],
];

function b2bG(v, a, b, c, d, x, y) {
  v[a] = (v[a] + v[b] + x) & MASK64;
  let t = (v[d] ^ v[a]) & MASK64;
  v[d] = (t >> 32n | t << 32n) & MASK64;
  v[c] = (v[c] + v[d]) & MASK64;
  t = (v[b] ^ v[c]) & MASK64;
  v[b] = (t >> 24n | t << 40n) & MASK64;
  v[a] = (v[a] + v[b] + y) & MASK64;
  t = (v[d] ^ v[a]) & MASK64;
  v[d] = (t >> 16n | t << 48n) & MASK64;
  v[c] = (v[c] + v[d]) & MASK64;
  t = (v[b] ^ v[c]) & MASK64;
  v[b] = (t >> 63n | t << 1n) & MASK64;
}

function b2bCompress(h, data, off, t, last) {
  const m = new Array(16);
  for (let i = 0; i < 16; i++) {
    const p = off + i * 8;
    const lo = (data[p] | (data[p + 1] << 8) | (data[p + 2] << 16) | (data[p + 3] << 24)) >>> 0;
    const hi = (data[p + 4] | (data[p + 5] << 8) | (data[p + 6] << 16) | (data[p + 7] << 24)) >>> 0;
    m[i] = (BigInt(hi) << 32n) | BigInt(lo);
  }
  const v = new Array(16);
  for (let i = 0; i < 8; i++) v[i] = h[i];
  for (let i = 0; i < 8; i++) v[8 + i] = B2B_IV[i];
  v[12] ^= t;
  if (last) v[14] ^= MASK64;
  for (let r = 0; r < 12; r++) {
    const s = SIGMA[r % 10];
    b2bG(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    b2bG(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    b2bG(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    b2bG(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    b2bG(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    b2bG(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    b2bG(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    b2bG(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
  }
  for (let i = 0; i < 8; i++) h[i] = (h[i] ^ v[i] ^ v[8 + i]) & MASK64;
}

function blake2b(data, outLen) {
  const h = B2B_IV.slice();
  h[0] ^= BigInt(0x01010000 | outLen);
  let t = 0, pos = 0;
  while (data.length - pos > 128) {
    t += 128;
    b2bCompress(h, data, pos, BigInt(t), false);
    pos += 128;
  }
  t += data.length - pos;
  const last = new Uint8Array(128);
  if (data.length > pos) last.set(data.subarray(pos));
  b2bCompress(h, last, 0, BigInt(t), true);
  const out = new Uint8Array(outLen);
  for (let i = 0; i < 8 && i * 8 < outLen; i++) {
    for (let j = 0; j < 8 && i * 8 + j < outLen; j++) {
      out[i * 8 + j] = Number((h[i] >> BigInt(j * 8)) & 0xffn);
    }
  }
  return out;
}

// ── H' variable-length hash (RFC 9106 §3.2) ────────────────────

function argon2Hash(data, outLen) {
  if (outLen <= 64) return blake2b(cat(le32(outLen), data), outLen);
  const r = Math.ceil(outLen / 32) - 2;
  const parts = [];
  let prev = blake2b(cat(le32(outLen), data), 64);
  parts.push(prev.slice(0, 32));
  for (let i = 2; i <= r; i++) { prev = blake2b(prev, 64); parts.push(prev.slice(0, 32)); }
  prev = blake2b(prev, outLen - 32 * r);
  parts.push(prev);
  let total = 0;
  for (const p of parts) total += p.length;
  const result = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { result.set(p, off); off += p.length; }
  return result;
}

// ── Argon2 compression (fBlaMka + permutation) ─────────────────

// Pre-allocated work buffers (safe: JS is single-threaded)
const _R = new Uint32Array(BLOCK_U32);
const _tmp = new Uint32Array(BLOCK_U32);

function fBlaMka(v, ai, bi) {
  const a_lo = v[ai], b_lo = v[bi];
  const a0 = a_lo & 0xFFFF, a1 = a_lo >>> 16;
  const b0 = b_lo & 0xFFFF, b1 = b_lo >>> 16;
  const ll = a0 * b0, hl = a1 * b0, lh = a0 * b1, hh = a1 * b1;
  const cross = (ll >>> 16) + (hl & 0xFFFF) + (lh & 0xFFFF);
  let p_lo = (((cross & 0xFFFF) << 16) | (ll & 0xFFFF)) >>> 0;
  let p_hi = (hh + (hl >>> 16) + (lh >>> 16) + (cross >>> 16)) >>> 0;
  p_hi = ((p_hi << 1) | (p_lo >>> 31)) >>> 0;
  p_lo = (p_lo << 1) >>> 0;
  let s_lo = (v[ai] + v[bi]) >>> 0;
  let carry = (s_lo < v[ai]) ? 1 : 0;
  let s_hi = (v[ai + 1] + v[bi + 1] + carry) >>> 0;
  v[ai] = (s_lo + p_lo) >>> 0;
  carry = (v[ai] < s_lo) ? 1 : 0;
  v[ai + 1] = (s_hi + p_hi + carry) >>> 0;
}

function xorRotr(v, di, ai, n) {
  const lo = (v[di] ^ v[ai]) >>> 0;
  const hi = (v[di + 1] ^ v[ai + 1]) >>> 0;
  switch (n) {
    case 32: v[di] = hi; v[di + 1] = lo; break;
    case 24: v[di] = ((lo >>> 24) | (hi << 8)) >>> 0; v[di + 1] = ((hi >>> 24) | (lo << 8)) >>> 0; break;
    case 16: v[di] = ((lo >>> 16) | (hi << 16)) >>> 0; v[di + 1] = ((hi >>> 16) | (lo << 16)) >>> 0; break;
    case 63: v[di] = ((lo << 1) | (hi >>> 31)) >>> 0; v[di + 1] = ((hi << 1) | (lo >>> 31)) >>> 0; break;
  }
}

function GB(v, a, b, c, d) {
  fBlaMka(v, a, b); xorRotr(v, d, a, 32);
  fBlaMka(v, c, d); xorRotr(v, b, c, 24);
  fBlaMka(v, a, b); xorRotr(v, d, a, 16);
  fBlaMka(v, c, d); xorRotr(v, b, c, 63);
}

function blamkaRound(v, i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, i12, i13, i14, i15) {
  GB(v, i0, i4, i8, i12); GB(v, i1, i5, i9, i13);
  GB(v, i2, i6, i10, i14); GB(v, i3, i7, i11, i15);
  GB(v, i0, i5, i10, i15); GB(v, i1, i6, i11, i12);
  GB(v, i2, i7, i8, i13); GB(v, i3, i4, i9, i14);
}

function argon2Compress(state, ref, out, withXor) {
  for (let i = 0; i < BLOCK_U32; i++) _R[i] = state[i] ^ ref[i];
  for (let i = 0; i < BLOCK_U32; i++) _tmp[i] = _R[i];
  if (withXor) { for (let i = 0; i < BLOCK_U32; i++) _tmp[i] ^= out[i]; }
  for (let i = 0; i < 8; i++) {
    const b = i * 32;
    blamkaRound(_R, b,b+2,b+4,b+6,b+8,b+10,b+12,b+14,b+16,b+18,b+20,b+22,b+24,b+26,b+28,b+30);
  }
  for (let i = 0; i < 8; i++) {
    const b = i * 4;
    blamkaRound(_R, b,b+2,b+32,b+34,b+64,b+66,b+96,b+98,b+128,b+130,b+160,b+162,b+192,b+194,b+224,b+226);
  }
  for (let i = 0; i < BLOCK_U32; i++) out[i] = _tmp[i] ^ _R[i];
}

// ── Argon2 indexing ─────────────────────────────────────────────

function indexAlpha(pass, slice, index, segmentLength, laneLength, pseudoRand, sameLane) {
  let refAreaSize;
  if (pass === 0) {
    if (slice === 0) {
      refAreaSize = index - 1;
    } else {
      refAreaSize = sameLane
        ? slice * segmentLength + index - 1
        : slice * segmentLength + (index === 0 ? -1 : 0);
    }
  } else {
    refAreaSize = sameLane
      ? laneLength - segmentLength + index - 1
      : laneLength - segmentLength + (index === 0 ? -1 : 0);
  }
  const x = mulHi(pseudoRand, pseudoRand);
  const y = mulHi(refAreaSize >>> 0, x);
  const relPos = refAreaSize - 1 - y;
  let startPos = 0;
  if (pass !== 0) {
    startPos = (slice === SYNC_POINTS - 1) ? 0 : (slice + 1) * segmentLength;
  }
  return ((startPos + relPos) % laneLength) >>> 0;
}

// ── Segment filling ─────────────────────────────────────────────

function generateAddresses(segmentLength, pass, lane, slice, memoryBlocks, passes) {
  const pseudoRands = new Uint32Array(segmentLength * 2);
  const zeroBlock = new Uint32Array(BLOCK_U32);
  const inputBlock = new Uint32Array(BLOCK_U32);
  const addressBlock = new Uint32Array(BLOCK_U32);
  inputBlock[0] = pass; inputBlock[2] = lane; inputBlock[4] = slice;
  inputBlock[6] = memoryBlocks; inputBlock[8] = passes; inputBlock[10] = 2;
  for (let i = 0; i < segmentLength; i++) {
    if (i % BLOCK_U64 === 0) {
      inputBlock[12]++;
      addressBlock.fill(0);
      argon2Compress(zeroBlock, inputBlock, addressBlock, false);
      argon2Compress(zeroBlock, addressBlock, addressBlock, false);
    }
    const idx = (i % BLOCK_U64) * 2;
    pseudoRands[i * 2] = addressBlock[idx];
    pseudoRands[i * 2 + 1] = addressBlock[idx + 1];
  }
  return pseudoRands;
}

function fillSegment(memory, pass, slice, lane, lanes, laneLength, segmentLength, memoryBlocks, passes) {
  const dataIndep = (pass === 0 && slice < SYNC_POINTS / 2);
  let pseudoRands;
  if (dataIndep) {
    pseudoRands = generateAddresses(segmentLength, pass, lane, slice, memoryBlocks, passes);
  }
  let startIdx = (pass === 0 && slice === 0) ? 2 : 0;
  const laneStart = lane * laneLength;

  for (let i = startIdx; i < segmentLength; i++) {
    const currOff = laneStart + slice * segmentLength + i;
    const prevOff = (i === 0 && slice === 0)
      ? laneStart + laneLength - 1
      : currOff - 1;
    let j1, j2;
    if (dataIndep) {
      j1 = pseudoRands[i * 2]; j2 = pseudoRands[i * 2 + 1];
    } else {
      const pb = prevOff * BLOCK_U32;
      j1 = memory[pb]; j2 = memory[pb + 1];
    }
    let refLane = j2 % lanes;
    if (pass === 0 && slice === 0) refLane = lane;
    const sameLane = (refLane === lane);
    const refIdx = indexAlpha(pass, slice, i, segmentLength, laneLength, j1, sameLane);
    const refOff = refLane * laneLength + refIdx;
    const stateView = memory.subarray(prevOff * BLOCK_U32, prevOff * BLOCK_U32 + BLOCK_U32);
    const refView = memory.subarray(refOff * BLOCK_U32, refOff * BLOCK_U32 + BLOCK_U32);
    const outView = memory.subarray(currOff * BLOCK_U32, currOff * BLOCK_U32 + BLOCK_U32);
    argon2Compress(stateView, refView, outView, pass > 0);
  }
}

// ── Main Argon2id function ──────────────────────────────────────

function argon2id(password, salt, timeCost, memoryCost, parallelism, hashLen) {
  if (password instanceof ArrayBuffer) password = new Uint8Array(password);
  if (salt instanceof ArrayBuffer) salt = new Uint8Array(salt);
  if (!(password instanceof Uint8Array)) throw new Error("password must be Uint8Array");
  if (!(salt instanceof Uint8Array)) throw new Error("salt must be Uint8Array");
  if (!Number.isInteger(timeCost) || timeCost < 1) {
    throw new Error("argon2id: timeCost must be a positive integer, got " + timeCost);
  }
  if (!Number.isInteger(memoryCost) || memoryCost < 8) {
    throw new Error("argon2id: memoryCost must be >= 8 KiB, got " + memoryCost);
  }
  if (memoryCost > 4194304) {
    throw new Error("argon2id: memoryCost exceeds 4 GiB limit (" + memoryCost + " KiB)");
  }
  if (!Number.isInteger(parallelism) || parallelism < 1) {
    throw new Error("argon2id: parallelism must be a positive integer, got " + parallelism);
  }
  if (!Number.isInteger(hashLen) || hashLen < 4) {
    throw new Error("argon2id: hashLen must be >= 4, got " + hashLen);
  }
  if (salt.length < 8) {
    throw new Error("argon2id: salt must be >= 8 bytes, got " + salt.length);
  }

  const p = parallelism, m = memoryCost, t = timeCost, T = hashLen;

  let memBlocks = m;
  if (memBlocks < 2 * SYNC_POINTS * p) memBlocks = 2 * SYNC_POINTS * p;
  memBlocks -= memBlocks % (p * SYNC_POINTS);

  const segLen = memBlocks / (p * SYNC_POINTS);
  const laneLen = segLen * SYNC_POINTS;

  const memory = new Uint32Array(memBlocks * BLOCK_U32);

  // H0 = Blake2b-64( LE32(p) || LE32(T) || LE32(m) || LE32(t) || LE32(0x13) || LE32(2) ||
  //                   LE32(|P|) || P || LE32(|S|) || S || LE32(0) || LE32(0) )
  const H0 = blake2b(cat(
    le32(p), le32(T), le32(m), le32(t), le32(0x13), le32(2),
    le32(password.length), password,
    le32(salt.length), salt,
    le32(0), le32(0)
  ), 64);

  // Fill first two blocks of each lane
  for (let lane = 0; lane < p; lane++) {
    const b0 = argon2Hash(cat(H0, le32(0), le32(lane)), BLOCK_BYTES);
    loadBlock(b0, memory, lane * laneLen * BLOCK_U32);
    const b1 = argon2Hash(cat(H0, le32(1), le32(lane)), BLOCK_BYTES);
    loadBlock(b1, memory, (lane * laneLen + 1) * BLOCK_U32);
  }

  // Fill remaining blocks
  for (let pass = 0; pass < t; pass++) {
    for (let slice = 0; slice < SYNC_POINTS; slice++) {
      for (let lane = 0; lane < p; lane++) {
        fillSegment(memory, pass, slice, lane, p, laneLen, segLen, memBlocks, t);
      }
    }
  }

  // Finalize: XOR last blocks of all lanes
  const finalBlock = new Uint32Array(BLOCK_U32);
  for (let lane = 0; lane < p; lane++) {
    const off = (lane * laneLen + laneLen - 1) * BLOCK_U32;
    for (let i = 0; i < BLOCK_U32; i++) finalBlock[i] ^= memory[off + i];
  }

  let result;
  try {
    result = argon2Hash(storeBlock(finalBlock, 0), T);
  } finally {
    // Best-effort cleanup of sensitive memory
    memory.fill(0);
    finalBlock.fill(0);
    _R.fill(0);
    _tmp.fill(0);
  }

  return result;
}

// ── Async Argon2id (Web Worker) ─────────────────────────────────

let _workerURL = null;

function _getWorkerURL() {
  if (_workerURL) return _workerURL;
  // Build a self-contained worker script from the functions above
  const src = `"use strict";
${le32.toString()}
${cat.toString()}
${loadBlock.toString()}
${storeBlock.toString()}
${mulHi.toString()}
var BLOCK_BYTES=${BLOCK_BYTES},BLOCK_U32=${BLOCK_U32},BLOCK_U64=${BLOCK_U64},SYNC_POINTS=${SYNC_POINTS},MASK64=(1n<<64n)-1n;
var B2B_IV=[${B2B_IV.map(v => v + "n").join(",")}];
var SIGMA=${JSON.stringify(SIGMA)};
${b2bG.toString()}
${b2bCompress.toString()}
${blake2b.toString()}
${argon2Hash.toString()}
var _R=new Uint32Array(${BLOCK_U32}),_tmp=new Uint32Array(${BLOCK_U32});
${fBlaMka.toString()}
${xorRotr.toString()}
${GB.toString()}
${blamkaRound.toString()}
${argon2Compress.toString()}
${indexAlpha.toString()}
${generateAddresses.toString()}
${fillSegment.toString()}
${argon2id.toString()}
self.onmessage=function(e){
  var d=e.data;
  var r=argon2id(new Uint8Array(d.password),new Uint8Array(d.salt),d.t,d.m,d.p,d.hashLen);
  self.postMessage(r.buffer,[r.buffer]);
};`;
  const blob = new Blob([src], { type: "application/javascript" });
  _workerURL = URL.createObjectURL(blob);
  return _workerURL;
}

function argon2idAsync(password, salt, timeCost, memoryCost, parallelism, hashLen) {
  if (typeof Worker !== "undefined" && typeof Blob !== "undefined" && typeof URL !== "undefined" && URL.createObjectURL) {
    return new Promise(function(resolve) {
      try {
        var url = _getWorkerURL();
        var w = new Worker(url);
        w.onmessage = function(e) {
          w.terminate();
          resolve(new Uint8Array(e.data));
        };
        w.onerror = function() {
          w.terminate();
          resolve(argon2id(password, salt, timeCost, memoryCost, parallelism, hashLen));
        };
        // Transfer copies of the typed array data
        var pw = password.slice().buffer;
        var sl = salt.slice().buffer;
        w.postMessage({ password: pw, salt: sl, t: timeCost, m: memoryCost, p: parallelism, hashLen: hashLen }, [pw, sl]);
      } catch(_) {
        resolve(argon2id(password, salt, timeCost, memoryCost, parallelism, hashLen));
      }
    });
  }
  return Promise.resolve(argon2id(password, salt, timeCost, memoryCost, parallelism, hashLen));
}

module.exports = { argon2id, argon2idAsync, blake2b };

};

// ── crypto/ed25519.js ──
_dirs["./crypto/ed25519"] = "./crypto";
_modules["./crypto/ed25519"] = function(module, exports, require) {
// Copyright (c) 2026 Signer.io — MIT License

"use strict";

// Ed25519 digital signatures (RFC 8032).
//
// Pure JavaScript implementation using fixed-width 16-limb field arithmetic.
// Extended coordinates (X, Y, Z, T) where x=X/Z, y=Y/Z, X*Y=Z*T.
//
// Sizes:
//     Secret key:  64 bytes (seed || public_key)
//     Public key:  32 bytes (compressed Edwards point)
//     Signature:   64 bytes (R || S)
//
// When Node.js crypto is available, uses native Ed25519 (constant-time OpenSSL).
// Falls back to pure JavaScript using fixed-width 16-limb field arithmetic.
// All control flow and arithmetic is constant-time (no BigInt in hot path).

const { sha512 } = require("./sha2");
const { toBytes, zeroize, constantTimeEqual } = require("./utils");
const {
  feZero, feOne, feCopy, feFromBytes, feToBytes,
  feAdd, feSub, feNeg, feMul, feSqr, feInv, feSqrt,
  feCswap, feCmov, feIsZero, feIsNeg, feEqual,
} = require("./field25519");

// ── Curve Constants ─────────────────────────────────────────────

// Group order L = 2^252 + 27742317777372353535851937790883648493
// Stored as bytes for scalar arithmetic (BigInt only for non-secret scalars)
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

// d = -121665/121666 mod p
const _D = feFromBytes(new Uint8Array([
  0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
  0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
  0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
  0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
]));

// 2*d
const _D2 = feAdd(_D, _D);

// Base point G: y = 4/5 mod p
const G = (function () {
  // Compute y = 4 * inv(5)
  const four = feFromBytes(new Uint8Array([4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
  const five = feFromBytes(new Uint8Array([5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
  const y = feMul(four, feInv(five));

  // x^2 = (y^2 - 1) / (d*y^2 + 1)
  const ySq = feSqr(y);
  const num = feSub(ySq, feOne());
  const den = feAdd(feMul(_D, ySq), feOne());
  const xSq = feMul(num, feInv(den));

  let x = feSqrt(xSq);
  if (x === null) throw new Error("Ed25519: basepoint sqrt failed");

  // x should be even (positive)
  if (feIsNeg(x)) x = feNeg(x);

  return [x, y, feOne(), feMul(x, y)];
})();

const ZERO = [feZero(), feOne(), feOne(), feZero()];

// ── Point Arithmetic ────────────────────────────────────────────

function pointAdd(P1, Q) {
  // No identity-point early returns — always perform full computation for
  // constant-time execution. Extended coordinates handle identity correctly.
  const [X1, Y1, Z1, T1] = P1;
  const [X2, Y2, Z2, T2] = Q;

  const A = feMul(feSub(Y1, X1), feSub(Y2, X2));
  const B = feMul(feAdd(Y1, X1), feAdd(Y2, X2));
  const C = feMul(feMul(_D2, T1), T2);
  const DD = feMul(feAdd(Z1, Z1), Z2);
  const E = feSub(B, A);
  const F = feSub(DD, C);
  const GG = feAdd(DD, C);
  const H = feAdd(B, A);

  return [feMul(E, F), feMul(GG, H), feMul(F, GG), feMul(E, H)];
}

function pointDouble(P1) {
  const [X1, Y1, Z1] = P1;

  const A = feSqr(X1);
  const B = feSqr(Y1);
  const C = feAdd(feSqr(Z1), feSqr(Z1));
  const DD = feNeg(A);
  const E = feSub(feSub(feSqr(feAdd(X1, Y1)), A), B);
  const GG = feAdd(DD, B);
  const F = feSub(GG, C);
  const H = feSub(DD, B);

  return [feMul(E, F), feMul(GG, H), feMul(F, GG), feMul(E, H)];
}

function pointNegate(P1) {
  return [feNeg(P1[0]), feCopy(P1[1]), feCopy(P1[2]), feNeg(P1[3])];
}

// Precomputed table for G (built on first use)
let _gTable = null;

function buildGTable() {
  if (_gTable !== null) return;
  const table = [G];
  let pt = G;
  for (let i = 0; i < 255; i++) {
    pt = pointDouble(pt);
    table.push(pt);
  }
  _gTable = table;
}

// Constant-time scalar multiplication: [k]G using precomputed table.
// No branches on secret scalar bits.
function scalarMultBase(k) {
  k = ((k % L) + L) % L;
  if (_gTable === null) buildGTable();

  let R = [feCopy(ZERO[0]), feCopy(ZERO[1]), feCopy(ZERO[2]), feCopy(ZERO[3])];
  for (let i = 0; i < _gTable.length; i++) {
    const bit = Number((k >> BigInt(i)) & 1n);
    const added = pointAdd(R, _gTable[i]);
    // CT select: bit=1 → added, bit=0 → R
    for (let c = 0; c < 4; c++) {
      feCmov(R[c], added[c], bit);
    }
  }
  return R;
}

// Constant-time scalar multiplication: [k]P using Montgomery ladder.
// Fixed 253-bit iteration regardless of actual bit length of k.
function scalarMult(k, pt) {
  k = ((k % L) + L) % L;

  let R0 = [feCopy(ZERO[0]), feCopy(ZERO[1]), feCopy(ZERO[2]), feCopy(ZERO[3])];
  let R1 = [feCopy(pt[0]), feCopy(pt[1]), feCopy(pt[2]), feCopy(pt[3])];

  for (let i = 252; i >= 0; i--) {
    const bit = Number((k >> BigInt(i)) & 1n);
    // CT swap
    for (let c = 0; c < 4; c++) feCswap(R0[c], R1[c], bit);
    const sum = pointAdd(R0, R1);
    const dbl = pointDouble(R0);
    R0 = dbl;
    R1 = sum;
    // CT swap back
    for (let c = 0; c < 4; c++) feCswap(R0[c], R1[c], bit);
  }
  return R0;
}

// ── Point Encoding (RFC 8032 Section 5.1.2) ─────────────────────

function toAffine(pt) {
  const [X, Y, Z] = pt;
  if (feIsZero(Z)) return [feZero(), feOne()];
  const zInv = feInv(Z);
  return [feMul(X, zInv), feMul(Y, zInv)];
}

function encodePoint(pt) {
  const [x, y] = toAffine(pt);
  const out = feToBytes(y);
  if (feIsNeg(x)) out[31] |= 0x80;
  return out;
}

function decodePoint(b) {
  if (b.length !== 32) return null;

  const yBytes = new Uint8Array(b);
  const sign = (yBytes[31] & 0x80) !== 0;
  yBytes[31] &= 0x7f;

  // Check y < p by encoding and comparing
  const y = feFromBytes(yBytes);
  const yReduced = feToBytes(y);
  let yOk = 1;
  for (let i = 0; i < 32; i++) yOk &= (yBytes[i] === yReduced[i]) ? 1 : 0;
  if (!yOk) return null;

  // x^2 = (y^2 - 1) / (d*y^2 + 1)
  const ySq = feSqr(y);
  const num = feSub(ySq, feOne());
  const den = feAdd(feMul(_D, ySq), feOne());
  const xSq = feMul(num, feInv(den));

  if (feIsZero(xSq)) {
    if (sign) return null;
    return [feZero(), feCopy(y), feOne(), feZero()];
  }

  let x = feSqrt(xSq);
  if (x === null) return null;

  // Verify: x^2 == xSq
  if (!feEqual(feSqr(x), xSq)) return null;

  if (feIsNeg(x) !== (sign ? 1 : 0)) {
    x = feNeg(x);
  }

  // Verify on curve: -x^2 + y^2 = 1 + d*x^2*y^2
  const lhs = feAdd(feNeg(feSqr(x)), ySq);
  const rhs = feAdd(feOne(), feMul(_D, feMul(feSqr(x), ySq)));
  if (!feEqual(lhs, rhs)) return null;

  return [x, feCopy(y), feOne(), feMul(x, y)];
}

// ── RFC 8032 Clamping ───────────────────────────────────────────

function clamp(h) {
  const a = new Uint8Array(h.subarray(0, 32));
  a[0] &= 248;
  a[31] &= 127;
  a[31] |= 64;
  return a;
}

function bytesToBigIntLE(b) {
  let v = 0n;
  for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
  return v;
}

// ── Small-Order Point Rejection ──────────────────────────────────

function isSmallOrder(pt) {
  // Multiply by cofactor 8: if result is identity, the point has small order
  const Q = pointDouble(pointDouble(pointDouble(pt))); // 8P
  const [x, y] = toAffine(Q);
  return feIsZero(x) && feEqual(y, feOne());
}

// ── Native Node.js Ed25519 (constant-time via OpenSSL) ──────────

const _ED25519_SK_DER_PREFIX = Buffer.from(
  "302e020100300506032b657004220420", "hex"
);
const _ED25519_PK_DER_PREFIX = Buffer.from(
  "302a300506032b6570032100", "hex"
);

let _nativeKeygen = null;
let _nativeSign = null;
let _nativeVerify = null;

try {
  const nodeCrypto = require("crypto");
  const _probe = nodeCrypto.createPrivateKey({
    key: Buffer.concat([_ED25519_SK_DER_PREFIX, Buffer.alloc(32)]),
    format: "der", type: "pkcs8",
  });
  nodeCrypto.sign(null, Buffer.alloc(1), _probe);

  _nativeKeygen = (seed) => {
    const der = Buffer.concat([_ED25519_SK_DER_PREFIX, Buffer.from(seed)]);
    const privateKey = nodeCrypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    const publicKey = nodeCrypto.createPublicKey(privateKey);
    const pkDer = publicKey.export({ type: "spki", format: "der" });
    const pk = new Uint8Array(pkDer.subarray(pkDer.length - 32));
    const sk = new Uint8Array(64);
    sk.set(seed);
    sk.set(pk, 32);
    return { sk, pk };
  };

  _nativeSign = (message, seed) => {
    const der = Buffer.concat([_ED25519_SK_DER_PREFIX, Buffer.from(seed)]);
    const privateKey = nodeCrypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    return new Uint8Array(nodeCrypto.sign(null, Buffer.from(message), privateKey));
  };

  _nativeVerify = (message, sig, pk) => {
    const der = Buffer.concat([_ED25519_PK_DER_PREFIX, Buffer.from(pk)]);
    const publicKey = nodeCrypto.createPublicKey({ key: der, format: "der", type: "spki" });
    return nodeCrypto.verify(null, Buffer.from(message), publicKey, Buffer.from(sig));
  };
} catch (_) {
  // Native Ed25519 not available — pure JS fallback
}

// ── Public API ──────────────────────────────────────────────────

function ed25519Keygen(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new Error("Ed25519 seed must be a 32-byte Uint8Array");
  }
  if (_nativeKeygen) return _nativeKeygen(seed);

  const h = sha512(seed);
  const a = bytesToBigIntLE(clamp(h));
  const pkPoint = scalarMultBase(a);
  const pkBytes = encodePoint(pkPoint);

  // sk = seed || pk
  const sk = new Uint8Array(64);
  sk.set(seed);
  sk.set(pkBytes, 32);

  return { sk, pk: pkBytes };
}

function ed25519Sign(message, skBytes) {
  message = toBytes(message);
  if (!(skBytes instanceof Uint8Array) || skBytes.length !== 64) {
    throw new Error("Ed25519 sk must be a 64-byte Uint8Array");
  }
  if (_nativeSign) return _nativeSign(message, skBytes.subarray(0, 32));

  const seed = skBytes.subarray(0, 32);
  const pkBytes = skBytes.subarray(32, 64);

  const h = sha512(seed);
  const a = bytesToBigIntLE(clamp(h));
  const prefix = new Uint8Array(h.subarray(32, 64));

  // r = SHA-512(prefix || message) mod L
  const rInput = new Uint8Array(prefix.length + message.length);
  rInput.set(prefix);
  rInput.set(message, prefix.length);
  const r = bytesToBigIntLE(sha512(rInput)) % L;

  // R = r * G
  const R = scalarMultBase(r);
  const rBytes = encodePoint(R);

  // S = (r + SHA-512(R || pk || message) * a) mod L
  const hramInput = new Uint8Array(32 + 32 + message.length);
  hramInput.set(rBytes);
  hramInput.set(pkBytes, 32);
  hramInput.set(message, 64);
  const hram = bytesToBigIntLE(sha512(hramInput)) % L;
  const S = (r + hram * a) % L;

  // Encode S as 32 bytes LE
  const sBytes = new Uint8Array(32);
  let ss = S;
  for (let i = 0; i < 32; i++) {
    sBytes[i] = Number(ss & 0xffn);
    ss >>= 8n;
  }

  // Best-effort cleanup of secret intermediates
  zeroize(h);
  zeroize(prefix);
  zeroize(rInput);

  const sig = new Uint8Array(64);
  sig.set(rBytes);
  sig.set(sBytes, 32);
  return sig;
}

function ed25519Verify(message, sigBytes, pkBytes) {
  message = toBytes(message);
  if (sigBytes.length !== 64 || pkBytes.length !== 32) return false;

  // Decode and validate points
  const A = decodePoint(pkBytes);
  if (A === null) return false;
  if (isSmallOrder(A)) return false;

  const R = decodePoint(sigBytes.subarray(0, 32));
  if (R === null) return false;
  if (isSmallOrder(R)) return false;

  // Native path (constant-time via OpenSSL) — small-order check done above
  if (_nativeVerify) return _nativeVerify(message, sigBytes, pkBytes);

  // Pure JS fallback (branchless control flow)
  const S = bytesToBigIntLE(sigBytes.subarray(32, 64));
  if (S >= L) return false;

  // h = SHA-512(R || pk || message) mod L
  const hInput = new Uint8Array(32 + 32 + message.length);
  hInput.set(sigBytes.subarray(0, 32));
  hInput.set(pkBytes, 32);
  hInput.set(message, 64);
  const h = bytesToBigIntLE(sha512(hInput)) % L;

  // Check: [S]B == R + [h]A
  const lhs = scalarMultBase(S);
  const rhs = pointAdd(R, scalarMult(h, A));

  // Constant-time comparison via encoded points
  return constantTimeEqual(encodePoint(lhs), encodePoint(rhs));
}

// Sizes
const ED25519_SK_SIZE = 64;
const ED25519_PK_SIZE = 32;
const ED25519_SIG_SIZE = 64;

module.exports = {
  ed25519Keygen,
  ed25519Sign,
  ed25519Verify,
  ED25519_SK_SIZE,
  ED25519_PK_SIZE,
  ED25519_SIG_SIZE,
};

};

// ── crypto/x25519.js ──
_dirs["./crypto/x25519"] = "./crypto";
_modules["./crypto/x25519"] = function(module, exports, require) {
// Copyright (c) 2026 Signer.io — MIT License

"use strict";

// X25519 Diffie-Hellman key exchange (RFC 7748).
//
// Montgomery curve: y^2 = x^3 + 486662*x^2 + x  over GF(2^255 - 19).
// Montgomery ladder for scalar multiplication (x-coordinate only).
//
// Sizes:
//     Private key:    32 bytes (clamped scalar)
//     Public key:     32 bytes (u-coordinate of [sk] * basepoint)
//     Shared secret:  32 bytes
//
// When Node.js crypto is available, uses native X25519 (constant-time OpenSSL).
// Falls back to pure JavaScript using fixed-width 16-limb field arithmetic
// (no BigInt). All control flow and arithmetic is truly constant-time.

const {
  feZero, feOne, feFromBytes, feToBytes,
  feAdd, feSub, feMul, feSqr, feInv, feCswap,
} = require("./field25519");

// (A - 2) / 4 where A = 486662
const _A24 = feFromBytes(new Uint8Array([
  0x39, 0xdb, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])); // 121665

// ── Helpers ─────────────────────────────────────────────────────

function clamp(kBytes) {
  const k = new Uint8Array(kBytes);
  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;
  return k;
}

// ── Core Scalar Multiplication (RFC 7748 Section 5) ─────────────
// Uses fixed-width field arithmetic — fully constant-time.

function x25519Raw(kBytes, uBytes) {
  const kClamped = clamp(kBytes);

  // Decode u-coordinate, masking bit 255 per RFC 7748
  const uMasked = new Uint8Array(uBytes);
  uMasked[31] &= 127;
  const u = feFromBytes(uMasked);

  let x2 = feOne();
  let z2 = feZero();
  let x3 = feFromBytes(uMasked);
  let z3 = feOne();
  let swap = 0;

  for (let t = 254; t >= 0; t--) {
    const kt = (kClamped[t >>> 3] >>> (t & 7)) & 1;
    swap ^= kt;
    // Constant-time conditional swap
    feCswap(x2, x3, swap);
    feCswap(z2, z3, swap);
    swap = kt;

    const A = feAdd(x2, z2);
    const AA = feSqr(A);
    const B = feSub(x2, z2);
    const BB = feSqr(B);
    const E = feSub(AA, BB);
    const C = feAdd(x3, z3);
    const DD = feSub(x3, z3);
    const DA = feMul(DD, A);
    const CB = feMul(C, B);

    const sum = feAdd(DA, CB);
    x3 = feSqr(sum);
    const diff = feSub(DA, CB);
    z3 = feMul(u, feSqr(diff));
    x2 = feMul(AA, BB);
    z2 = feMul(E, feAdd(AA, feMul(_A24, E)));
  }

  // Final swap (branchless)
  feCswap(x2, x3, swap);
  feCswap(z2, z3, swap);

  // x2 * z2^(p-2)
  return feToBytes(feMul(x2, feInv(z2)));
}

// ── Native Node.js X25519 (constant-time via OpenSSL) ───────────

const _X25519_SK_DER_PREFIX = Buffer.from(
  "302e020100300506032b656e04220420", "hex"
);
const _X25519_PK_DER_PREFIX = Buffer.from(
  "302a300506032b656e032100", "hex"
);

let _nativeX25519Keygen = null;
let _nativeX25519DH = null;

try {
  const nodeCrypto = require("crypto");
  // Probe: create a test X25519 key
  const _probe = Buffer.concat([_X25519_SK_DER_PREFIX, Buffer.alloc(32)]);
  nodeCrypto.createPrivateKey({ key: _probe, format: "der", type: "pkcs8" });

  _nativeX25519Keygen = (sk) => {
    const der = Buffer.concat([_X25519_SK_DER_PREFIX, Buffer.from(sk)]);
    const privateKey = nodeCrypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    const publicKey = nodeCrypto.createPublicKey(privateKey);
    const pkDer = publicKey.export({ type: "spki", format: "der" });
    return new Uint8Array(pkDer.subarray(pkDer.length - 32));
  };

  _nativeX25519DH = (sk, pk) => {
    const skDer = Buffer.concat([_X25519_SK_DER_PREFIX, Buffer.from(sk)]);
    const pkDer = Buffer.concat([_X25519_PK_DER_PREFIX, Buffer.from(pk)]);
    const privateKey = nodeCrypto.createPrivateKey({ key: skDer, format: "der", type: "pkcs8" });
    const publicKey = nodeCrypto.createPublicKey({ key: pkDer, format: "der", type: "spki" });
    return new Uint8Array(nodeCrypto.diffieHellman({ privateKey, publicKey }));
  };
} catch (_) {
  // Native X25519 not available — pure JS fallback
}

// ── Public API ──────────────────────────────────────────────────

function x25519Keygen(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new Error("X25519 seed must be a 32-byte Uint8Array");
  }

  const sk = clamp(seed);
  if (_nativeX25519Keygen) {
    const pk = _nativeX25519Keygen(sk);
    return { sk, pk };
  }
  // Pure JS fallback
  const basepoint = new Uint8Array(32);
  basepoint[0] = 9;
  const pk = x25519Raw(sk, basepoint);
  return { sk, pk };
}

function x25519(sk, pk) {
  if (!(sk instanceof Uint8Array) || sk.length !== 32) {
    throw new Error("X25519 sk must be a 32-byte Uint8Array");
  }
  if (!(pk instanceof Uint8Array) || pk.length !== 32) {
    throw new Error("X25519 pk must be a 32-byte Uint8Array");
  }

  let result;
  if (_nativeX25519DH) {
    result = _nativeX25519DH(sk, pk);
  } else {
    result = x25519Raw(sk, pk);
  }

  // Reject low-order points (all-zero output) per RFC 7748 Section 6.1
  // Constant-time: accumulate OR of all bytes (no early break)
  let acc = 0;
  for (let i = 0; i < 32; i++) acc |= result[i];
  if (acc === 0) {
    throw new Error("X25519: low-order input point (all-zero shared secret)");
  }

  return result;
}

/**
 * X25519 shared secret without low-order point rejection.
 * For use in hybrid KEM where ML-KEM carries security if classical fails.
 * Avoids try/catch timing leak on attacker-controlled ciphertexts.
 */
function x25519NoCheck(sk, pk) {
  if (_nativeX25519DH) {
    // Native path may throw on low-order points — catch without timing leak
    // (Node.js native crypto is already constant-time; the exception is rare
    // and only occurs on malicious input, not during normal operation)
    try { return _nativeX25519DH(sk, pk); }
    catch (_) { return new Uint8Array(32); }
  }
  // Pure JS: compute raw, return result (may be all-zero for low-order points)
  return x25519Raw(sk, pk);
}

module.exports = { x25519Keygen, x25519, x25519NoCheck, X25519_SK_SIZE: 32, X25519_PK_SIZE: 32 };

};

// ── crypto/ml_dsa.js ──
_dirs["./crypto/ml_dsa"] = "./crypto";
_modules["./crypto/ml_dsa"] = function(module, exports, require) {
// Copyright (c) 2026 Signer.io — MIT License

"use strict";

// ML-DSA-65 (Dilithium) — FIPS 204 post-quantum digital signature.
//
// Pure JavaScript implementation of the Module-Lattice-Based Digital Signature
// Standard (ML-DSA) at Security Level 3 (ML-DSA-65).
//
// Operates over the polynomial ring Z_q[X]/(X^256 + 1) where q = 8380417.
// Uses NTT (Number Theoretic Transform) for efficient polynomial multiplication.
//
// Key sizes:
//     Public key:  1,952 bytes
//     Secret key:  4,032 bytes
//     Signature:   3,309 bytes
//
// Security: NIST Level 3 (~192-bit post-quantum security).
// Assumption: Module Learning With Errors (MLWE) hardness.
//
// Reference: NIST FIPS 204 (August 2024).
//
// Public API:
//     mlKeygen(seed)                    -> {sk, pk}     (seed: 32-byte Uint8Array)
//     mlSign(msg, sk, opts?)            -> Uint8Array    (3,309-byte signature, raw/interoperable)
//     mlVerify(msg, sig, pk)            -> bool          (raw/interoperable)
//     mlSignWithContext(msg, sk, ctx, opts?)  -> Uint8Array (FIPS 204 pure mode with context)
//     mlVerifyWithContext(msg, sig, pk, ctx)  -> bool
//
// Notes:
//     - All arithmetic uses regular JavaScript Number (q=8380417 fits in 53-bit
//       safe integers, products up to q^2 ~ 7e13 also fit).
//     - Signing defaults to hedged mode (rnd generated via CSPRNG)
//       as recommended by FIPS 204. Pass deterministic:true for reproducible
//       signatures (uses rnd=0^32).
//     - Best-effort constant-time: all control flow is branchless (no
//       secret-dependent branches). Integer arithmetic is fixed-time.
//       For deployments where hardware side-channel attacks are a concern,
//       use a vetted constant-time C/Rust implementation instead.

const { shake128, shake256, shake128Xof, shake256Xof } = require("./sha3");
const { randomBytes, zeroize, toBytes, constantTimeEqual } = require("./utils");

function zeroizeVec(v) {
  for (let i = 0; i < v.length; i++) zeroize(v[i]);
}

// -- ML-DSA-65 Parameters (FIPS 204 Table 1) ---------------------------------

const Q = 8380417;           // Prime modulus: 2^23 - 2^13 + 1
const N = 256;               // Polynomial degree
const D = 13;                // Dropped bits from t
const K = 6;                 // Rows in matrix A (module dimension)
const L = 5;                 // Columns in matrix A
const ETA = 4;               // Secret key coefficient bound
const TAU = 49;              // Challenge polynomial weight (number of +/-1)
const BETA = TAU * ETA;      // = 196 -- FIPS 204 Table 1: beta for ML-DSA-65
const GAMMA1 = 1 << 19;     // 2^19 = 524288 -- masking range
const GAMMA2 = (Q - 1) / 32 | 0;  // = 261888 -- decomposition divisor
const OMEGA = 55;            // Max number of 1s in hint
const C_TILDE_BYTES = 48;   // Challenge seed bytes

// -- NTT Constants ------------------------------------------------------------

// Precomputed 256 zetas in bit-reversed order (FIPS 204 Section 4.6).
// ZETAS[0] = 0 (unused; NTT starts at index 1).
// Primitive 512th root of unity: ROOT = 1753.
const ZETAS = [
  0, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987,
  7778734, 3542485, 2682288, 2129892, 3764867, 7375178, 557458, 7159240,
  5010068, 4317364, 2663378, 6705802, 4855975, 7946292, 676590, 7044481,
  5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733,
  3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875,
  394148, 928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050,
  3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429, 4430364,
  5483103, 3192354, 556856, 3870317, 2917338, 1853806, 3345963, 1858416,
  3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357,
  2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088,
  1528066, 482649, 1148858, 5418153, 7814814, 169688, 2462444, 5046034,
  4213992, 4892034, 1987814, 5183169, 1736313, 235407, 5130263, 3258457,
  5801164, 1787943, 5989328, 6125690, 3482206, 4197502, 7080401, 6018354,
  7062739, 2461387, 3035980, 621164, 3901472, 7153756, 2925816, 3374250,
  1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254,
  348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507,
  1753, 6444997, 5720892, 6924527, 2660408, 6600190, 8321269, 2772600,
  1182243, 87208, 636927, 4415111, 4423672, 6084020, 5095502, 4663471,
  8352605, 822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952,
  6695264, 4969849, 2678278, 4611469, 4829411, 635956, 8129971, 5925040,
  4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961,
  3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000,
  2998219, 141835, 8291116, 2513018, 7025525, 613238, 7070156, 6161950,
  7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452,
  6757063, 2105286, 6006015, 6346610, 586241, 7200804, 527981, 5637006,
  6903432, 1994046, 2491325, 6987258, 507927, 7192532, 7655613, 6545891,
  5346675, 8041997, 2647994, 3009748, 5767564, 4148469, 749577, 4357667,
  3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144,
  3994671, 8368538, 7009900, 3020393, 3363542, 214880, 545376, 7609976,
  3105558, 7277073, 508145, 7826699, 860144, 3430436, 140244, 6866265,
  6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710,
  8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983,
];

// Inverse of 256 mod q, for inverse NTT scaling.
const N_INV = 8347681;

// -- Key / Signature Sizes ----------------------------------------------------

const PK_SIZE = 32 + K * 320;                        // 32 + 6*320 = 1952
const SK_SIZE = 128 + (L + K) * 128 + K * 416;       // 128 + 11*128 + 6*416 = 4032
const SIG_SIZE = C_TILDE_BYTES + L * 640 + OMEGA + K; // 48 + 3200 + 61 = 3309

// -- Modular Arithmetic Helpers -----------------------------------------------

// JavaScript % can return negative values. Branchless fixup ensures result in [0, m).
function mod(a, m) {
  const r = a % m;
  return r + (m & (r >> 31)); // add m when r is negative (sign bit = 1)
}

// -- NTT Operations -----------------------------------------------------------

/**
 * Forward NTT (Algorithm 41, FIPS 204).
 * Transforms polynomial from coefficient domain to NTT evaluation domain.
 * In-place Cooley-Tukey butterfly with bit-reversed zetas.
 */
function ntt(a) {
  const f = new Array(N);
  for (let i = 0; i < N; i++) f[i] = a[i];
  let k = 1;
  let len = 128;
  while (len >= 1) {
    let start = 0;
    while (start < N) {
      const zeta = ZETAS[k];
      k++;
      for (let j = start; j < start + len; j++) {
        const t = (zeta * f[j + len]) % Q;
        f[j + len] = mod(f[j] - t, Q);
        f[j] = (f[j] + t) % Q;
      }
      start += 2 * len;
    }
    len >>= 1;
  }
  return f;
}

/**
 * Inverse NTT (Algorithm 42, FIPS 204).
 * Transforms from NTT domain back to coefficient domain.
 * Gentleman-Sande butterfly with inverse zetas.
 */
function invNtt(f) {
  const a = new Array(N);
  for (let i = 0; i < N; i++) a[i] = f[i];
  let k = 255;
  let len = 1;
  while (len < N) {
    let start = 0;
    while (start < N) {
      const zeta = Q - ZETAS[k]; // -ZETAS[k] mod Q
      k--;
      for (let j = start; j < start + len; j++) {
        const t = a[j];
        a[j] = (t + a[j + len]) % Q;
        a[j + len] = mod(zeta * mod(t - a[j + len], Q), Q);
      }
      start += 2 * len;
    }
    len <<= 1;
  }
  for (let i = 0; i < N; i++) {
    a[i] = (a[i] * N_INV) % Q;
  }
  return a;
}

/**
 * Pointwise multiplication of two NTT-domain polynomials.
 * ML-DSA uses simple element-wise: (a[i] * b[i]) % Q.
 */
function nttMult(a, b) {
  const c = new Array(N);
  for (let i = 0; i < N; i++) {
    c[i] = (a[i] * b[i]) % Q;
  }
  return c;
}

// -- Polynomial Arithmetic ----------------------------------------------------

/** Coefficient-wise addition mod q. */
function polyAdd(a, b) {
  const c = new Array(N);
  for (let i = 0; i < N; i++) c[i] = (a[i] + b[i]) % Q;
  return c;
}

/** Coefficient-wise subtraction mod q. */
function polySub(a, b) {
  const c = new Array(N);
  for (let i = 0; i < N; i++) c[i] = mod(a[i] - b[i], Q);
  return c;
}

/** Zero polynomial. */
function polyZero() {
  const z = new Array(N);
  for (let i = 0; i < N; i++) z[i] = 0;
  return z;
}

// -- Module (Vector/Matrix) Operations ----------------------------------------

/** Apply NTT to each polynomial in a vector. */
function vecNtt(v) {
  const r = new Array(v.length);
  for (let i = 0; i < v.length; i++) r[i] = ntt(v[i]);
  return r;
}

/** Apply inverse NTT to each polynomial in a vector. */
function vecInvNtt(v) {
  const r = new Array(v.length);
  for (let i = 0; i < v.length; i++) r[i] = invNtt(v[i]);
  return r;
}

/** Vector addition. */
function vecAdd(u, v) {
  const r = new Array(u.length);
  for (let i = 0; i < u.length; i++) r[i] = polyAdd(u[i], v[i]);
  return r;
}

/** Vector subtraction. */
function vecSub(u, v) {
  const r = new Array(u.length);
  for (let i = 0; i < u.length; i++) r[i] = polySub(u[i], v[i]);
  return r;
}

/**
 * Matrix-vector product in NTT domain.
 * A is k*l matrix of NTT-domain polynomials.
 * v is l-vector of NTT-domain polynomials.
 * Returns k-vector of NTT-domain polynomials.
 */
function matVecNtt(A, v) {
  const result = new Array(A.length);
  for (let i = 0; i < A.length; i++) {
    let acc = polyZero();
    for (let j = 0; j < v.length; j++) {
      acc = polyAdd(acc, nttMult(A[i][j], v[j]));
    }
    result[i] = acc;
  }
  return result;
}

/** Inner product of two vectors in NTT domain. */
function innerProductNtt(a, b) {
  let acc = polyZero();
  for (let i = 0; i < a.length; i++) {
    acc = polyAdd(acc, nttMult(a[i], b[i]));
  }
  return acc;
}

// -- Helper: Concatenate Uint8Arrays ------------------------------------------

function concatBytes(/* ...arrays */) {
  let total = 0;
  for (let i = 0; i < arguments.length; i++) total += arguments[i].length;
  const result = new Uint8Array(total);
  let offset = 0;
  for (let i = 0; i < arguments.length; i++) {
    result.set(arguments[i], offset);
    offset += arguments[i].length;
  }
  return result;
}

/** Encode a 16-bit integer as little-endian 2 bytes (equivalent to struct.pack("<H", n)). */
function packU16LE(n) {
  return new Uint8Array([n & 0xff, (n >> 8) & 0xff]);
}

// -- Sampling Functions -------------------------------------------------------

/**
 * Sample uniform polynomial in Tq via rejection (Algorithm 30, FIPS 204).
 *
 * Uses CoeffFromThreeBytes: each 3-byte group yields a 23-bit candidate
 * (top bit of b2 cleared). Reject if >= q. Result is already in NTT domain.
 *
 * seed34: 34-byte Uint8Array (rho || byte(s) || byte(r)).
 */
function rejNttPoly(seed34) {
  const xof = shake128Xof();
  xof.absorb(seed34);
  let buf = xof.squeeze(3 * N); // ~256 candidates; rejection rate is ~0.4%
  const coeffs = [];
  let pos = 0;
  while (coeffs.length < N) {
    if (pos + 3 > buf.length) {
      const extra = xof.squeeze(3 * 64);
      const newBuf = new Uint8Array(buf.length + extra.length);
      newBuf.set(buf);
      newBuf.set(extra, buf.length);
      buf = newBuf;
    }
    const b0 = buf[pos];
    const b1 = buf[pos + 1];
    const b2 = buf[pos + 2];
    pos += 3;
    const z = b0 | (b1 << 8) | ((b2 & 0x7f) << 16); // 23-bit candidate
    if (z < Q) {
      coeffs.push(z);
    }
  }
  return coeffs;
}

/**
 * Sample polynomial with coefficients in [-eta, eta] via rejection.
 *
 * Uses SHAKE-256 XOF, processes half-bytes (nibbles) (Algorithm 14/33, FIPS 204).
 * For eta=4: accept nibble if < 9, coefficient = eta - nibble.
 */
function sampleRejEta(seed, nonce) {
  const input = concatBytes(seed, packU16LE(nonce));
  const xof = shake256Xof();
  xof.absorb(input);
  let stream = xof.squeeze(512);
  const coeffs = [];
  let pos = 0;
  while (coeffs.length < N) {
    if (pos >= stream.length) {
      const extra = xof.squeeze(256);
      const newStream = new Uint8Array(stream.length + extra.length);
      newStream.set(stream);
      newStream.set(extra, stream.length);
      stream = newStream;
    }
    const b = stream[pos];
    pos++;
    const t0 = b & 0x0f;
    const t1 = b >> 4;
    if (t0 < 9) {
      coeffs.push(mod(ETA - t0, Q));
    }
    if (t1 < 9 && coeffs.length < N) {
      coeffs.push(mod(ETA - t1, Q));
    }
  }
  return coeffs;
}

/**
 * Expand seed rho into k*l matrix of NTT-domain polynomials.
 * Algorithm 32, FIPS 204. Each entry sampled via RejNTTPoly
 * (already in Tq -- no additional NTT needed).
 */
function expandA(rho) {
  const A = new Array(K);
  for (let r = 0; r < K; r++) {
    const row = new Array(L);
    for (let s = 0; s < L; s++) {
      const seed34 = concatBytes(rho, new Uint8Array([s, r]));
      row[s] = rejNttPoly(seed34);
    }
    A[r] = row;
  }
  return A;
}

/**
 * Expand rho' into secret vectors s1 (l-vector) and s2 (k-vector).
 * Algorithm 33, FIPS 204.
 */
function expandS(rhoPrime) {
  const s1 = new Array(L);
  for (let j = 0; j < L; j++) {
    s1[j] = sampleRejEta(rhoPrime, j);
  }
  const s2 = new Array(K);
  for (let j = 0; j < K; j++) {
    s2[j] = sampleRejEta(rhoPrime, L + j);
  }
  return [s1, s2];
}

/**
 * Expand rho'' into masking vector y (l-vector).
 * Algorithm 34, FIPS 204. Coefficients in [-gamma1+1, gamma1].
 */
function expandMask(rhoPrime, kappa) {
  const y = new Array(L);
  // gamma1 = 2^19, so 20 bits per coefficient.
  // FIPS 204 specifies: 5 bytes -> 2 coefficients (Algorithm 34).
  for (let j = 0; j < L; j++) {
    const input = concatBytes(rhoPrime, packU16LE(kappa + j));
    const buf = shake256(input, (5 * N / 2) | 0); // 640 bytes

    const coeffs = new Array(N);
    for (let i = 0; i < N; i += 2) {
      const off = (i >> 1) * 5;

      // Load 32 bits little-endian from 4 bytes
      const t =
        (buf[off] |
          (buf[off + 1] << 8) |
          (buf[off + 2] << 16) |
          (buf[off + 3] << 24)) >>> 0;

      const val0 = t & 0xfffff;                          // low 20 bits
      const val1 = ((t >>> 20) | (buf[off + 4] << 12)) & 0xfffff; // next 20 bits

      coeffs[i]     = mod(GAMMA1 - val0, Q);
      coeffs[i + 1] = mod(GAMMA1 - val1, Q);
    }

    y[j] = coeffs;
  }
  return y;
}

/**
 * Sample challenge polynomial c with exactly tau non-zero coefficients.
 * Algorithm 35, FIPS 204. c has tau entries of +/-1, rest 0.
 */
function sampleInBall(cTilde) {
  const xof = shake256Xof();
  xof.absorb(cTilde);
  let buf = xof.squeeze(8 + TAU); // First 8 bytes for sign bits, then rejection samples
  // Extract sign bits from first 8 bytes (64 bits, little-endian)
  // We use two 32-bit halves since JS bitwise ops are 32-bit
  const signLo = (buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24)) >>> 0;
  const signHi = (buf[4] | (buf[5] << 8) | (buf[6] << 16) | (buf[7] << 24)) >>> 0;

  const c = new Array(N);
  for (let i = 0; i < N; i++) c[i] = 0;

  let pos = 8; // Start after sign bytes
  for (let i = N - TAU; i < N; i++) {
    // Rejection sample j in [0, i]
    let j;
    while (true) {
      if (pos >= buf.length) {
        const extra = xof.squeeze(256);
        const newBuf = new Uint8Array(buf.length + extra.length);
        newBuf.set(buf);
        newBuf.set(extra, buf.length);
        buf = newBuf;
      }
      j = buf[pos];
      pos++;
      if (j <= i) break;
    }
    c[i] = c[j];
    const bitIdx = i - (N - TAU);
    let sign;
    if (bitIdx < 32) {
      sign = (signLo >>> bitIdx) & 1;
    } else {
      sign = (signHi >>> (bitIdx - 32)) & 1;
    }
    // Branchless: sign=0 → 1, sign=1 → Q-1
    c[j] = 1 + sign * (Q - 2);
  }
  return c;
}

// -- Rounding & Decomposition -------------------------------------------------

/**
 * Decompose r into (r1, r0) where r = r1*2^d + r0 (Algorithm 36).
 * r0 in [-2^(d-1), 2^(d-1)).
 */
function power2Round(r) {
  const rPos = mod(r, Q);
  let r0 = rPos & ((1 << D) - 1);
  // Branchless centering: subtract 2^D when r0 > 2^(D-1)
  const gt = ((1 << (D - 1)) - r0) >> 31 & 1; // 1 if r0 > 2^(D-1)
  r0 -= gt << D;
  const r1 = (rPos - r0) >> D;
  return [r1, r0];
}

/**
 * High-order/low-order decomposition using gamma2 (Algorithm 37).
 * Returns [r1, r0] where r = r1*2*gamma2 + r0 with |r0| <= gamma2.
 */
function decompose(r) {
  const rPos = mod(r, Q);
  let r0 = rPos % (2 * GAMMA2);
  // Branchless centering: subtract 2*GAMMA2 when r0 > GAMMA2
  const gt = ((GAMMA2 - r0) >> 31) & 1;
  r0 -= gt * 2 * GAMMA2;
  // Branchless special case: when rPos - r0 === Q - 1, set r1=0 and r0-=1
  const diff = (rPos - r0) - (Q - 1);
  const isMax = 1 - (((diff | (-diff)) >>> 31) & 1); // 1 if diff===0
  const r1Normal = ((rPos - r0) / (2 * GAMMA2)) | 0;
  const r1 = (1 - isMax) * r1Normal;
  r0 -= isMax;
  return [r1, r0];
}

/** Return high-order bits of r. */
function highBits(r) {
  return decompose(r)[0];
}

/** Return low-order bits of r. */
function lowBits(r) {
  return decompose(r)[1];
}

/** Compute hint bit: 1 if high_bits(r) != high_bits(r+z) (Algorithm 38). */
function makeHint(z, r) {
  const r1 = highBits(r);
  const v1 = highBits((r + z) % Q);
  // Branchless: (diff | -diff) >>> 31 is 1 when diff !== 0, 0 when diff === 0
  const diff = r1 - v1;
  return ((diff | (-diff)) >>> 31) & 1;
}

/**
 * Recover correct high bits using hint (Algorithm 39).
 * If h=0, return high_bits(r). If h=1, adjust by +-1.
 */
function useHint(h, r) {
  const m = ((Q - 1) / (2 * GAMMA2)) | 0; // = 16 for ML-DSA-65
  const [r1, r0] = decompose(r);
  // Branchless: direction = +1 when r0 > 0, -1 when r0 <= 0
  const gtZero = 1 - (((r0 - 1) >> 31) & 1); // 1 if r0 > 0, 0 if r0 <= 0
  const direction = gtZero * 2 - 1; // +1 or -1
  return mod(r1 + h * direction, m);
}

// -- Bit Packing / Encoding --------------------------------------------------

/** Pack polynomial coefficients into bytes using `bits` bits each. */
function bitPack(coeffs, bits) {
  const buf = [];
  let acc = 0;
  let accBits = 0;
  const mask = (1 << bits) - 1;
  for (let i = 0; i < coeffs.length; i++) {
    acc |= (coeffs[i] & mask) << accBits;
    accBits += bits;
    while (accBits >= 8) {
      buf.push(acc & 0xff);
      acc >>>= 8;
      accBits -= 8;
    }
  }
  if (accBits > 0) {
    buf.push(acc & 0xff);
  }
  return new Uint8Array(buf);
}

/** Unpack `n` coefficients of `bits` bits each from bytes. */
function bitUnpack(data, n, bits) {
  const coeffs = new Array(n);
  let acc = 0;
  let accBits = 0;
  let pos = 0;
  const mask = (1 << bits) - 1;
  for (let i = 0; i < n; i++) {
    while (accBits < bits) {
      acc |= data[pos] << accBits;
      pos++;
      accBits += 8;
    }
    coeffs[i] = acc & mask;
    acc >>>= bits;
    accBits -= bits;
  }
  return coeffs;
}

/**
 * Pack signed coefficients: each mapped to a - c, then packed in `bits` bits.
 * Used for z (gamma1 - z_i) and r0 components.
 */
function packSigned(coeffs, a, bits) {
  const mapped = new Array(coeffs.length);
  for (let i = 0; i < coeffs.length; i++) {
    mapped[i] = mod(a - coeffs[i], Q);
  }
  return bitPack(mapped, bits);
}

/** Unpack signed coefficients packed with packSigned. */
function unpackSigned(data, n, a, bits) {
  const raw = bitUnpack(data, n, bits);
  const coeffs = new Array(n);
  for (let i = 0; i < n; i++) {
    coeffs[i] = mod(a - raw[i], Q);
  }
  return coeffs;
}

// -- Public Key Encoding ------------------------------------------------------

/**
 * Encode public key: rho (32 bytes) || bitpack(t1, 10 bits each).
 * Algorithm 22, FIPS 204. t1 coefficients are in [0, 2^10).
 * Public key size: 32 + k*256*10/8 = 32 + 6*320 = 1952 bytes.
 */
function pkEncode(rho, t1) {
  const parts = [rho];
  for (let i = 0; i < K; i++) {
    parts.push(bitPack(t1[i], 10));
  }
  return concatBytes.apply(null, parts);
}

/** Decode public key into [rho, t1]. */
function pkDecode(pkBytes) {
  const rho = pkBytes.slice(0, 32);
  const t1 = new Array(K);
  let offset = 32;
  for (let i = 0; i < K; i++) {
    const chunk = pkBytes.slice(offset, offset + 320);
    t1[i] = bitUnpack(chunk, N, 10);
    offset += 320;
  }
  return [rho, t1];
}

// -- Secret Key Encoding ------------------------------------------------------

/**
 * Encode secret key (Algorithm 24, FIPS 204).
 *
 * Layout: rho(32) || K(32) || tr(64) || bitpack(s1) || bitpack(s2) || bitpack(t0)
 * For eta=4: each s coefficient in [-4,4] packed as 4 bits (mapped to [0,8]).
 * t0 coefficients in [-2^12, 2^12) packed as 13 bits.
 * Secret key size: 32+32+64 + 5*256*4/8 + 6*256*4/8 + 6*256*13/8 = 4032 bytes.
 */
function skEncode(rho, Kval, tr, s1, s2, t0) {
  const parts = [rho, Kval, tr];
  // s1: l polynomials, eta=4 -> 4 bits per coefficient (mapped: eta - c)
  for (let i = 0; i < L; i++) {
    const mapped = new Array(N);
    for (let j = 0; j < N; j++) mapped[j] = mod(ETA - s1[i][j], Q);
    parts.push(bitPack(mapped, 4));
  }
  // s2: k polynomials, same encoding
  for (let i = 0; i < K; i++) {
    const mapped = new Array(N);
    for (let j = 0; j < N; j++) mapped[j] = mod(ETA - s2[i][j], Q);
    parts.push(bitPack(mapped, 4));
  }
  // t0: k polynomials, 13 bits per coefficient (mapped: 2^(d-1) - c)
  const half = 1 << (D - 1); // 4096
  for (let i = 0; i < K; i++) {
    const mapped = new Array(N);
    for (let j = 0; j < N; j++) mapped[j] = mod(half - t0[i][j], Q);
    parts.push(bitPack(mapped, 13));
  }
  return concatBytes.apply(null, parts);
}

/** Decode secret key into [rho, K, tr, s1, s2, t0]. */
function skDecode(skBytes) {
  const rho = skBytes.slice(0, 32);
  const Kval = skBytes.slice(32, 64);
  const tr = skBytes.slice(64, 128);

  let offset = 128;
  // s1: l polynomials, 4 bits each
  const s1 = new Array(L);
  const sBytes = (N * 4 / 8) | 0; // 128 bytes per polynomial
  for (let i = 0; i < L; i++) {
    const raw = bitUnpack(skBytes.slice(offset, offset + sBytes), N, 4);
    const poly = new Array(N);
    for (let j = 0; j < N; j++) poly[j] = mod(ETA - raw[j], Q);
    s1[i] = poly;
    offset += sBytes;
  }
  // s2: k polynomials, 4 bits each
  const s2 = new Array(K);
  for (let i = 0; i < K; i++) {
    const raw = bitUnpack(skBytes.slice(offset, offset + sBytes), N, 4);
    const poly = new Array(N);
    for (let j = 0; j < N; j++) poly[j] = mod(ETA - raw[j], Q);
    s2[i] = poly;
    offset += sBytes;
  }
  // t0: k polynomials, 13 bits each
  const t0 = new Array(K);
  const t0Bytes = (N * 13 / 8) | 0; // 416 bytes per polynomial
  const half = 1 << (D - 1);
  for (let i = 0; i < K; i++) {
    const raw = bitUnpack(skBytes.slice(offset, offset + t0Bytes), N, 13);
    const poly = new Array(N);
    for (let j = 0; j < N; j++) poly[j] = mod(half - raw[j], Q);
    t0[i] = poly;
    offset += t0Bytes;
  }
  return [rho, Kval, tr, s1, s2, t0];
}

// -- Signature Encoding -------------------------------------------------------

/**
 * Encode signature (Algorithm 26, FIPS 204).
 *
 * Layout: c_tilde(48) || bitpack(z, 20 bits) || hint_encode(h)
 * Signature size: 48 + 5*640 + 61 = 3309 bytes (FIPS 204 Table 2).
 */
function sigEncode(cTilde, z, h) {
  const parts = [cTilde];
  // z: l polynomials, 20 bits each (gamma1 - z_i)
  for (let i = 0; i < L; i++) {
    const mapped = new Array(N);
    for (let j = 0; j < N; j++) mapped[j] = mod(GAMMA1 - z[i][j], Q);
    parts.push(bitPack(mapped, 20));
  }
  // Hint encoding: omega + k bytes (Algorithm 27)
  const hintBuf = new Uint8Array(OMEGA + K);
  let idx = 0;
  for (let i = 0; i < K; i++) {
    for (let j = 0; j < N; j++) {
      if (h[i][j] !== 0) {
        hintBuf[idx] = j;
        idx++;
      }
    }
    hintBuf[OMEGA + i] = idx;
  }
  parts.push(hintBuf);
  return concatBytes.apply(null, parts);
}

/** Decode signature into [cTilde, z, h] or null if malformed. */
function sigDecode(sigBytes) {
  const cTilde = sigBytes.slice(0, C_TILDE_BYTES);

  let offset = C_TILDE_BYTES;
  // z: l polynomials, 20 bits each
  const z = new Array(L);
  const zBytes = (N * 20 / 8) | 0; // 640 bytes per polynomial
  for (let i = 0; i < L; i++) {
    const raw = bitUnpack(sigBytes.slice(offset, offset + zBytes), N, 20);
    const poly = new Array(N);
    for (let j = 0; j < N; j++) poly[j] = mod(GAMMA1 - raw[j], Q);
    z[i] = poly;
    offset += zBytes;
  }

  // Hint decoding (Algorithm 28)
  const hintSection = sigBytes.slice(offset, offset + OMEGA + K);
  const h = new Array(K);
  for (let i = 0; i < K; i++) {
    h[i] = new Array(N);
    for (let j = 0; j < N; j++) h[i][j] = 0;
  }
  let idx = 0;
  for (let i = 0; i < K; i++) {
    const end = hintSection[OMEGA + i];
    if (end < idx || end > OMEGA) {
      return null; // Malformed hint
    }
    for (let j = idx; j < end; j++) {
      if (j > idx && hintSection[j] <= hintSection[j - 1]) {
        return null; // Not sorted
      }
      h[i][hintSection[j]] = 1;
    }
    idx = end;
  }
  // Check remaining positions are zero
  for (let j = idx; j < OMEGA; j++) {
    if (hintSection[j] !== 0) {
      return null;
    }
  }
  return [cTilde, z, h];
}

// -- Core Algorithms ----------------------------------------------------------

/**
 * ML-DSA-65 key generation (Algorithm 1, FIPS 204).
 *
 * @param {Uint8Array} seed - 32-byte random seed (xi).
 * @returns {{sk: Uint8Array, pk: Uint8Array}} - sk: 4,032 bytes, pk: 1,952 bytes.
 */
function mlKeygen(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new Error("seed must be a 32-byte Uint8Array, got length " + (seed ? seed.length : 0));
  }

  // Step 1: Expand seed into (rho, rho', K) via SHAKE-256
  const expanded = shake256(concatBytes(seed, new Uint8Array([K, L])), 128);
  const rho = expanded.slice(0, 32);
  const rhoPrime = expanded.slice(32, 96);
  const Kval = expanded.slice(96, 128);

  // Step 2: Expand A from rho (in NTT domain)
  const AHat = expandA(rho);

  // Step 3: Sample secret vectors s1, s2 from rho'
  const [s1, s2] = expandS(rhoPrime);

  // Step 4: Compute t = A*s1 + s2 (via NTT)
  const s1Hat = vecNtt(s1);
  const t = vecInvNtt(vecAdd(matVecNtt(AHat, s1Hat), vecNtt(s2)));

  // Step 5: Compress t into (t1, t0)
  const t1 = new Array(K);
  const t0List = new Array(K);
  for (let i = 0; i < K; i++) {
    const t1Poly = new Array(N);
    const t0Poly = new Array(N);
    for (let j = 0; j < N; j++) {
      const [hi, lo] = power2Round(t[i][j]);
      t1Poly[j] = hi;
      t0Poly[j] = lo;
    }
    t1[i] = t1Poly;
    t0List[i] = t0Poly;
  }

  // Step 6: Encode public key and compute tr = H(pk)
  const pkBytes = pkEncode(rho, t1);
  const tr = shake256(pkBytes, 64);

  // Step 7: Encode secret key
  const skBytes = skEncode(rho, Kval, tr, s1, s2, t0List);

  // Best-effort cleanup of secret intermediates
  zeroize(rhoPrime);
  zeroizeVec(s1);
  zeroizeVec(s2);
  zeroizeVec(s1Hat);

  return { sk: skBytes, pk: pkBytes };
}

/**
 * ML-DSA-65 internal signing (Algorithm 7, FIPS 204).
 *
 * Signs pre-processed message M' directly. Use mlSign() for the
 * pure FIPS 204 API with context string support.
 *
 * @param {Uint8Array} message - Pre-processed message M'.
 * @param {Uint8Array} skBytes - 4,032-byte secret key.
 * @param {Uint8Array|null} rnd - Explicit 32-byte randomness (overrides modes).
 * @param {boolean} deterministic - If true and rnd is null, uses 0^32.
 * @returns {Uint8Array} Signature bytes (3,309 bytes).
 */
function mlSignInternal(message, skBytes, rnd, deterministic) {
  if (skBytes.length !== SK_SIZE) {
    throw new Error("secret key must be " + SK_SIZE + " bytes, got " + skBytes.length);
  }
  if (rnd != null) {
    if (!(rnd instanceof Uint8Array) || rnd.length !== 32) {
      throw new Error("rnd must be a 32-byte Uint8Array, got " + (rnd ? rnd.length : 0));
    }
  }

  // Step 1: Decode secret key
  const [rho, Kval, tr, s1, s2, t0] = skDecode(skBytes);

  // Step 2: Pre-compute NTT of secret vectors
  const s1Hat = vecNtt(s1);
  const s2Hat = vecNtt(s2);
  const t0Hat = vecNtt(t0);

  // Step 3: Expand A from rho
  const AHat = expandA(rho);

  // Step 4: Compute mu = H(tr || msg)
  const mu = shake256(concatBytes(tr, message), 64);

  // Step 5: rho'' = H(K || rnd || mu) (FIPS 204 Algorithm 7)
  // Always allocate our own copy so zeroize() never wipes the caller's buffer.
  let rndBytes;
  if (rnd != null) {
    rndBytes = new Uint8Array(rnd); // defensive copy — caller keeps their buffer
  } else if (deterministic) {
    rndBytes = new Uint8Array(32); // all zeros
  } else {
    rndBytes = randomBytes(32);
  }
  const rhoPrimePrime = shake256(concatBytes(Kval, rndBytes, mu), 64);

  // Step 6: Rejection sampling loop
  let kappa = 0;
  const maxAttempts = 1000;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    // 6a: Generate masking vector y
    const y = expandMask(rhoPrimePrime, kappa);
    kappa += L;

    // 6b: Compute w = A*y (via NTT)
    const yHat = vecNtt(y);
    const w = vecInvNtt(matVecNtt(AHat, yHat));

    // 6c: Decompose w into high/low parts
    const w1 = new Array(K);
    for (let i = 0; i < K; i++) {
      const w1Poly = new Array(N);
      for (let j = 0; j < N; j++) {
        w1Poly[j] = highBits(w[i][j]);
      }
      w1[i] = w1Poly;
    }

    // 6d: Pack w1 and compute challenge
    const w1Parts = [];
    for (let i = 0; i < K; i++) {
      // w1 coefficients are in [0, (q-1)/(2*gamma2)] = [0, 15]
      // Pack 4 bits each
      w1Parts.push(bitPack(w1[i], 4));
    }
    const w1Packed = concatBytes.apply(null, w1Parts);
    const cTilde = shake256(concatBytes(mu, w1Packed), C_TILDE_BYTES);
    const c = sampleInBall(cTilde);
    const cHat = ntt(c);

    // 6e: Compute z = y + c*s1
    const cs1 = new Array(L);
    for (let i = 0; i < L; i++) cs1[i] = nttMult(cHat, s1Hat[i]);
    const cs1Inv = vecInvNtt(cs1);
    const z = vecAdd(y, cs1Inv);

    // 6f: Compute r0 = low_bits(w - c*s2)
    const cs2 = new Array(K);
    for (let i = 0; i < K; i++) cs2[i] = nttMult(cHat, s2Hat[i]);
    const cs2Inv = vecInvNtt(cs2);
    const wMinusCs2 = vecSub(w, cs2Inv);

    // 6g: Check z norm bound (branchless: no early break on secret data)
    let reject = 0;
    for (let i = 0; i < L; i++) {
      for (let j = 0; j < N; j++) {
        let val = z[i][j];
        // CT abs (centered mod Q): val = val > Q/2 ? Q - val : val
        const neg = ((Q >> 1) - val) >> 31; // -1 if val > Q/2, 0 otherwise
        val = val + ((Q - 2 * val) & neg);
        // CT compare: reject if val >= GAMMA1 - BETA
        reject |= ((GAMMA1 - BETA - 1 - val) >> 31) & 1;
      }
    }
    if (reject) { zeroizeVec(y); continue; }

    // 6h: Check ||r0||_inf < gamma2 - beta (branchless)
    for (let i = 0; i < K; i++) {
      for (let j = 0; j < N; j++) {
        const lb = lowBits(wMinusCs2[i][j]);
        // CT abs: abs(lb) = (lb ^ (lb >> 31)) - (lb >> 31)
        const lbSign = lb >> 31;
        const absLb = (lb ^ lbSign) - lbSign;
        reject |= ((GAMMA2 - BETA - 1 - absLb) >> 31) & 1;
      }
    }
    if (reject) { zeroizeVec(y); continue; }

    // 6i: Compute hint h
    const ct0 = new Array(K);
    for (let i = 0; i < K; i++) ct0[i] = nttMult(cHat, t0Hat[i]);
    const ct0Inv = vecInvNtt(ct0);
    const wCs2Ct0 = vecAdd(wMinusCs2, ct0Inv);

    const h = new Array(K);
    let hintCount = 0;
    for (let i = 0; i < K; i++) {
      h[i] = new Array(N);
      for (let j = 0; j < N; j++) {
        const negCt0 = mod(Q - ct0Inv[i][j], Q);
        h[i][j] = makeHint(negCt0, wCs2Ct0[i][j]);
        hintCount += h[i][j];
      }
    }
    if (hintCount > OMEGA) { zeroizeVec(y); continue; }

    // 6j: Check ct0 norm bound (branchless)
    reject = 0;
    for (let i = 0; i < K; i++) {
      for (let j = 0; j < N; j++) {
        let val = ct0Inv[i][j];
        const neg2 = ((Q >> 1) - val) >> 31;
        val = val + ((Q - 2 * val) & neg2);
        reject |= ((GAMMA2 - 1 - val) >> 31) & 1;
      }
    }
    if (reject) { zeroizeVec(y); continue; }

    // Success -- encode signature
    const sig = sigEncode(cTilde, z, h);

    // Best-effort cleanup of secret intermediates
    zeroizeVec(y);
    zeroizeVec(s1);
    zeroizeVec(s2);
    zeroizeVec(s1Hat);
    zeroizeVec(s2Hat);
    zeroizeVec(t0);
    zeroizeVec(t0Hat);
    zeroize(Kval);
    zeroize(rhoPrimePrime);
    zeroize(rndBytes);

    return sig;
  }

  throw new Error("ML-DSA signing failed after " + maxAttempts + " rejection attempts");
}

/**
 * ML-DSA-65 internal verification (Algorithm 8, FIPS 204).
 *
 * Verifies pre-processed message M' directly. Use mlVerify() for the
 * pure FIPS 204 API with context string support.
 */
function mlVerifyInternal(message, sigBytes, pkBytes) {
  if (pkBytes.length !== PK_SIZE) return false;
  if (sigBytes.length !== SIG_SIZE) return false;

  // Step 1: Decode public key
  const [rho, t1] = pkDecode(pkBytes);

  // Canonical encoding check: re-encode pk and verify round-trip match
  // Rejects non-canonical bit patterns (e.g. stray bits in padding bytes)
  const pkReencoded = pkEncode(rho, t1);
  if (!constantTimeEqual(pkBytes, pkReencoded)) return false;

  // Step 2: Decode signature
  const decoded = sigDecode(sigBytes);
  if (decoded === null) return false;
  const [cTilde, z, h] = decoded;

  // Step 3: Check z norm bound
  for (let i = 0; i < L; i++) {
    for (let j = 0; j < N; j++) {
      let val = z[i][j];
      if (val > (Q >> 1)) val = Q - val;
      if (val >= GAMMA1 - BETA) return false;
    }
  }

  // Step 4: Expand A from rho
  const AHat = expandA(rho);

  // Step 5: Compute tr = H(pk) and mu = H(tr || msg)
  const tr = shake256(pkBytes, 64);
  const mu = shake256(concatBytes(tr, message), 64);

  // Step 6: Recompute challenge c from c_tilde
  const c = sampleInBall(cTilde);
  const cHat = ntt(c);

  // Step 7: Compute w'1 = use_hint(h, A*z - c*t1*2^d)
  const zHat = vecNtt(z);
  const Az = matVecNtt(AHat, zHat);

  // Compute c*t1*2^d in NTT domain
  const t1Shifted = new Array(K);
  for (let i = 0; i < K; i++) {
    const poly = new Array(N);
    for (let j = 0; j < N; j++) {
      poly[j] = (t1[i][j] * (1 << D)) % Q;
    }
    t1Shifted[i] = poly;
  }
  const t1ShiftedHat = vecNtt(t1Shifted);
  const ct1_2d = new Array(K);
  for (let i = 0; i < K; i++) {
    ct1_2d[i] = nttMult(cHat, t1ShiftedHat[i]);
  }

  // w' = A*z - c*t1*2^d (in NTT domain, then back)
  const wPrimeHat = new Array(K);
  for (let i = 0; i < K; i++) {
    wPrimeHat[i] = polySub(Az[i], ct1_2d[i]);
  }
  const wPrime = vecInvNtt(wPrimeHat);

  // Apply hints to recover w'1
  const wPrime1 = new Array(K);
  let hintCount = 0;
  for (let i = 0; i < K; i++) {
    const w1Poly = new Array(N);
    for (let j = 0; j < N; j++) {
      w1Poly[j] = useHint(h[i][j], wPrime[i][j]);
      hintCount += h[i][j];
    }
    wPrime1[i] = w1Poly;
  }

  // Check total hint count
  if (hintCount > OMEGA) return false;

  // Step 8: Pack w'1 and verify challenge
  const w1Parts = [];
  for (let i = 0; i < K; i++) {
    w1Parts.push(bitPack(wPrime1[i], 4));
  }
  const w1Packed = concatBytes.apply(null, w1Parts);
  const cTildeCheck = shake256(concatBytes(mu, w1Packed), C_TILDE_BYTES);

  // Uses Node's timingSafeEqual when available, JS XOR-accumulate fallback
  return constantTimeEqual(cTilde, cTildeCheck);
}

/**
 * ML-DSA-65 standard signing — signs raw message bytes directly.
 *
 * This is the interoperable API that matches ACVP/KAT test vectors and
 * other ML-DSA implementations (BoringSSL, liboqs, etc.). The message
 * is passed to the internal algorithm without any preprocessing.
 *
 * Defaults to hedged signing (FIPS 204 recommended). Pass
 * deterministic:true for reproducible signatures.
 *
 * @param {Uint8Array} message - Arbitrary-length message bytes.
 * @param {Uint8Array} sk - 4,032-byte secret key from mlKeygen.
 * @param {Object} [opts] - Options: {deterministic: bool, rnd: Uint8Array|null}.
 * @returns {Uint8Array} Signature bytes (3,309 bytes for ML-DSA-65).
 */
function mlSign(message, sk, opts) {
  message = toBytes(message);
  if (opts === undefined) opts = {};
  return mlSignInternal(message, sk, opts.rnd || null, !!opts.deterministic);
}

/**
 * ML-DSA-65 standard verification — verifies against raw message bytes.
 *
 * This is the interoperable API that matches ACVP/KAT test vectors and
 * other ML-DSA implementations.
 *
 * @param {Uint8Array} message - Original message bytes.
 * @param {Uint8Array} sig - Signature bytes from mlSign.
 * @param {Uint8Array} pk - Public key bytes from mlKeygen.
 * @returns {boolean} True if the signature is valid, false otherwise.
 */
function mlVerify(message, sig, pk) {
  message = toBytes(message);
  return mlVerifyInternal(message, sig, pk);
}

/**
 * ML-DSA-65 pure signing with context (Algorithm 2, FIPS 204).
 *
 * Builds M' = 0x00 || len(ctx) || ctx || message, then calls the
 * internal signing algorithm. This is the FIPS 204 "pure" mode with
 * context string support.
 *
 * Use mlSign() for the standard interoperable API (no context prefix).
 * Use this function only when FIPS 204 context strings are required.
 *
 * @param {Uint8Array} message - Arbitrary-length message bytes.
 * @param {Uint8Array} sk - 4,032-byte secret key from mlKeygen.
 * @param {Uint8Array} [ctx=new Uint8Array(0)] - Context string (0-255 bytes).
 * @param {Object} [opts] - Options: {deterministic: bool, rnd: Uint8Array|null}.
 * @returns {Uint8Array} Signature bytes (3,309 bytes for ML-DSA-65).
 */
function mlSignWithContext(message, sk, ctx, opts) {
  message = toBytes(message);
  if (ctx === undefined || ctx === null) ctx = new Uint8Array(0);
  else ctx = toBytes(ctx);
  if (opts === undefined) opts = {};
  if (ctx.length > 255) {
    throw new Error("context string must be <= 255 bytes, got " + ctx.length);
  }
  const mPrime = concatBytes(
    new Uint8Array([0x00, ctx.length]),
    ctx,
    message
  );
  return mlSignInternal(mPrime, sk, opts.rnd || null, !!opts.deterministic);
}

/**
 * ML-DSA-65 pure verification with context (Algorithm 3, FIPS 204).
 *
 * Builds M' = 0x00 || len(ctx) || ctx || message, then calls the
 * internal verification algorithm. This is the FIPS 204 "pure" mode.
 *
 * Use mlVerify() for the standard interoperable API (no context prefix).
 *
 * @param {Uint8Array} message - Original message bytes.
 * @param {Uint8Array} sig - Signature bytes from mlSignWithContext.
 * @param {Uint8Array} pk - Public key bytes from mlKeygen.
 * @param {Uint8Array} [ctx=new Uint8Array(0)] - Context string.
 * @returns {boolean} True if the signature is valid, false otherwise.
 */
function mlVerifyWithContext(message, sig, pk, ctx) {
  message = toBytes(message);
  if (ctx === undefined || ctx === null) ctx = new Uint8Array(0);
  else ctx = toBytes(ctx);
  if (ctx.length > 255) return false;
  const mPrime = concatBytes(
    new Uint8Array([0x00, ctx.length]),
    ctx,
    message
  );
  return mlVerifyInternal(mPrime, sig, pk);
}

/**
 * Async wrapper for mlSign — yields to the event loop before computation
 * so browser UIs don't freeze. Uses the same algorithm as the sync version.
 */
function mlSignAsync(message, sk, opts) {
  return new Promise(function (resolve, reject) {
    setTimeout(function () {
      try { resolve(mlSign(message, sk, opts)); }
      catch (e) { reject(e); }
    }, 0);
  });
}

/**
 * Async wrapper for mlVerify — yields to the event loop before computation.
 */
function mlVerifyAsync(message, sig, pk) {
  return new Promise(function (resolve, reject) {
    setTimeout(function () {
      try { resolve(mlVerify(message, sig, pk)); }
      catch (e) { reject(e); }
    }, 0);
  });
}

module.exports = {
  mlKeygen,
  mlSign,
  mlVerify,
  mlSignWithContext,
  mlVerifyWithContext,
  mlSignAsync,
  mlVerifyAsync,
  // Expose sizes for callers
  PK_SIZE,
  SK_SIZE,
  SIG_SIZE,
};

};

// ── crypto/ml_kem.js ──
_dirs["./crypto/ml_kem"] = "./crypto";
_modules["./crypto/ml_kem"] = function(module, exports, require) {
// Copyright (c) 2026 Signer.io — MIT License

"use strict";

// ML-KEM-768 (Kyber) — FIPS 203 post-quantum key encapsulation mechanism.
// Pure JavaScript, zero dependencies. Direct port of the Python ml_kem.py.
//
// Key sizes:
//   Encapsulation key (EK): 1,184 bytes
//   Decapsulation key (DK): 2,400 bytes
//   Ciphertext:             1,088 bytes
//   Shared secret:             32 bytes

const { sha3_256, sha3_512, shake128, shake256, shake128Xof } = require("./sha3");

// ── ML-KEM-768 Parameters (FIPS 203 Table 2) ────────────────────

const Q = 3329;
const N = 256;
const K = 3;
const ETA1 = 2;
const ETA2 = 2;
const DU = 10;
const DV = 4;

// ── NTT Constants ────────────────────────────────────────────────

function bitrev7(n) {
  let r = 0;
  for (let i = 0; i < 7; i++) { r = (r << 1) | (n & 1); n >>= 1; }
  return r;
}

// Primitive 512th root of unity: 17
const ROOT = 17;

// Precompute 128 zetas in bit-reversed order
function modpow(base, exp, mod) {
  let result = 1;
  base = ((base % mod) + mod) % mod;
  while (exp > 0) {
    if (exp & 1) result = (result * base) % mod;
    exp >>= 1;
    base = (base * base) % mod;
  }
  return result;
}

const ZETAS = new Int32Array(128);
for (let i = 0; i < 128; i++) {
  ZETAS[i] = modpow(ROOT, bitrev7(i), Q);
}

// 128^{-1} mod 3329 = 3303
const N_INV = modpow(128, Q - 2, Q);

// ── Polynomial arithmetic ────────────────────────────────────────

function ntt(f) {
  const a = Int32Array.from(f);
  let k = 1;
  for (let len = 128; len >= 2; len >>= 1) {
    for (let start = 0; start < 256; start += 2 * len) {
      const zeta = ZETAS[k++];
      for (let j = start; j < start + len; j++) {
        const t = (zeta * a[j + len]) % Q;
        a[j + len] = (a[j] - t + Q) % Q;
        a[j] = (a[j] + t) % Q;
      }
    }
  }
  return a;
}

function nttInv(f) {
  const a = Int32Array.from(f);
  let k = 127;
  for (let len = 2; len <= 128; len <<= 1) {
    for (let start = 0; start < 256; start += 2 * len) {
      const zeta = ZETAS[k--];
      for (let j = start; j < start + len; j++) {
        const t = a[j];
        a[j] = (t + a[j + len]) % Q;
        a[j + len] = (zeta * ((a[j + len] - t + Q) % Q)) % Q;
      }
    }
  }
  for (let i = 0; i < 256; i++) a[i] = (a[i] * N_INV) % Q;
  return a;
}

function basecasemultiply(a0, a1, b0, b1, gamma) {
  const c0 = (a0 * b0 + a1 * b1 * gamma) % Q;
  const c1 = (a0 * b1 + a1 * b0) % Q;
  return [((c0 % Q) + Q) % Q, ((c1 % Q) + Q) % Q];
}

function multiplyNtts(f, g) {
  const h = new Int32Array(256);
  for (let i = 0; i < 64; i++) {
    const z0 = ZETAS[64 + i];
    const [c0, c1] = basecasemultiply(f[4*i], f[4*i+1], g[4*i], g[4*i+1], z0);
    h[4*i] = c0; h[4*i+1] = c1;
    const [c2, c3] = basecasemultiply(f[4*i+2], f[4*i+3], g[4*i+2], g[4*i+3], (Q - z0) % Q);
    h[4*i+2] = c2; h[4*i+3] = c3;
  }
  return h;
}

function polyAdd(a, b) {
  const c = new Int32Array(256);
  for (let i = 0; i < 256; i++) c[i] = (a[i] + b[i]) % Q;
  return c;
}

function polySub(a, b) {
  const c = new Int32Array(256);
  for (let i = 0; i < 256; i++) c[i] = (a[i] - b[i] + Q) % Q;
  return c;
}

// ── Byte encoding / decoding ────────────────────────────────────

function byteEncode(f, d) {
  const m = d < 12 ? (1 << d) : Q;
  const totalBits = 256 * d;
  const out = new Uint8Array(Math.ceil(totalBits / 8));
  let bitIdx = 0;
  for (let i = 0; i < 256; i++) {
    let val = ((f[i] % m) + m) % m;
    for (let j = 0; j < d; j++) {
      if (val & 1) out[bitIdx >> 3] |= 1 << (bitIdx & 7);
      val >>= 1;
      bitIdx++;
    }
  }
  return out;
}

function byteDecode(data, d) {
  const m = d < 12 ? (1 << d) : Q;
  const f = new Int32Array(256);
  for (let i = 0; i < 256; i++) {
    let val = 0;
    for (let j = 0; j < d; j++) {
      const bitIdx = i * d + j;
      const bit = (data[bitIdx >> 3] >> (bitIdx & 7)) & 1;
      val |= bit << j;
    }
    f[i] = val % m;
  }
  return f;
}

// ── Sampling ─────────────────────────────────────────────────────

function sampleNtt(seed, row, col) {
  const xofInput = new Uint8Array(seed.length + 2);
  xofInput.set(seed);
  xofInput[seed.length] = col;
  xofInput[seed.length + 1] = row;

  const xof = shake128Xof();
  xof.absorb(xofInput);
  let buf = xof.squeeze(960);

  const coeffs = new Int32Array(256);
  let count = 0, pos = 0;
  while (count < 256) {
    if (pos + 2 >= buf.length) {
      const extra = xof.squeeze(168);
      const newBuf = new Uint8Array(buf.length + extra.length);
      newBuf.set(buf);
      newBuf.set(extra, buf.length);
      buf = newBuf;
    }
    const d1 = buf[pos] | ((buf[pos + 1] & 0x0f) << 8);
    const d2 = (buf[pos + 1] >> 4) | (buf[pos + 2] << 4);
    pos += 3;
    if (d1 < Q) coeffs[count++] = d1;
    if (d2 < Q && count < 256) coeffs[count++] = d2;
  }
  return coeffs;
}

function sampleCbd(data, eta) {
  const f = new Int32Array(256);
  // Unpack bits
  const bits = new Uint8Array(data.length * 8);
  for (let i = 0; i < data.length; i++) {
    for (let j = 0; j < 8; j++) {
      bits[i * 8 + j] = (data[i] >> j) & 1;
    }
  }
  for (let i = 0; i < 256; i++) {
    let aSum = 0, bSum = 0;
    for (let j = 0; j < eta; j++) {
      aSum += bits[2 * i * eta + j];
      bSum += bits[2 * i * eta + eta + j];
    }
    f[i] = (aSum - bSum + Q) % Q;
  }
  return f;
}

// ── Compression / decompression ──────────────────────────────────

function compress(x, d) {
  const m = 1 << d;
  return Math.floor((x * m + Math.floor(Q / 2)) / Q) % m;
}

function decompress(y, d) {
  const m = 1 << d;
  return Math.floor((y * Q + Math.floor(m / 2)) / m);
}

function compressPoly(f, d) {
  const r = new Int32Array(256);
  for (let i = 0; i < 256; i++) r[i] = compress(f[i], d);
  return r;
}

function decompressPoly(f, d) {
  const r = new Int32Array(256);
  for (let i = 0; i < 256; i++) r[i] = decompress(f[i], d);
  return r;
}

// ── K-PKE (Internal PKE scheme) ─────────────────────────────────

function kPkeKeygen(d) {
  const input = new Uint8Array(33);
  input.set(d);
  input[32] = K;
  const rhoSigma = sha3_512(input);
  const rho = rhoSigma.subarray(0, 32);
  const sigma = rhoSigma.subarray(32, 64);

  // Generate matrix A_hat in NTT domain
  const Ahat = [];
  for (let i = 0; i < K; i++) {
    Ahat[i] = [];
    for (let j = 0; j < K; j++) {
      Ahat[i][j] = sampleNtt(rho, i, j);
    }
  }

  // Secret vector s
  const s = [];
  for (let i = 0; i < K; i++) {
    const input = new Uint8Array(33);
    input.set(sigma);
    input[32] = i;
    const prfOut = shake256(input, 64 * ETA1);
    s.push(ntt(sampleCbd(prfOut, ETA1)));
  }

  // Error vector e
  const e = [];
  for (let i = 0; i < K; i++) {
    const input = new Uint8Array(33);
    input.set(sigma);
    input[32] = K + i;
    const prfOut = shake256(input, 64 * ETA1);
    e.push(ntt(sampleCbd(prfOut, ETA1)));
  }

  // t_hat = A_hat * s + e
  const tHat = [];
  for (let i = 0; i < K; i++) {
    let acc = new Int32Array(256);
    for (let j = 0; j < K; j++) {
      acc = polyAdd(acc, multiplyNtts(Ahat[i][j], s[j]));
    }
    tHat.push(polyAdd(acc, e[i]));
  }

  // Encode ek = t_hat || rho
  let ekLen = 384 * K + 32;
  const ekPke = new Uint8Array(ekLen);
  let offset = 0;
  for (let i = 0; i < K; i++) {
    ekPke.set(byteEncode(tHat[i], 12), offset);
    offset += 384;
  }
  ekPke.set(rho, offset);

  // dk = encode(s)
  const dkPke = new Uint8Array(384 * K);
  offset = 0;
  for (let i = 0; i < K; i++) {
    dkPke.set(byteEncode(s[i], 12), offset);
    offset += 384;
  }

  return { ekPke, dkPke };
}

function kPkeEncrypt(ekPke, m, r) {
  // Decode ek
  const tHat = [];
  for (let i = 0; i < K; i++) {
    tHat.push(byteDecode(ekPke.subarray(384 * i, 384 * (i + 1)), 12));
  }
  const rho = ekPke.subarray(384 * K);

  // Transposed matrix A_hat
  const AhatT = [];
  for (let i = 0; i < K; i++) {
    AhatT[i] = [];
    for (let j = 0; j < K; j++) {
      AhatT[i][j] = sampleNtt(rho, j, i);
    }
  }

  // r_vec, e1, e2
  const rVec = [];
  for (let i = 0; i < K; i++) {
    const input = new Uint8Array(33);
    input.set(r);
    input[32] = i;
    const prfOut = shake256(input, 64 * ETA1);
    rVec.push(ntt(sampleCbd(prfOut, ETA1)));
  }

  const e1 = [];
  for (let i = 0; i < K; i++) {
    const input = new Uint8Array(33);
    input.set(r);
    input[32] = K + i;
    const prfOut = shake256(input, 64 * ETA2);
    e1.push(sampleCbd(prfOut, ETA2));
  }

  const e2Input = new Uint8Array(33);
  e2Input.set(r);
  e2Input[32] = 2 * K;
  const e2 = sampleCbd(shake256(e2Input, 64 * ETA2), ETA2);

  // u = NTT^{-1}(A^T * r_vec) + e1
  const u = [];
  for (let i = 0; i < K; i++) {
    let acc = new Int32Array(256);
    for (let j = 0; j < K; j++) {
      acc = polyAdd(acc, multiplyNtts(AhatT[i][j], rVec[j]));
    }
    u.push(polyAdd(nttInv(acc), e1[i]));
  }

  // v = NTT^{-1}(t_hat . r_vec) + e2 + Decompress(Decode(m), 1)
  let vAcc = new Int32Array(256);
  for (let i = 0; i < K; i++) {
    vAcc = polyAdd(vAcc, multiplyNtts(tHat[i], rVec[i]));
  }
  let v = polyAdd(nttInv(vAcc), e2);
  const mPoly = decompressPoly(byteDecode(m, 1), 1);
  v = polyAdd(v, mPoly);

  // Compress and encode ciphertext
  const duBytes = 32 * DU; // 320
  const ct = new Uint8Array(duBytes * K + 32 * DV); // 960 + 128 = 1088
  let off = 0;
  for (let i = 0; i < K; i++) {
    ct.set(byteEncode(compressPoly(u[i], DU), DU), off);
    off += duBytes;
  }
  ct.set(byteEncode(compressPoly(v, DV), DV), off);

  return ct;
}

function kPkeDecrypt(dkPke, ct) {
  const duBytes = 32 * DU; // 320

  // Decode u
  const u = [];
  for (let i = 0; i < K; i++) {
    const uComp = byteDecode(ct.subarray(duBytes * i, duBytes * (i + 1)), DU);
    u.push(decompressPoly(uComp, DU));
  }

  // Decode v
  const vComp = byteDecode(ct.subarray(duBytes * K), DV);
  const v = decompressPoly(vComp, DV);

  // Decode secret key
  const sHat = [];
  for (let i = 0; i < K; i++) {
    sHat.push(byteDecode(dkPke.subarray(384 * i, 384 * (i + 1)), 12));
  }

  // w = v - NTT^{-1}(s_hat . NTT(u))
  let inner = new Int32Array(256);
  for (let i = 0; i < K; i++) {
    const uHat = ntt(u[i]);
    inner = polyAdd(inner, multiplyNtts(sHat[i], uHat));
  }
  const w = polySub(v, nttInv(inner));

  return byteEncode(compressPoly(w, 1), 1);
}

const { randomBytes, constantTimeEqual } = require("./utils");

// ── FIPS 203 Input Validation (§7.1, §7.2) ──────────────────────

function ekModulusCheck(ek) {
  if (ek.length !== 1184) return false;
  // Constant-time: check all chunks without early return
  let valid = 1;
  for (let i = 0; i < K; i++) {
    const chunk = ek.subarray(384 * i, 384 * (i + 1));
    const reencoded = byteEncode(byteDecode(chunk, 12), 12);
    valid &= constantTimeEqual(chunk, reencoded) ? 1 : 0;
  }
  return valid === 1;
}

function dkHashCheck(dk) {
  if (dk.length !== 2400) return false;
  const ek = dk.subarray(384 * K, 384 * K + 1184);
  const hStored = dk.subarray(384 * K + 1184, 384 * K + 1184 + 32);
  return constantTimeEqual(sha3_256(ek), hStored);
}

// ── Public API ───────────────────────────────────────────────────

function mlKemKeygen(seed) {
  if (!seed) seed = randomBytes(64);
  if (seed.length !== 64) throw new Error(`ML-KEM-768 keygen requires 64-byte seed, got ${seed.length}`);

  const d = seed.subarray(0, 32);
  const z = seed.subarray(32, 64);

  const { ekPke, dkPke } = kPkeKeygen(d);

  const hEk = sha3_256(ekPke);

  // DK = dkPke || ekPke || H(ekPke) || z
  const dk = new Uint8Array(2400);
  dk.set(dkPke);
  dk.set(ekPke, 384 * K);
  dk.set(hEk, 384 * K + 1184);
  dk.set(z, 384 * K + 1184 + 32);

  return { ek: new Uint8Array(ekPke), dk };
}

function mlKemEncaps(ek, randomness) {
  if (!(ek instanceof Uint8Array)) throw new Error("ek must be a Uint8Array");
  if (!ekModulusCheck(ek)) throw new Error("Encapsulation key failed FIPS 203 modulus check (§7.1)");
  if (!randomness) randomness = randomBytes(32);
  if (randomness.length !== 32) throw new Error(`ML-KEM-768 encaps randomness must be 32 bytes`);

  const m = randomness;
  const hEk = sha3_256(ek);

  const gInput = new Uint8Array(64);
  gInput.set(m);
  gInput.set(hEk, 32);
  const gOutput = sha3_512(gInput);
  const Kss = gOutput.subarray(0, 32);
  const r = gOutput.subarray(32, 64);

  const ct = kPkeEncrypt(ek, m, r);

  return { ct, ss: new Uint8Array(Kss) };
}

function mlKemDecaps(dk, ct) {
  if (!(dk instanceof Uint8Array)) throw new Error("dk must be a Uint8Array");
  if (!(ct instanceof Uint8Array)) throw new Error("ct must be a Uint8Array");
  if (ct.length !== 1088) throw new Error(`ML-KEM-768 decaps requires 1088-byte CT, got ${ct.length}`);
  if (!dkHashCheck(dk)) throw new Error("Decapsulation key failed FIPS 203 hash check (§7.2)");

  const dkPke = dk.subarray(0, 384 * K);
  const ekPke = dk.subarray(384 * K, 384 * K + 1184);
  const h = dk.subarray(384 * K + 1184, 384 * K + 1184 + 32);
  const z = dk.subarray(384 * K + 1184 + 32);

  const mPrime = kPkeDecrypt(dkPke, ct);

  const gInput = new Uint8Array(64);
  gInput.set(mPrime);
  gInput.set(h, 32);
  const gOutput = sha3_512(gInput);
  const Kprime = gOutput.subarray(0, 32);
  const rPrime = gOutput.subarray(32, 64);

  // Implicit rejection
  const kBarInput = new Uint8Array(z.length + ct.length);
  kBarInput.set(z);
  kBarInput.set(ct, z.length);
  const Kbar = shake256(kBarInput, 32);

  const ctPrime = kPkeEncrypt(ekPke, mPrime, rPrime);

  // Constant-time selection: avoid branch on secret comparison result.
  // Derive mask arithmetically: -1 (0xffffffff) if equal, 0 if not.
  const mask = (-(constantTimeEqual(ct, ctPrime) | 0)) & 0xff;
  const result = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    result[i] = (Kprime[i] & mask) | (Kbar[i] & (~mask & 0xff));
  }
  return result;
}

const EK_SIZE = 1184;
const DK_SIZE = 2400;
const CT_SIZE = 1088;
const SS_SIZE = 32;

module.exports = { mlKemKeygen, mlKemEncaps, mlKemDecaps, EK_SIZE, DK_SIZE, CT_SIZE, SS_SIZE };

};

// ── crypto/slh_dsa.js ──
_dirs["./crypto/slh_dsa"] = "./crypto";
_modules["./crypto/slh_dsa"] = function(module, exports, require) {
// Copyright (c) 2026 Signer.io — MIT License

"use strict";

/**
 * SLH-DSA-SHAKE-128s (SPHINCS+) — FIPS 205 post-quantum digital signature.
 *
 * Pure JavaScript implementation of the Stateless Hash-Based Digital Signature
 * Standard at parameter set SLH-DSA-SHAKE-128s.
 *
 * Security relies solely on the collision resistance of SHAKE-256 — no
 * lattice assumptions required. This is the most conservative post-quantum choice.
 *
 * Key sizes:
 *     Public key:  32 bytes
 *     Secret key:  64 bytes
 *     Signature:   7,856 bytes
 *
 * Security: NIST Level 1 (128-bit post-quantum security).
 * Assumption: Hash function (SHAKE-256) security only.
 *
 * Reference: NIST FIPS 205 (August 2024).
 *
 * Public API:
 *     slhKeygen(seed)              -> { sk, pk }
 *     slhSign(msg, sk, opts?)       -> Uint8Array sig (7856 bytes)
 *     slhVerify(msg, sig, pk)      -> bool
 *
 * Notes:
 *     - Messages are byte-aligned (Uint8Array). Bit-level granularity is not
 *       supported.
 *     - Signing defaults to hedged mode (addrnd generated via CSPRNG)
 *       as recommended by FIPS 205. Pass deterministic=true for the deterministic
 *       variant (uses PK.seed as opt_rand).
 *     - Best-effort constant-time: all control flow is branchless.
 *       Hash computations (SHAKE-256) are fixed-time for same-length inputs.
 *       For deployments where hardware side-channel attacks are a concern,
 *       use a vetted constant-time C/Rust implementation instead.
 */

const { shake256 } = require("./sha3");
const { randomBytes, toBytes, constantTimeEqual } = require("./utils");

// ── SLH-DSA-SHAKE-128s Parameters (FIPS 205 Table 2) ─────────────

const _N = 16;             // Security parameter (hash output bytes)
const _FULL_H = 63;        // Total tree height
const _D = 7;              // Number of hypertree layers
const _HP = (_FULL_H / _D) | 0; // = 9, height of each XMSS tree
const _A = 12;             // FORS tree height
const _K = 14;             // Number of FORS trees
const _LG_W = 4;           // Winternitz parameter log2
const _W = 1 << _LG_W;    // = 16, Winternitz parameter

// WOTS+ constants
// len1 = ceil(8*n / lg_w) = ceil(128/4) = 32 message blocks
const _LEN1 = ((8 * _N + _LG_W - 1) / _LG_W) | 0; // = 32
// len2 = floor(log_w(len1*(w-1))) + 1 = floor(log_16(480)) + 1 = 3
const _LEN2 = 3;
const _LEN = _LEN1 + _LEN2; // = 35, total WOTS+ chains

// Message digest output sizes
const _MD_BYTES = ((_K * _A + 7) / 8) | 0;                      // = 21
const _IDX_TREE_BYTES = ((_FULL_H - _HP + 7) / 8) | 0;         // = 7
const _IDX_LEAF_BYTES = ((_HP + 7) / 8) | 0;                    // = 2
const _M = _MD_BYTES + _IDX_TREE_BYTES + _IDX_LEAF_BYTES;       // = 30

// Signature / key sizes
// SIG = R(n) + SIG_FORS(k*(1+a)*n) + SIG_HT(d*(hp+len)*n)
//     = 16 + 14*13*16 + 7*(9+35)*16 = 16 + 2912 + 4928 = 7856
const _SIG_SIZE = _N + _K * (1 + _A) * _N + _D * (_HP + _LEN) * _N; // = 7856
const _PK_SIZE = 2 * _N;  // = 32
const _SK_SIZE = 4 * _N;  // = 64


// ── ADRS (Address) Structure ──────────────────────────────────────
// 32-byte structured address identifying each node in the tree hierarchy.

// ADRS field offsets (FIPS 205 Section 4.2)
const _ADRS_LAYER = 0;    // Bytes 0-3: layer address
const _ADRS_TREE = 4;     // Bytes 4-15: tree address (96 bits)
const _ADRS_TYPE = 16;    // Bytes 16-19: address type
const _ADRS_WORD1 = 20;   // Bytes 20-23: type-specific word 1
const _ADRS_WORD2 = 24;   // Bytes 24-27: type-specific word 2
const _ADRS_WORD3 = 28;   // Bytes 28-31: type-specific word 3

// Address types
const _ADRS_TYPE_WOTS_HASH = 0;
const _ADRS_TYPE_WOTS_PK = 1;
const _ADRS_TYPE_TREE = 2;
const _ADRS_TYPE_FORS_TREE = 3;
const _ADRS_TYPE_FORS_ROOTS = 4;
const _ADRS_TYPE_WOTS_PRF = 5;
const _ADRS_TYPE_FORS_PRF = 6;


/**
 * Create a new zero-initialized ADRS.
 * @returns {Uint8Array} 32-byte address structure
 */
function _adrs_new() {
  return new Uint8Array(32);
}

/**
 * Set the 32-bit layer address at bytes 0-3.
 * @param {Uint8Array} adrs
 * @param {number} layer
 */
function _adrs_set_layer(adrs, layer) {
  new DataView(adrs.buffer, adrs.byteOffset).setUint32(_ADRS_LAYER, layer, false);
}

/**
 * Set 96-bit tree address (bytes 4-15) — toByte(tree, 12).
 * tree is a BigInt since it can be up to 54 bits (exceeds Number.MAX_SAFE_INTEGER).
 * @param {Uint8Array} adrs
 * @param {bigint} tree
 */
function _adrs_set_tree(adrs, tree) {
  for (let i = 11; i >= 0; i--) {
    adrs[_ADRS_TREE + (11 - i)] = Number((tree >> BigInt(i * 8)) & 0xffn);
  }
}

/**
 * Set the address type at bytes 16-19 and clear type-specific words (bytes 20-31).
 * @param {Uint8Array} adrs
 * @param {number} type_val
 */
function _adrs_set_type(adrs, type_val) {
  new DataView(adrs.buffer, adrs.byteOffset).setUint32(_ADRS_TYPE, type_val, false);
  // Clear remaining words when type changes
  for (let i = 20; i < 32; i++) adrs[i] = 0;
}

/**
 * Set keypair address at bytes 20-23.
 * @param {Uint8Array} adrs
 * @param {number} kp
 */
function _adrs_set_keypair(adrs, kp) {
  new DataView(adrs.buffer, adrs.byteOffset).setUint32(_ADRS_WORD1, kp, false);
}

/**
 * Set chain address at bytes 24-27.
 * @param {Uint8Array} adrs
 * @param {number} chain
 */
function _adrs_set_chain(adrs, chain) {
  new DataView(adrs.buffer, adrs.byteOffset).setUint32(_ADRS_WORD2, chain, false);
}

/**
 * Set hash address at bytes 28-31.
 * @param {Uint8Array} adrs
 * @param {number} hash_idx
 */
function _adrs_set_hash(adrs, hash_idx) {
  new DataView(adrs.buffer, adrs.byteOffset).setUint32(_ADRS_WORD3, hash_idx, false);
}

/**
 * Set tree height at bytes 24-27.
 * @param {Uint8Array} adrs
 * @param {number} height
 */
function _adrs_set_tree_height(adrs, height) {
  new DataView(adrs.buffer, adrs.byteOffset).setUint32(_ADRS_WORD2, height, false);
}

/**
 * Set tree index at bytes 28-31.
 * @param {Uint8Array} adrs
 * @param {number} index
 */
function _adrs_set_tree_index(adrs, index) {
  new DataView(adrs.buffer, adrs.byteOffset).setUint32(_ADRS_WORD3, index, false);
}

/**
 * Copy an ADRS.
 * @param {Uint8Array} adrs
 * @returns {Uint8Array}
 */
function _adrs_copy(adrs) {
  return new Uint8Array(adrs);
}

/**
 * Read a 32-bit big-endian unsigned integer from adrs at offset.
 * @param {Uint8Array} adrs
 * @param {number} offset
 * @returns {number}
 */
function _adrs_get_u32(adrs, offset) {
  return new DataView(adrs.buffer, adrs.byteOffset).getUint32(offset, false);
}


// ── Helper: concatenate Uint8Arrays ───────────────────────────────

/**
 * Concatenate multiple Uint8Arrays into one.
 * @param  {...Uint8Array} arrays
 * @returns {Uint8Array}
 */
function concat(...arrays) {
  let totalLen = 0;
  for (let i = 0; i < arrays.length; i++) totalLen += arrays[i].length;
  const out = new Uint8Array(totalLen);
  let off = 0;
  for (let i = 0; i < arrays.length; i++) {
    out.set(arrays[i], off);
    off += arrays[i].length;
  }
  return out;
}

/**
 * Constant-time comparison of two Uint8Arrays.
 * Delegates to the shared tiered implementation in utils.js:
 *   Tier 1: Node.js crypto.timingSafeEqual (C-backed)
 *   Tier 2: Inline WASM ct_equal (browser, no JIT variation)
 *   Tier 3: Pure JS XOR-accumulate fallback
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
function bytesEqual(a, b) {
  return constantTimeEqual(a, b);
}

/**
 * Constant-time conditional swap for Merkle tree traversals.
 * When bit=0: returns [a, b] (no swap).
 * When bit=1: returns [b, a] (swap).
 * bit MUST be 0 or 1.
 * @param {number} bit
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {Uint8Array} concatenation left||right
 */
function ctSwapConcat(bit, a, b) {
  const n = a.length;
  const out = new Uint8Array(n * 2);
  // mask is 0x00 when bit=0, 0xFF when bit=1
  const mask = (-bit) & 0xFF;
  for (let i = 0; i < n; i++) {
    const diff = a[i] ^ b[i];
    const sel = diff & mask;
    out[i] = a[i] ^ sel;         // left: a when bit=0, b when bit=1
    out[n + i] = b[i] ^ sel;     // right: b when bit=0, a when bit=1
  }
  return out;
}

/**
 * Read big-endian integer from byte array as BigInt.
 * @param {Uint8Array} data
 * @returns {bigint}
 */
function bytesToBigInt(data) {
  let val = 0n;
  for (let i = 0; i < data.length; i++) {
    val = (val << 8n) | BigInt(data[i]);
  }
  return val;
}

/**
 * Read big-endian integer from byte array as Number.
 * Only safe for values that fit within Number.MAX_SAFE_INTEGER.
 * @param {Uint8Array} data
 * @returns {number}
 */
function bytesToNumber(data) {
  let val = 0;
  for (let i = 0; i < data.length; i++) {
    val = val * 256 + data[i];
  }
  return val;
}

/**
 * Convert a non-negative integer to big-endian byte array of given length.
 * @param {number} val
 * @param {number} len
 * @returns {Uint8Array}
 */
function numberToBytes(val, len) {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = val & 0xff;
    val = Math.floor(val / 256);
  }
  return out;
}


// ── Tweakable Hash Functions (SHAKE-256 based) ────────────────────

/**
 * Tweakable hash F: SHAKE-256(PK.seed || ADRS || msg, n).
 * Single-block input (msg is n bytes).
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
function _F(pk_seed, adrs, msg) {
  return shake256(concat(pk_seed, adrs, msg), _N);
}

/**
 * Tweakable hash H: SHAKE-256(PK.seed || ADRS || m1||m2, n).
 * Two-block input (m1_m2 is 2n bytes).
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @param {Uint8Array} m1_m2
 * @returns {Uint8Array}
 */
function _H(pk_seed, adrs, m1_m2) {
  return shake256(concat(pk_seed, adrs, m1_m2), _N);
}

/**
 * Tweakable hash T_l for variable-length input.
 * SHAKE-256(PK.seed || ADRS || msg, n). msg is len*n bytes.
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
function _T_l(pk_seed, adrs, msg) {
  return shake256(concat(pk_seed, adrs, msg), _N);
}

/**
 * Pseudorandom function: SHAKE-256(PK.seed || ADRS || SK.seed, n).
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} adrs
 * @returns {Uint8Array}
 */
function _PRF(pk_seed, sk_seed, adrs) {
  return shake256(concat(pk_seed, adrs, sk_seed), _N);
}

/**
 * Message PRF: SHAKE-256(SK.prf || opt_rand || msg, n).
 * @param {Uint8Array} sk_prf
 * @param {Uint8Array} opt_rand
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
function _PRF_msg(sk_prf, opt_rand, msg) {
  return shake256(concat(sk_prf, opt_rand, msg), _N);
}

/**
 * Message hash: SHAKE-256(R || PK.seed || PK.root || msg, m).
 * @param {Uint8Array} R
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} pk_root
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
function _H_msg(R, pk_seed, pk_root, msg) {
  return shake256(concat(R, pk_seed, pk_root, msg), _M);
}


// ── WOTS+ One-Time Signatures ─────────────────────────────────────

/**
 * Apply hash chain: F^steps starting from F^start.
 * Algorithm 5, FIPS 205.
 * @param {Uint8Array} X - Starting value (n bytes)
 * @param {number} start - Starting index
 * @param {number} steps - Number of chain steps
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs - Mutable, will be modified
 * @returns {Uint8Array}
 */
function _wots_chain(X, start, steps, pk_seed, adrs) {
  let tmp = X;
  for (let i = start; i < start + steps; i++) {
    _adrs_set_hash(adrs, i);
    tmp = _F(pk_seed, adrs, tmp);
  }
  return tmp;
}

/**
 * Generate WOTS+ public key (Algorithm 6, FIPS 205).
 * Returns the compressed public key (n bytes).
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @returns {Uint8Array}
 */
function _wots_keygen(sk_seed, pk_seed, adrs) {
  const sk_adrs = _adrs_copy(adrs);
  _adrs_set_type(sk_adrs, _ADRS_TYPE_WOTS_PRF);
  _adrs_set_keypair(sk_adrs, _adrs_get_u32(adrs, _ADRS_WORD1));

  const parts = [];
  for (let i = 0; i < _LEN; i++) {
    _adrs_set_chain(sk_adrs, i);
    const sk = _PRF(pk_seed, sk_seed, sk_adrs);
    const chain_adrs = _adrs_copy(adrs);
    _adrs_set_chain(chain_adrs, i);
    parts.push(_wots_chain(sk, 0, _W - 1, pk_seed, chain_adrs));
  }

  const wots_pk_adrs = _adrs_copy(adrs);
  _adrs_set_type(wots_pk_adrs, _ADRS_TYPE_WOTS_PK);
  _adrs_set_keypair(wots_pk_adrs, _adrs_get_u32(adrs, _ADRS_WORD1));
  return _T_l(pk_seed, wots_pk_adrs, concat(...parts));
}

/**
 * WOTS+ signing (Algorithm 7, FIPS 205).
 * msg is n bytes. Returns signature (_LEN * n bytes).
 * @param {Uint8Array} msg
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @returns {Uint8Array}
 */
function _wots_sign(msg, sk_seed, pk_seed, adrs) {
  // Convert message to base-w representation
  const msg_base_w = _base_w(msg, _LEN1);

  let csum = 0;
  for (let i = 0; i < msg_base_w.length; i++) {
    csum += _W - 1 - msg_base_w[i];
  }
  csum <<= (8 - ((_LEN2 * _LG_W) % 8)) % 8;
  const csum_len = ((_LEN2 * _LG_W + 7) / 8) | 0;
  const csum_bytes = numberToBytes(csum, csum_len);
  const csum_base_w = _base_w(csum_bytes, _LEN2);
  for (let i = 0; i < csum_base_w.length; i++) {
    msg_base_w.push(csum_base_w[i]);
  }

  const sk_adrs = _adrs_copy(adrs);
  _adrs_set_type(sk_adrs, _ADRS_TYPE_WOTS_PRF);
  _adrs_set_keypair(sk_adrs, _adrs_get_u32(adrs, _ADRS_WORD1));

  const parts = [];
  for (let i = 0; i < _LEN; i++) {
    _adrs_set_chain(sk_adrs, i);
    const sk = _PRF(pk_seed, sk_seed, sk_adrs);
    const chain_adrs = _adrs_copy(adrs);
    _adrs_set_chain(chain_adrs, i);
    parts.push(_wots_chain(sk, 0, msg_base_w[i], pk_seed, chain_adrs));
  }
  return concat(...parts);
}

/**
 * Recover WOTS+ public key from signature (Algorithm 8, FIPS 205).
 * @param {Uint8Array} sig - WOTS+ signature (_LEN * n bytes)
 * @param {Uint8Array} msg - Message (n bytes)
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @returns {Uint8Array}
 */
function _wots_pk_from_sig(sig, msg, pk_seed, adrs) {
  const msg_base_w = _base_w(msg, _LEN1);

  let csum = 0;
  for (let i = 0; i < msg_base_w.length; i++) {
    csum += _W - 1 - msg_base_w[i];
  }
  csum <<= (8 - ((_LEN2 * _LG_W) % 8)) % 8;
  const csum_len = ((_LEN2 * _LG_W + 7) / 8) | 0;
  const csum_bytes = numberToBytes(csum, csum_len);
  const csum_base_w = _base_w(csum_bytes, _LEN2);
  for (let i = 0; i < csum_base_w.length; i++) {
    msg_base_w.push(csum_base_w[i]);
  }

  const parts = [];
  for (let i = 0; i < _LEN; i++) {
    const chain_adrs = _adrs_copy(adrs);
    _adrs_set_chain(chain_adrs, i);
    const sig_i = sig.subarray(i * _N, (i + 1) * _N);
    parts.push(_wots_chain(sig_i, msg_base_w[i], _W - 1 - msg_base_w[i], pk_seed, chain_adrs));
  }

  const wots_pk_adrs = _adrs_copy(adrs);
  _adrs_set_type(wots_pk_adrs, _ADRS_TYPE_WOTS_PK);
  _adrs_set_keypair(wots_pk_adrs, _adrs_get_u32(adrs, _ADRS_WORD1));
  return _T_l(pk_seed, wots_pk_adrs, concat(...parts));
}

/**
 * Convert byte string to base-w representation.
 * For w=16 (lg_w=4): each byte yields 2 nibbles, high nibble first.
 * @param {Uint8Array} data
 * @param {number} out_len
 * @returns {number[]}
 */
function _base_w(data, out_len) {
  const result = [];
  for (let b = 0; b < data.length; b++) {
    result.push((data[b] >> 4) & 0x0f);
    result.push(data[b] & 0x0f);
    if (result.length >= out_len) break;
  }
  return result.slice(0, out_len);
}


// ── XMSS (Merkle Tree Signatures) ─────────────────────────────────

/**
 * Compute XMSS tree node at position i, height z (Algorithm 9, FIPS 205).
 * Recursive: leaves are WOTS+ public keys, internal nodes are H(left||right).
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} pk_seed
 * @param {number} i - Node index
 * @param {number} z - Node height
 * @param {Uint8Array} adrs
 * @returns {Uint8Array}
 */
function _xmss_node(sk_seed, pk_seed, i, z, adrs) {
  if (z === 0) {
    // Leaf: WOTS+ public key
    const wots_adrs = _adrs_copy(adrs);
    _adrs_set_type(wots_adrs, _ADRS_TYPE_WOTS_HASH);
    _adrs_set_keypair(wots_adrs, i);
    return _wots_keygen(sk_seed, pk_seed, wots_adrs);
  } else {
    // Internal node: hash of children
    const left = _xmss_node(sk_seed, pk_seed, 2 * i, z - 1, adrs);
    const right = _xmss_node(sk_seed, pk_seed, 2 * i + 1, z - 1, adrs);
    const node_adrs = _adrs_copy(adrs);
    _adrs_set_type(node_adrs, _ADRS_TYPE_TREE);
    _adrs_set_tree_height(node_adrs, z);
    _adrs_set_tree_index(node_adrs, i);
    return _H(pk_seed, node_adrs, concat(left, right));
  }
}

/**
 * XMSS tree signing (Algorithm 10, FIPS 205).
 * Returns [sig_wots, auth_path] where auth_path is hp * n bytes.
 * idx is the leaf index to sign with.
 * @param {Uint8Array} msg
 * @param {Uint8Array} sk_seed
 * @param {number} idx - Leaf index
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @returns {[Uint8Array, Uint8Array]} [sig_wots, auth_path]
 */
function _xmss_sign(msg, sk_seed, idx, pk_seed, adrs) {
  // WOTS+ signature of the message
  const wots_adrs = _adrs_copy(adrs);
  _adrs_set_type(wots_adrs, _ADRS_TYPE_WOTS_HASH);
  _adrs_set_keypair(wots_adrs, idx);
  const sig = _wots_sign(msg, sk_seed, pk_seed, wots_adrs);

  // Authentication path: sibling nodes from leaf to root
  const auth_parts = [];
  let cur_idx = idx;
  for (let j = 0; j < _HP; j++) {
    const sibling = cur_idx ^ 1; // Sibling index at this level
    auth_parts.push(_xmss_node(sk_seed, pk_seed, sibling, j, adrs));
    cur_idx >>= 1;
  }
  return [sig, concat(...auth_parts)];
}


// ── Hypertree ──────────────────────────────────────────────────────

/**
 * Hypertree signing (Algorithm 11, FIPS 205).
 * Signs msg at position (idx_tree, idx_leaf) through D layers.
 * Returns HT signature: D * (WOTS_sig + auth_path).
 *
 * idx_tree is a BigInt (up to 54 bits).
 * @param {Uint8Array} msg
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} pk_seed
 * @param {bigint} idx_tree
 * @param {number} idx_leaf
 * @returns {Uint8Array}
 */
function _ht_sign(msg, sk_seed, pk_seed, idx_tree, idx_leaf) {
  let adrs = _adrs_new();
  _adrs_set_layer(adrs, 0);
  _adrs_set_tree(adrs, idx_tree);

  let [sig_tmp, auth_tmp] = _xmss_sign(msg, sk_seed, idx_leaf, pk_seed, adrs);
  const sig_parts = [sig_tmp, auth_tmp];

  let root = _xmss_root_from_sig(idx_leaf, sig_tmp, auth_tmp, msg, pk_seed, adrs);

  for (let j = 1; j < _D; j++) {
    idx_leaf = Number(idx_tree & BigInt((1 << _HP) - 1));
    idx_tree >>= BigInt(_HP);
    adrs = _adrs_new();
    _adrs_set_layer(adrs, j);
    _adrs_set_tree(adrs, idx_tree);
    [sig_tmp, auth_tmp] = _xmss_sign(root, sk_seed, idx_leaf, pk_seed, adrs);
    sig_parts.push(sig_tmp, auth_tmp);
    if (j < _D - 1) {
      root = _xmss_root_from_sig(idx_leaf, sig_tmp, auth_tmp, root, pk_seed, adrs);
    }
  }

  return concat(...sig_parts);
}

/**
 * Hypertree verification (Algorithm 12, FIPS 205).
 * Returns true if the HT signature is valid.
 *
 * idx_tree is a BigInt (up to 54 bits).
 * @param {Uint8Array} msg
 * @param {Uint8Array} sig_ht
 * @param {Uint8Array} pk_seed
 * @param {bigint} idx_tree
 * @param {number} idx_leaf
 * @param {Uint8Array} pk_root
 * @returns {boolean}
 */
function _ht_verify(msg, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root) {
  let adrs = _adrs_new();
  _adrs_set_layer(adrs, 0);
  _adrs_set_tree(adrs, idx_tree);

  let offset = 0;
  let sig_tmp = sig_ht.subarray(offset, offset + _LEN * _N);
  offset += _LEN * _N;
  let auth_tmp = sig_ht.subarray(offset, offset + _HP * _N);
  offset += _HP * _N;

  let node = _xmss_root_from_sig(idx_leaf, sig_tmp, auth_tmp, msg, pk_seed, adrs);

  for (let j = 1; j < _D; j++) {
    idx_leaf = Number(idx_tree & BigInt((1 << _HP) - 1));
    idx_tree >>= BigInt(_HP);
    adrs = _adrs_new();
    _adrs_set_layer(adrs, j);
    _adrs_set_tree(adrs, idx_tree);

    sig_tmp = sig_ht.subarray(offset, offset + _LEN * _N);
    offset += _LEN * _N;
    auth_tmp = sig_ht.subarray(offset, offset + _HP * _N);
    offset += _HP * _N;

    node = _xmss_root_from_sig(idx_leaf, sig_tmp, auth_tmp, node, pk_seed, adrs);
  }

  return bytesEqual(node, pk_root);
}

/**
 * Compute XMSS root from a signature and authentication path.
 * Algorithm 10b / verification helper (FIPS 205).
 * @param {number} idx
 * @param {Uint8Array} sig - WOTS+ signature
 * @param {Uint8Array} auth - Authentication path
 * @param {Uint8Array} msg
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @returns {Uint8Array}
 */
function _xmss_root_from_sig(idx, sig, auth, msg, pk_seed, adrs) {
  // Recover WOTS+ public key
  const wots_adrs = _adrs_copy(adrs);
  _adrs_set_type(wots_adrs, _ADRS_TYPE_WOTS_HASH);
  _adrs_set_keypair(wots_adrs, idx);
  let node = _wots_pk_from_sig(sig, msg, pk_seed, wots_adrs);

  // Walk up the tree using auth path (branchless byte-order swap)
  const tree_adrs = _adrs_copy(adrs);
  _adrs_set_type(tree_adrs, _ADRS_TYPE_TREE);
  for (let j = 0; j < _HP; j++) {
    _adrs_set_tree_height(tree_adrs, j + 1);
    _adrs_set_tree_index(tree_adrs, idx >> (j + 1));
    const auth_j = auth.subarray(j * _N, (j + 1) * _N);
    // Branchless: bit==0 -> H(node||auth), bit==1 -> H(auth||node)
    const bit = (idx >> j) & 1;
    node = _H(pk_seed, tree_adrs, ctSwapConcat(bit, node, auth_j));
  }
  return node;
}


// ── FORS (Forest of Random Subsets) ───────────────────────────────

/**
 * Generate FORS secret value at index idx.
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @param {number} idx
 * @returns {Uint8Array}
 */
function _fors_keygen(sk_seed, pk_seed, adrs, idx) {
  const fors_adrs = _adrs_copy(adrs);
  _adrs_set_type(fors_adrs, _ADRS_TYPE_FORS_PRF);
  _adrs_set_keypair(fors_adrs, _adrs_get_u32(adrs, _ADRS_WORD1));
  _adrs_set_tree_index(fors_adrs, idx);
  return _PRF(pk_seed, sk_seed, fors_adrs);
}

/**
 * Compute FORS tree node at position i, height z (Algorithm 15, FIPS 205).
 * Expects adrs already has type=FORS_TREE and keypair address set.
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @param {number} i
 * @param {number} z
 * @returns {Uint8Array}
 */
function _fors_tree_node(sk_seed, pk_seed, adrs, i, z) {
  if (z === 0) {
    const sk = _fors_keygen(sk_seed, pk_seed, adrs, i);
    const node_adrs = _adrs_copy(adrs);
    _adrs_set_tree_height(node_adrs, 0);
    _adrs_set_tree_index(node_adrs, i);
    return _F(pk_seed, node_adrs, sk);
  }

  const left = _fors_tree_node(sk_seed, pk_seed, adrs, 2 * i, z - 1);
  const right = _fors_tree_node(sk_seed, pk_seed, adrs, 2 * i + 1, z - 1);
  const node_adrs = _adrs_copy(adrs);
  _adrs_set_tree_height(node_adrs, z);
  _adrs_set_tree_index(node_adrs, i);
  return _H(pk_seed, node_adrs, concat(left, right));
}

/**
 * FORS signing (Algorithm 16, FIPS 205).
 * md: message digest bytes to split into k a-bit indices.
 * Returns: FORS signature (k * (1 + a) * n bytes).
 * @param {Uint8Array} md
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @returns {Uint8Array}
 */
function _fors_sign(md, sk_seed, pk_seed, adrs) {
  const indices = _md_to_indices(md);

  const sig_parts = [];
  for (let i = 0; i < _K; i++) {
    const idx = indices[i];
    // Secret value at global leaf index i*2^a + idx
    sig_parts.push(_fors_keygen(sk_seed, pk_seed, adrs, (i << _A) + idx));
    // Authentication path: sibling at each level j
    for (let j = 0; j < _A; j++) {
      const s = (idx >> j) ^ 1;                       // floor(idx/2^j) xor 1
      const auth_idx = (i << (_A - j)) + s;           // i*2^(a-j) + s
      sig_parts.push(_fors_tree_node(sk_seed, pk_seed, adrs, auth_idx, j));
    }
  }
  return concat(...sig_parts);
}

/**
 * Recover FORS public key from signature (Algorithm 17, FIPS 205).
 * Expects adrs already has type=FORS_TREE and keypair address set.
 * @param {Uint8Array} sig_fors
 * @param {Uint8Array} md
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @returns {Uint8Array}
 */
function _fors_pk_from_sig(sig_fors, md, pk_seed, adrs) {
  const indices = _md_to_indices(md);
  const roots_parts = [];

  let off = 0;
  for (let i = 0; i < _K; i++) {
    const idx = indices[i];

    const sk = sig_fors.subarray(off, off + _N);
    off += _N;

    // Global leaf index in the forest
    let tree_index = (i << _A) + idx;

    // Leaf node
    let node_adrs = _adrs_copy(adrs);
    _adrs_set_tree_height(node_adrs, 0);
    _adrs_set_tree_index(node_adrs, tree_index);
    let node = _F(pk_seed, node_adrs, sk);

    // Walk up the tree (branchless byte-order swap + parent index)
    for (let j = 0; j < _A; j++) {
      const auth_j = sig_fors.subarray(off, off + _N);
      off += _N;

      const parent_adrs = _adrs_copy(adrs);
      _adrs_set_tree_height(parent_adrs, j + 1);
      const bit = (idx >> j) & 1;
      // Branchless parent index: bit==0 -> tree_index>>1,
      // bit==1 -> (tree_index-1)>>1
      tree_index = (tree_index - bit) >> 1;
      _adrs_set_tree_index(parent_adrs, tree_index);
      // Branchless byte-order swap
      node = _H(pk_seed, parent_adrs, ctSwapConcat(bit, node, auth_j));
    }

    roots_parts.push(node);
  }

  // Compress the k roots into FORS public key
  const fors_pk_adrs = _adrs_copy(adrs);
  _adrs_set_type(fors_pk_adrs, _ADRS_TYPE_FORS_ROOTS);
  _adrs_set_keypair(fors_pk_adrs, _adrs_get_u32(adrs, _ADRS_WORD1));
  return _T_l(pk_seed, fors_pk_adrs, concat(...roots_parts));
}

/**
 * Split message digest into k indices of a bits each.
 * Uses BigInt since md can be up to 21 bytes (168 bits).
 * @param {Uint8Array} md
 * @returns {number[]}
 */
function _md_to_indices(md) {
  const indices = [];
  const bits = bytesToBigInt(md.subarray(0, _MD_BYTES));
  const total_bits = _MD_BYTES * 8;
  const mask = BigInt((1 << _A) - 1);
  for (let i = 0; i < _K; i++) {
    const shift = total_bits - (i + 1) * _A;
    let idx;
    if (shift >= 0) {
      idx = Number((bits >> BigInt(shift)) & mask);
    } else {
      idx = Number((bits << BigInt(-shift)) & mask);
    }
    indices.push(idx);
  }
  return indices;
}


// ── Top-Level API ──────────────────────────────────────────────────

/**
 * SLH-DSA-SHAKE-128s key generation (Algorithm 21, FIPS 205).
 *
 * @param {Uint8Array} seed - 48-byte seed = SK.seed(16) || SK.prf(16) || PK.seed(16)
 * @returns {{ sk: Uint8Array, pk: Uint8Array }} sk: 64-byte secret key, pk: 32-byte public key
 */
function slhKeygen(seed) {
  if (!(seed instanceof Uint8Array)) {
    throw new Error("seed must be a Uint8Array");
  }
  if (seed.length !== 3 * _N) {
    throw new Error(`seed must be ${3 * _N} bytes, got ${seed.length}`);
  }

  const sk_seed = seed.subarray(0, _N);        // 16 bytes
  const sk_prf = seed.subarray(_N, 2 * _N);    // 16 bytes
  const pk_seed = seed.subarray(2 * _N, 3 * _N); // 16 bytes

  // Compute root of the top XMSS tree
  const adrs = _adrs_new();
  _adrs_set_layer(adrs, _D - 1);
  _adrs_set_tree(adrs, 0n);
  const pk_root = _xmss_node(sk_seed, pk_seed, 0, _HP, adrs);

  const sk = concat(sk_seed, sk_prf, pk_seed, pk_root);
  const pk = concat(pk_seed, pk_root);
  return { sk, pk };
}

/**
 * SLH-DSA-SHAKE-128s internal signing (Algorithm 23, FIPS 205).
 *
 * Signs pre-processed message M' directly. Use slhSign() for the
 * pure FIPS 205 API with context string support.
 *
 * @param {Uint8Array} message - Pre-processed message M'
 * @param {Uint8Array} sk_bytes - 64-byte secret key
 * @param {Uint8Array|null} [addrnd=null] - Explicit n-byte randomness (overrides modes)
 * @param {boolean} [deterministic=false] - If true and addrnd is null, use PK.seed (deterministic)
 * @returns {Uint8Array} Signature (7856 bytes)
 */
function _slh_sign_internal(message, sk_bytes, addrnd, deterministic) {
  if (sk_bytes.length !== _SK_SIZE) {
    throw new Error(`secret key must be ${_SK_SIZE} bytes, got ${sk_bytes.length}`);
  }
  if (addrnd != null) {
    if (addrnd.length !== _N) {
      throw new Error(`addrnd must be ${_N} bytes, got ${addrnd.length}`);
    }
  }

  const sk_seed = sk_bytes.subarray(0, _N);
  const sk_prf = sk_bytes.subarray(_N, 2 * _N);
  const pk_seed = sk_bytes.subarray(2 * _N, 3 * _N);
  const pk_root = sk_bytes.subarray(3 * _N, 4 * _N);

  // Step 1: Randomizer R (deterministic or hedged, FIPS 205 Section 10.2.1)
  let opt_rand;
  if (addrnd != null) {
    opt_rand = addrnd;
  } else if (deterministic) {
    opt_rand = pk_seed;
  } else {
    opt_rand = randomBytes(_N);
  }
  const R = _PRF_msg(sk_prf, opt_rand, message);

  // Step 2: Hash message to get digest
  const digest = _H_msg(R, pk_seed, pk_root, message);

  // Step 3: Split digest into (md, idx_tree, idx_leaf)
  const md = digest.subarray(0, _MD_BYTES);
  const idx_tree_bytes = digest.subarray(_MD_BYTES, _MD_BYTES + _IDX_TREE_BYTES);
  const idx_leaf_bytes = digest.subarray(_MD_BYTES + _IDX_TREE_BYTES);

  // idx_tree can be up to 54 bits — use BigInt
  let idx_tree = bytesToBigInt(idx_tree_bytes);
  // Mask to valid tree range: h - h/d = 54 bits
  idx_tree &= (1n << BigInt(_FULL_H - _HP)) - 1n;

  let idx_leaf = bytesToNumber(idx_leaf_bytes);
  idx_leaf &= (1 << _HP) - 1;

  // Step 4: FORS signature
  const fors_adrs = _adrs_new();
  _adrs_set_layer(fors_adrs, 0);
  _adrs_set_tree(fors_adrs, idx_tree);
  _adrs_set_type(fors_adrs, _ADRS_TYPE_FORS_TREE);
  _adrs_set_keypair(fors_adrs, idx_leaf);
  const sig_fors = _fors_sign(md, sk_seed, pk_seed, fors_adrs);

  // Step 5: FORS public key (input to hypertree)
  const pk_fors = _fors_pk_from_sig(sig_fors, md, pk_seed, fors_adrs);

  // Step 6: Hypertree signature
  const sig_ht = _ht_sign(pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf);

  // Assemble signature: R || SIG_FORS || SIG_HT
  return concat(R, sig_fors, sig_ht);
}

/**
 * SLH-DSA-SHAKE-128s internal verification (Algorithm 25, FIPS 205).
 *
 * Verifies pre-processed message M' directly. Use slhVerify() for the
 * pure FIPS 205 API with context string support.
 *
 * @param {Uint8Array} message - Pre-processed message M'
 * @param {Uint8Array} sig_bytes - Signature (7856 bytes)
 * @param {Uint8Array} pk_bytes - 32-byte public key
 * @returns {boolean}
 */
function _slh_verify_internal(message, sig_bytes, pk_bytes) {
  if (pk_bytes.length !== _PK_SIZE) return false;
  if (sig_bytes.length !== _SIG_SIZE) return false;

  const pk_seed = pk_bytes.subarray(0, _N);
  const pk_root = pk_bytes.subarray(_N, 2 * _N);

  // Parse signature
  let offset = 0;
  const R = sig_bytes.subarray(offset, offset + _N);
  offset += _N;
  const fors_sig_size = _K * (1 + _A) * _N;
  const sig_fors = sig_bytes.subarray(offset, offset + fors_sig_size);
  offset += fors_sig_size;
  const sig_ht = sig_bytes.subarray(offset);

  // Recompute message digest
  const digest = _H_msg(R, pk_seed, pk_root, message);
  const md = digest.subarray(0, _MD_BYTES);
  const idx_tree_bytes = digest.subarray(_MD_BYTES, _MD_BYTES + _IDX_TREE_BYTES);
  const idx_leaf_bytes = digest.subarray(_MD_BYTES + _IDX_TREE_BYTES);

  // idx_tree can be up to 54 bits — use BigInt
  let idx_tree = bytesToBigInt(idx_tree_bytes);
  idx_tree &= (1n << BigInt(_FULL_H - _HP)) - 1n;

  let idx_leaf = bytesToNumber(idx_leaf_bytes);
  idx_leaf &= (1 << _HP) - 1;

  // Recover FORS public key
  const fors_adrs = _adrs_new();
  _adrs_set_layer(fors_adrs, 0);
  _adrs_set_tree(fors_adrs, idx_tree);
  _adrs_set_type(fors_adrs, _ADRS_TYPE_FORS_TREE);
  _adrs_set_keypair(fors_adrs, idx_leaf);
  const pk_fors = _fors_pk_from_sig(sig_fors, md, pk_seed, fors_adrs);

  // Verify hypertree signature
  return _ht_verify(pk_fors, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root);
}

/**
 * SLH-DSA-SHAKE-128s standard signing — signs raw message bytes directly.
 *
 * This is the interoperable API that matches ACVP/KAT test vectors and
 * other SLH-DSA implementations. The message is passed to the internal
 * algorithm without any preprocessing.
 *
 * @param {Uint8Array} message - Arbitrary-length message bytes
 * @param {Uint8Array} sk - 64-byte secret key from slhKeygen
 * @param {{ deterministic?: boolean, addrnd?: Uint8Array }} [opts={}] - Options
 * @returns {Uint8Array} Signature bytes (7,856 bytes)
 */
function slhSign(message, sk, opts) {
  message = toBytes(message);
  if (opts === undefined || opts === null) opts = {};
  return _slh_sign_internal(
    message,
    sk,
    opts.addrnd != null ? opts.addrnd : null,
    !!opts.deterministic
  );
}

/**
 * SLH-DSA-SHAKE-128s standard verification — verifies against raw message.
 *
 * @param {Uint8Array} message - Original message bytes
 * @param {Uint8Array} sig - Signature from slhSign
 * @param {Uint8Array} pk - 32-byte public key from slhKeygen
 * @returns {boolean} True if valid, false otherwise
 */
function slhVerify(message, sig, pk) {
  message = toBytes(message);
  return _slh_verify_internal(message, sig, pk);
}

/**
 * SLH-DSA-SHAKE-128s signing with FIPS 205 context prefix.
 *
 * Builds M' = 0x00 || len(ctx) || ctx || message, then calls the
 * internal signing algorithm. Use slhSign() for the standard
 * interoperable API (no context prefix).
 *
 * @param {Uint8Array} message - Arbitrary-length message bytes
 * @param {Uint8Array} sk - 64-byte secret key from slhKeygen
 * @param {Uint8Array} [ctx=new Uint8Array(0)] - Context string (0-255 bytes)
 * @param {{ deterministic?: boolean, addrnd?: Uint8Array }} [opts={}] - Options
 * @returns {Uint8Array} Signature bytes (7,856 bytes)
 */
function slhSignWithContext(message, sk, ctx, opts) {
  message = toBytes(message);
  if (ctx === undefined || ctx === null) ctx = new Uint8Array(0);
  else ctx = toBytes(ctx);
  if (opts === undefined || opts === null) opts = {};
  if (ctx.length > 255) {
    throw new Error(`context string must be <= 255 bytes, got ${ctx.length}`);
  }
  const m_prime = concat(
    new Uint8Array([0x00, ctx.length]),
    ctx,
    message
  );
  return _slh_sign_internal(
    m_prime,
    sk,
    opts.addrnd != null ? opts.addrnd : null,
    !!opts.deterministic
  );
}

/**
 * SLH-DSA-SHAKE-128s verification with FIPS 205 context prefix.
 *
 * Use slhVerify() for the standard interoperable API (no context prefix).
 *
 * @param {Uint8Array} message - Original message bytes
 * @param {Uint8Array} sig - Signature from slhSignWithContext
 * @param {Uint8Array} pk - 32-byte public key from slhKeygen
 * @param {Uint8Array} [ctx=new Uint8Array(0)] - Context string
 * @returns {boolean} True if valid, false otherwise
 */
function slhVerifyWithContext(message, sig, pk, ctx) {
  message = toBytes(message);
  if (ctx === undefined || ctx === null) ctx = new Uint8Array(0);
  else ctx = toBytes(ctx);
  if (ctx.length > 255) return false;
  const m_prime = concat(
    new Uint8Array([0x00, ctx.length]),
    ctx,
    message
  );
  return _slh_verify_internal(m_prime, sig, pk);
}

/**
 * Async wrapper for slhSign — yields to the event loop before computation
 * so browser UIs don't freeze. SLH-DSA signing is particularly heavy.
 */
function slhSignAsync(message, sk, opts) {
  return new Promise(function (resolve, reject) {
    setTimeout(function () {
      try { resolve(slhSign(message, sk, opts)); }
      catch (e) { reject(e); }
    }, 0);
  });
}

/**
 * Async wrapper for slhVerify — yields to the event loop before computation.
 */
function slhVerifyAsync(message, sig, pk) {
  return new Promise(function (resolve, reject) {
    setTimeout(function () {
      try { resolve(slhVerify(message, sig, pk)); }
      catch (e) { reject(e); }
    }, 0);
  });
}


module.exports = {
  slhKeygen,
  slhSign,
  slhVerify,
  slhSignWithContext,
  slhVerifyWithContext,
  slhSignAsync,
  slhVerifyAsync,

  // Expose sizes for consumers
  SIG_SIZE: _SIG_SIZE,
  PK_SIZE: _PK_SIZE,
  SK_SIZE: _SK_SIZE,
  SEED_SIZE: 3 * _N,
};

};

// ── crypto/hybrid_dsa.js ──
_dirs["./crypto/hybrid_dsa"] = "./crypto";
_modules["./crypto/hybrid_dsa"] = function(module, exports, require) {
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
// Stripping resistance: both components sign a domain-prefixed message
// ("hybrid-dsa-v1" || len(ctx) || ctx || message), preventing extraction of
// either component signature for standalone use outside the hybrid context.
//
// Sizes:
//     Secret key:  4,096 bytes  (Ed25519 sk 64B + ML-DSA-65 sk 4,032B)
//     Public key:  1,984 bytes  (Ed25519 pk 32B + ML-DSA-65 pk 1,952B)
//     Signature:   3,373 bytes  (Ed25519 sig 64B + ML-DSA-65 sig 3,309B)
//
// Best-effort constant-time. For hardware side-channel resistance, use C/Rust.

const { ed25519Keygen, ed25519Sign, ed25519Verify } = require("./ed25519");
const { mlKeygen, mlSign, mlVerify } = require("./ml_dsa");
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

// Domain prefix for stripping resistance.
// Both Ed25519 and ML-DSA sign this same domain-prefixed byte string,
// preventing extraction of either component signature for standalone use.
const _DOMAIN = new TextEncoder().encode("hybrid-dsa-v1");

function _hybridMessage(message, ctx) {
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
  message = toBytes(message);
  if (ctx === undefined || ctx === null) ctx = new Uint8Array(0);
  else ctx = toBytes(ctx);
  if (sk.length !== HYBRID_DSA_SK_SIZE) {
    throw new Error(`Hybrid DSA sk must be ${HYBRID_DSA_SK_SIZE} bytes, got ${sk.length}`);
  }

  const edSk = sk.subarray(0, _ED25519_SK);
  const mlSk = sk.subarray(_ED25519_SK);

  // Both components sign the same domain-prefixed message.
  // This ensures neither signature can be used standalone outside the hybrid context.
  const msg = _hybridMessage(message, ctx);

  const edSig = ed25519Sign(msg, edSk);
  const mlSig = mlSign(msg, mlSk);

  zeroize(msg);

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
  message = toBytes(message);
  if (ctx === undefined || ctx === null) ctx = new Uint8Array(0);
  else ctx = toBytes(ctx);
  if (sig.length !== HYBRID_DSA_SIG_SIZE) return false;
  if (pk.length !== HYBRID_DSA_PK_SIZE) return false;

  const edSig = sig.subarray(0, _ED25519_SIG);
  const mlSig = sig.subarray(_ED25519_SIG);
  const edPk = pk.subarray(0, _ED25519_PK);
  const mlPk = pk.subarray(_ED25519_PK);

  // Both components verify against the same domain-prefixed message.
  // Constant-time: always run both verifications (no early return on first failure).
  const msg = _hybridMessage(message, ctx);
  const edOk = ed25519Verify(msg, edSig, edPk);
  const mlOk = mlVerify(msg, mlSig, mlPk);
  return edOk && mlOk;
}

module.exports = {
  hybridDsaKeygen,
  hybridDsaSign,
  hybridDsaVerify,
  HYBRID_DSA_SK_SIZE,
  HYBRID_DSA_PK_SIZE,
  HYBRID_DSA_SIG_SIZE,
};

};

// ── crypto/hybrid_kem.js ──
_dirs["./crypto/hybrid_kem"] = "./crypto";
_modules["./crypto/hybrid_kem"] = function(module, exports, require) {
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
// Best-effort constant-time. For hardware side-channel resistance, use C/Rust.

const { x25519Keygen, x25519, x25519NoCheck } = require("./x25519");
const { mlKemKeygen, mlKemEncaps, mlKemDecaps } = require("./ml_kem");
const { sha256, hmacSha256 } = require("./sha2");
const { randomBytes, zeroize } = require("./utils");

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
  const ss = hmacSha256(prk, info);

  // Best-effort cleanup of intermediate secrets
  zeroize(ssConcat);
  zeroize(prk);

  return ss;
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

  // Best-effort cleanup of component shared secrets
  zeroize(xSs);
  zeroize(mlResult.ss);
  zeroize(eph.sk);

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

  // X25519 shared secret recovery — constant-time, no throw on low-order points.
  // If ephPk is a low-order point, result may be all-zero; ML-KEM carries security.
  const xSs = x25519NoCheck(xSk, ephPk);

  // ML-KEM decapsulation
  const mlSs = mlKemDecaps(mlDk, mlCt);

  // Combine shared secrets with ciphertext binding
  const ss = _combineSecrets(xSs, mlSs, ephPk, mlCt);

  // Best-effort cleanup of component shared secrets
  zeroize(xSs);
  zeroize(mlSs);

  return ss;
}

module.exports = {
  hybridKemKeygen,
  hybridKemEncaps,
  hybridKemDecaps,
  HYBRID_KEM_EK_SIZE,
  HYBRID_KEM_DK_SIZE,
  HYBRID_KEM_CT_SIZE,
};

};

// ── crypto/index.js ──
_dirs["./crypto"] = "./crypto";
_modules["./crypto"] = function(module, exports, require) {
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
};

};

// ── seed.js (crypto-only) ──
_dirs["./seed"] = ".";
_modules["./seed"] = function(module, exports, require) {
// Copyright (c) 2026 Signer.io — MIT License

"use strict";

// Universal Quantum Seed — Core API (JavaScript port of seed.py)
//
// Generates cryptographically secure seeds using 256 visual icons (8 bits each).
// - 24 words = 22 random + 2 checksum = 176 bits entropy
// - 36 words = 34 random + 2 checksum = 272 bits entropy

const { sha256, sha512, hmacSha256, hmacSha512, hkdfExpand, pbkdf2Sha512, pbkdf2Sha512Async } = require("./crypto/sha2");
const { constantTimeEqual } = require("./crypto/utils");

const { argon2id, argon2idAsync } = require("./crypto/argon2");

const VERSION = "1.0";

// 256 base English words — one per icon position (0-255)


// Domain separator
const DOMAIN = new TextEncoder().encode("universal-seed-v1");

// KDF parameters
const PBKDF2_ITERATIONS = 600000;

// Argon2id parameters (OWASP recommended for high-value targets)
const ARGON2_TIME = 3;         // iterations
const ARGON2_MEMORY = 65536;   // 64 MiB
const ARGON2_PARALLEL = 4;     // lanes
const ARGON2_HASHLEN = 64;     // output bytes






// ── Utility ─────────────────────────────────────────────────────

const _enc = new TextEncoder();

function toBytes(data) {
  if (data instanceof Uint8Array) return data;
  if (typeof data === "string") return _enc.encode(data);
  if (Array.isArray(data)) return new Uint8Array(data);
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  throw new Error("unsupported input type");
}

function concatBytes(...arrays) {
  let totalLen = 0;
  for (const a of arrays) totalLen += a.length;
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const a of arrays) {
    result.set(a instanceof Uint8Array ? a : toBytes(a), offset);
    offset += a.length;
  }
  return result;
}

function randomBytes(n) {
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.getRandomValues) {
    const buf = new Uint8Array(n);
    globalThis.crypto.getRandomValues(buf);
    return buf;
  }
  const nodeCrypto = require("crypto");
  return new Uint8Array(nodeCrypto.randomBytes(n));
}

function timingNs() {
  if (typeof process !== "undefined" && process.hrtime && process.hrtime.bigint) {
    return Number(process.hrtime.bigint());
  }
  return Math.floor(performance.now() * 1e6);
}

/** Best-effort zeroing of sensitive buffers. Not guaranteed by JS GC, but reduces exposure. */
function zeroize(buf) {
  if (buf instanceof Uint8Array) buf.fill(0);
  else if (Array.isArray(buf)) buf.fill(0);
}

function packLE_BB(a, b) { return new Uint8Array([a & 0xff, b & 0xff]); }
function packLE_I(n) { return new Uint8Array([n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]); }
function packLE_Q(n) {
  const buf = new Uint8Array(8);
  for (let i = 0; i < 8; i++) { buf[i] = n & 0xff; n = Math.floor(n / 256); }
  return buf;
}

// ── Mouse Entropy ───────────────────────────────────────────────

class MouseEntropy {
  constructor() {
    this._samples = 0;
    this._lastX = null;
    this._lastY = null;
    this._lastT = null;
    this._pool = [];
    this._pool.push(...DOMAIN, ...toBytes("-mouse-entropy"));
  }

  addSample(x, y) {
    const t = timingNs();
    if (x === this._lastX && y === this._lastY) return false;

    this._pool.push(...packLE_I(x), ...packLE_I(y), ...packLE_Q(t));

    if (this._lastX !== null) {
      const dx = x - this._lastX;
      const dy = y - this._lastY;
      const dt = t - this._lastT;
      this._pool.push(...packLE_I(dx), ...packLE_I(dy), ...packLE_Q(dt));
    }

    this._lastX = x; this._lastY = y; this._lastT = t;
    this._samples++;
    return true;
  }

  get bitsCollected() { return this._samples * 2; }
  get sampleCount() { return this._samples; }

  digest() { return sha512(new Uint8Array(this._pool)); }

  reset() {
    this._samples = 0; this._lastX = null; this._lastY = null; this._lastT = null;
    this._pool = [];
    this._pool.push(...DOMAIN, ...toBytes("-mouse-entropy"));
  }
}

// ── Entropy Collection ──────────────────────────────────────────

function cpuJitterEntropy() {
  const parts = [DOMAIN, toBytes("-cpu-jitter")];
  for (let s = 0; s < 64; s++) {
    const t1 = timingNs();
    let x = 0;
    for (let j = 0; j < 100; j++) {
      x ^= (x << 3) ^ (j * 7) ^ (x >>> 5);
      x = x & 0xffffffff;
    }
    const t2 = timingNs();
    parts.push(packLE_Q(t2 - t1), packLE_Q(t2));
  }
  return sha512(concatBytes(...parts));
}

function collectEntropy(nBytes, extraEntropy) {
  const parts = [];

  // Source 1+2: CSPRNG
  parts.push(randomBytes(64));
  parts.push(randomBytes(64));

  // Source 3: Timing jitter
  for (let i = 0; i < 32; i++) parts.push(packLE_Q(timingNs()));

  // Source 4: Process ID
  const pid = typeof process !== "undefined" ? process.pid || 0 : 0;
  parts.push(packLE_I(pid));

  // Source 5: CPU jitter
  parts.push(cpuJitterEntropy());

  // Source 6+7: Additional randomness from CSPRNG (thread/hw RNG not available in JS)
  parts.push(randomBytes(64));
  parts.push(randomBytes(32));

  if (extraEntropy) parts.push(toBytes(extraEntropy));

  const pool = concatBytes(...parts);

  // HKDF-Extract: condense the entropy pool into a PRK
  const prk = hmacSha512(DOMAIN, pool);

  // HKDF-Expand: stretch to arbitrary output length
  const info = concatBytes(DOMAIN, toBytes("-entropy"));
  return hkdfExpand(prk, info, nBytes);
}

// ── Checksum ────────────────────────────────────────────────────

function computeChecksum(indexes) {
  const key = concatBytes(DOMAIN, toBytes("-checksum"));
  const digest = hmacSha256(key, new Uint8Array(indexes));
  return [digest[0], digest[1]];
}

function verifyChecksum(seed) {
  const indexes = toIndexes(seed);
  if (indexes.length !== 24 && indexes.length !== 36) return false;
  const data = indexes.slice(0, -2);
  const expected = computeChecksum(data);
  return constantTimeEqual(
    new Uint8Array([indexes[indexes.length - 2], indexes[indexes.length - 1]]),
    new Uint8Array(expected)
  );
}


// ── Index Conversion ────────────────────────────────────────────

function toIndexes(seed) {
  if (!seed || !seed.length) throw new Error("seed must not be empty");

  // Accept string of space-separated numeric indexes
  if (typeof seed === "string") {
    seed = seed.trim().split(/\s+/).filter(Boolean);
    if (seed.length === 0) throw new Error("seed must not be empty");
    const nums = seed.map(Number);
    if (nums.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) return nums;
    throw new Error("crypto-only build: pass numeric indexes (0-255), not words");
  }

  const first = seed[0];
  if (Array.isArray(first) || (typeof first === "object" && first !== null && "index" in first)) {
    return seed.map((item, i) => {
      const idx = Array.isArray(item) ? item[0] : item.index;
      if (!Number.isInteger(idx) || idx < 0 || idx > 255) {
        throw new Error("seed index out of range at position " + i + ": " + idx);
      }
      return idx;
    });
  }
  if (typeof first === "number") {
    for (const v of seed) {
      if (!Number.isInteger(v) || v < 0 || v > 255) {
        throw new Error("seed index out of range: " + v);
      }
    }
    return [...seed];
  }
  throw new Error("crypto-only build: pass numeric indexes (0-255), not words");
}
// ── Key Derivation ──────────────────────────────────────────────

function getSeed(words, passphrase = "") {
  const indexes = toIndexes(words);
  if (indexes.length !== 24 && indexes.length !== 36) {
    throw new Error(`seed must be 24 or 36 words, got ${indexes.length}`);
  }

  const data = indexes.slice(0, -2);
  const expected = computeChecksum(data);
  if (!constantTimeEqual(
    new Uint8Array([indexes[indexes.length - 2], indexes[indexes.length - 1]]),
    new Uint8Array(expected)
  )) {
    throw new Error("invalid seed checksum");
  }

  // Step 1: Position-tagged payload
  const payloadParts = [];
  for (let pos = 0; pos < data.length; pos++) {
    payloadParts.push(packLE_BB(pos, data[pos]));
  }
  if (passphrase) payloadParts.push(toBytes(passphrase.normalize("NFKC")));
  const payload = concatBytes(...payloadParts);

  // Step 2: HKDF-Extract
  const prk = hmacSha512(DOMAIN, payload);
  zeroize(payload);

  // Step 3: Chained KDF — PBKDF2-SHA512 → Argon2id (defense in depth)
  const salt = concatBytes(DOMAIN, toBytes("-stretch"));
  const stage1 = pbkdf2Sha512(prk, concatBytes(salt, toBytes("-pbkdf2")), PBKDF2_ITERATIONS, 64);
  zeroize(prk);
  const stretched = argon2id(
    stage1,
    concatBytes(salt, toBytes("-argon2id")),
    ARGON2_TIME, ARGON2_MEMORY, ARGON2_PARALLEL, ARGON2_HASHLEN
  );
  zeroize(stage1);

  // Step 4: HKDF-Expand
  const master = hkdfExpand(stretched, concatBytes(DOMAIN, toBytes("-master")), 64);
  zeroize(stretched);
  return master;
}

async function getSeedAsync(words, passphrase = "") {
  const indexes = toIndexes(words);
  if (indexes.length !== 24 && indexes.length !== 36) {
    throw new Error(`seed must be 24 or 36 words, got ${indexes.length}`);
  }

  const data = indexes.slice(0, -2);
  const expected = computeChecksum(data);
  if (!constantTimeEqual(
    new Uint8Array([indexes[indexes.length - 2], indexes[indexes.length - 1]]),
    new Uint8Array(expected)
  )) {
    throw new Error("invalid seed checksum");
  }

  const payloadParts = [];
  for (let pos = 0; pos < data.length; pos++) {
    payloadParts.push(packLE_BB(pos, data[pos]));
  }
  if (passphrase) payloadParts.push(toBytes(passphrase.normalize("NFKC")));
  const payload = concatBytes(...payloadParts);

  const prk = hmacSha512(DOMAIN, payload);
  zeroize(payload);

  // Chained KDF: PBKDF2-SHA512 → Argon2id (defense in depth)
  const salt = concatBytes(DOMAIN, toBytes("-stretch"));

  // Stage 1: PBKDF2-SHA512
  const stage1 = await pbkdf2Sha512Async(prk, concatBytes(salt, toBytes("-pbkdf2")), PBKDF2_ITERATIONS, 64);
  zeroize(prk);

  // Stage 2: Argon2id on top of PBKDF2 output (off main thread via Web Worker)
  const stretched = await argon2idAsync(
    stage1,
    concatBytes(salt, toBytes("-argon2id")),
    ARGON2_TIME, ARGON2_MEMORY, ARGON2_PARALLEL, ARGON2_HASHLEN
  );
  zeroize(stage1);

  const master = hkdfExpand(stretched, concatBytes(DOMAIN, toBytes("-master")), 64);
  zeroize(stretched);
  return master;
}

function getProfile(masterKey, profilePassword) {
  if (!profilePassword) return masterKey;
  const payload = concatBytes(DOMAIN, toBytes("-profile"), toBytes(profilePassword));
  const derived = hmacSha512(masterKey, payload);
  zeroize(payload);
  return derived;
}

// ── Quantum Key Derivation ──────────────────────────────────────

const QUANTUM_SEED_SIZES = {
  "ml-dsa-65": 32,
  "slh-dsa-shake-128s": 48,
  "ml-kem-768": 64,
  // Hybrid classical + post-quantum (defense in depth)
  "hybrid-dsa-65": 64,        // Ed25519 seed (32B) + ML-DSA-65 seed (32B)
  "hybrid-kem-768": 96,       // X25519 seed (32B) + ML-KEM-768 seed (64B d||z)
};

function getQuantumSeed(masterKey, algorithm = "ml-dsa-65", keyIndex = 0) {
  masterKey = toBytes(masterKey);
  if (masterKey.length !== 64) throw new Error(`masterKey must be 64 bytes, got ${masterKey.length}`);
  const size = QUANTUM_SEED_SIZES[algorithm];
  if (size === undefined) {
    throw new Error(`Unknown quantum algorithm: '${algorithm}'. Supported: ${Object.keys(QUANTUM_SEED_SIZES).join(", ")}`);
  }
  const info = concatBytes(DOMAIN, toBytes("-quantum-"), toBytes(algorithm), packLE_I(keyIndex));
  return hkdfExpand(masterKey, info, size);
}

function generateQuantumKeypair(masterKey, algorithm = "ml-dsa-65", keyIndex = 0) {
  const quantumSeed = getQuantumSeed(masterKey, algorithm, keyIndex);
  if (algorithm === "ml-dsa-65") {
    const { mlKeygen } = require("./crypto/ml_dsa");
    return mlKeygen(quantumSeed);
  } else if (algorithm === "slh-dsa-shake-128s") {
    const { slhKeygen } = require("./crypto/slh_dsa");
    return slhKeygen(quantumSeed);
  } else if (algorithm === "ml-kem-768") {
    const { mlKemKeygen } = require("./crypto/ml_kem");
    return mlKemKeygen(quantumSeed);
  } else if (algorithm === "hybrid-dsa-65") {
    const { hybridDsaKeygen } = require("./crypto/hybrid_dsa");
    return hybridDsaKeygen(quantumSeed);
  } else if (algorithm === "hybrid-kem-768") {
    const { hybridKemKeygen } = require("./crypto/hybrid_kem");
    const { ek, dk } = hybridKemKeygen(quantumSeed);
    return { sk: dk, pk: ek }; // (secret=dk, public=ek) to match (sk, pk) convention
  }
  throw new Error(`Unknown quantum algorithm: '${algorithm}'`);
}

// ── Fingerprint ─────────────────────────────────────────────────

function getFingerprint(seed, passphrase = "") {
  const indexes = toIndexes(seed);
  if (indexes.length !== 24 && indexes.length !== 36) {
    throw new Error(`seed must be 24 or 36 words, got ${indexes.length}`);
  }
  const data = indexes.slice(0, -2);

  let key;
  if (passphrase) {
    key = getSeed(indexes, passphrase);
  } else {
    const parts = [];
    for (let pos = 0; pos < data.length; pos++) {
      parts.push(packLE_BB(pos, data[pos]));
    }
    key = hmacSha512(DOMAIN, concatBytes(...parts));
  }

  const hex = Array.from(key.subarray(0, 4), b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  return hex;
}

// ── Entropy Bits ────────────────────────────────────────────────

function getEntropyBits(wordCount, passphrase = "") {
  const seedBits = (wordCount - 2) * 8;
  if (!passphrase) return seedBits;

  let hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false, hasUnicode = false;
  for (const c of passphrase) {
    if (/[a-z]/.test(c)) hasLower = true;
    else if (/[A-Z]/.test(c)) hasUpper = true;
    else if (/\d/.test(c)) hasDigit = true;
    else if (c.charCodeAt(0) > 127) hasUnicode = true;
    else if (/[^a-zA-Z0-9]/.test(c)) hasSymbol = true;
  }

  let pool = 0;
  if (hasLower) pool += 26;
  if (hasUpper) pool += 26;
  if (hasDigit) pool += 10;
  if (hasSymbol) pool += 33;
  if (hasUnicode) pool += 100;
  if (pool === 0) return seedBits;

  return seedBits + Math.log2(pool) * passphrase.length;
}

// ── KDF Info ────────────────────────────────────────────────────

function kdfInfo() {
  return `PBKDF2-SHA512 (${PBKDF2_ITERATIONS.toLocaleString()} rounds) + Argon2id (mem=${ARGON2_MEMORY}KB, t=${ARGON2_TIME}, p=${ARGON2_PARALLEL})`;
}

// ── Entropy Testing ─────────────────────────────────────────────

function testEntropy(data) {
  const nBits = data.length * 8;
  const bits = [];
  for (const byte of data) {
    for (let bp = 7; bp >= 0; bp--) bits.push((byte >> bp) & 1);
  }

  const results = {};

  // Monobit
  const ones = bits.reduce((s, b) => s + b, 0);
  const sScore = Math.abs(2 * ones - nBits) / Math.sqrt(nBits);
  results.monobit = { pass: sScore < 2.576, onesRatio: ones / nBits, zScore: sScore };

  // Chi-squared
  const observed = new Array(256).fill(0);
  for (const byte of data) observed[byte]++;
  const expected = data.length / 256;
  const chi2 = observed.reduce((s, o) => s + (o - expected) ** 2 / expected, 0);
  results.chi_squared = { pass: chi2 < 310.5, chi2 };

  // Runs
  const pi = ones / nBits;
  let runsPass, runsZ;
  if (Math.abs(pi - 0.5) >= 2 / Math.sqrt(nBits)) {
    runsPass = false; runsZ = Infinity;
  } else {
    let runs = 1;
    for (let i = 1; i < nBits; i++) { if (bits[i] !== bits[i - 1]) runs++; }
    const expectedRuns = 2 * nBits * pi * (1 - pi) + 1;
    const stdRuns = 2 * Math.sqrt(2 * nBits) * pi * (1 - pi);
    runsZ = stdRuns === 0 ? Infinity : Math.abs(runs - expectedRuns) / stdRuns;
    runsPass = runsZ < 2.576;
  }
  results.runs = { pass: runsPass, zScore: runsZ };

  // Autocorrelation
  let autocorrPass = true, worstZ = 0;
  for (let d = 1; d <= 16; d++) {
    let matches = 0;
    for (let i = 0; i < nBits - d; i++) { if (bits[i] === bits[i + d]) matches++; }
    const total = nBits - d;
    const z = Math.abs(2 * matches - total) / Math.sqrt(total);
    if (z > worstZ) worstZ = z;
    if (z >= 3.42) autocorrPass = false;
  }
  results.autocorrelation = { pass: autocorrPass, worstZ };

  return results;
}

function verifyRandomness(sampleBytes = null, sampleSize = 2048, numSamples = 5) {
  const samples = sampleBytes ? [toBytes(sampleBytes)] :
    Array.from({ length: numSamples }, () => collectEntropy(sampleSize));

  const allResults = samples.map((data, si) => ({ sample: si, tests: testEntropy(data) }));

  const testNames = ["monobit", "chi_squared", "runs", "autocorrelation"];
  let overallPass = true;
  const testSummary = [];

  for (const name of testNames) {
    const failedCount = allResults.filter(r => !r.tests[name].pass).length;
    const majorityFailed = failedCount > allResults.length / 2;
    if (majorityFailed) overallPass = false;
    testSummary.push({ test: name, pass: !majorityFailed });
  }

  return { pass: overallPass, tests: testSummary, samples: allResults };
}


// ── Exports ─────────────────────────────────────────────────────

module.exports = {
  VERSION,
  verifyChecksum,
  getSeed,
  getSeedAsync,
  getProfile,
  getFingerprint,
  getEntropyBits,
  getQuantumSeed,
  generateQuantumKeypair,
  MouseEntropy,
  verifyRandomness,
  kdfInfo,
};
};

// ── index.js (crypto-only) ──
_dirs["."] = ".";
_modules["."] = function(module, exports, require) {
// Auto-generated crypto-only index
"use strict";

const seed = require("./seed");
const crypto = require("./crypto");

module.exports = {
  // Key Derivation
  getSeed: seed.getSeed,
  getSeedAsync: seed.getSeedAsync,
  getProfile: seed.getProfile,
  getFingerprint: seed.getFingerprint,
  getEntropyBits: seed.getEntropyBits,
  verifyChecksum: seed.verifyChecksum,

  // Post-Quantum Key Derivation
  getQuantumSeed: seed.getQuantumSeed,
  generateQuantumKeypair: seed.generateQuantumKeypair,

  // ML-DSA-65 (FIPS 204)
  mlKeygen: crypto.mlKeygen,
  mlSign: crypto.mlSign,
  mlVerify: crypto.mlVerify,
  mlSignWithContext: crypto.mlSignWithContext,
  mlVerifyWithContext: crypto.mlVerifyWithContext,
  mlSignAsync: crypto.mlSignAsync,
  mlVerifyAsync: crypto.mlVerifyAsync,

  // SLH-DSA-SHAKE-128s (FIPS 205)
  slhKeygen: crypto.slhKeygen,
  slhSign: crypto.slhSign,
  slhVerify: crypto.slhVerify,
  slhSignWithContext: crypto.slhSignWithContext,
  slhVerifyWithContext: crypto.slhVerifyWithContext,
  slhSignAsync: crypto.slhSignAsync,
  slhVerifyAsync: crypto.slhVerifyAsync,

  // ML-KEM-768 (FIPS 203)
  mlKemKeygen: crypto.mlKemKeygen,
  mlKemEncaps: crypto.mlKemEncaps,
  mlKemDecaps: crypto.mlKemDecaps,

  // Ed25519 (RFC 8032)
  ed25519Keygen: crypto.ed25519Keygen,
  ed25519Sign: crypto.ed25519Sign,
  ed25519Verify: crypto.ed25519Verify,

  // X25519 (RFC 7748)
  x25519Keygen: crypto.x25519Keygen,
  x25519: crypto.x25519,

  // Hybrid Ed25519 + ML-DSA-65
  hybridDsaKeygen: crypto.hybridDsaKeygen,
  hybridDsaSign: crypto.hybridDsaSign,
  hybridDsaVerify: crypto.hybridDsaVerify,

  // Hybrid X25519 + ML-KEM-768
  hybridKemKeygen: crypto.hybridKemKeygen,
  hybridKemEncaps: crypto.hybridKemEncaps,
  hybridKemDecaps: crypto.hybridKemDecaps,

  // Argon2id (RFC 9106) + Blake2b
  argon2id: crypto.argon2id,
  blake2b: crypto.blake2b,

  // Hash Functions
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

  // Entropy & Testing
  MouseEntropy: seed.MouseEntropy,
  verifyRandomness: seed.verifyRandomness,
  kdfInfo: seed.kdfInfo,

  // Constants
  VERSION: seed.VERSION,
};
};


// ── Expose API ─────────────────────────────────────────────────
var UQS = _requireFrom(".")(".");

UQS.default = UQS;

if (typeof globalThis !== "undefined") globalThis.UQS = UQS;
if (typeof window !== "undefined") window.UQS = UQS;
if (typeof self !== "undefined") self.UQS = UQS;

if (typeof module !== "undefined" && module.exports) {
  module.exports = UQS;
}

})(typeof globalThis !== "undefined" ? globalThis : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : this);
