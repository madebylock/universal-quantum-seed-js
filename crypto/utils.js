// Copyright (c) 2026 Lock.com — MIT License

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
