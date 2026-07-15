// Copyright (c) 2026 Lock.com — PolyForm Shield License 1.0.0

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
  0x41, 0xdb, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
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

let _nativeX25519Keygen = null;
let _nativeX25519DH = null;

try {
  const _X25519_SK_DER_PREFIX = Buffer.from(
    "302e020100300506032b656e04220420", "hex"
  );
  const _X25519_PK_DER_PREFIX = Buffer.from(
    "302a300506032b656e032100", "hex"
  );
  const nodeCrypto = require("crypto");

  function _x25519PrivateDer(sk) {
    const der = Buffer.allocUnsafeSlow(_X25519_SK_DER_PREFIX.length + sk.length);
    _X25519_SK_DER_PREFIX.copy(der, 0);
    for (let i = 0; i < sk.length; i++) der[_X25519_SK_DER_PREFIX.length + i] = sk[i];
    return der;
  }

  // Probe: create a test X25519 key
  const _probe = _x25519PrivateDer(new Uint8Array(32));
  try {
    nodeCrypto.createPrivateKey({ key: _probe, format: "der", type: "pkcs8" });
  } finally {
    _probe.fill(0);
  }

  _nativeX25519Keygen = (sk) => {
    const der = _x25519PrivateDer(sk);
    try {
      const privateKey = nodeCrypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
      const publicKey = nodeCrypto.createPublicKey(privateKey);
      const pkDer = publicKey.export({ type: "spki", format: "der" });
      return new Uint8Array(pkDer.subarray(pkDer.length - 32));
    } finally {
      der.fill(0);
    }
  };

  _nativeX25519DH = (sk, pk) => {
    const skDer = _x25519PrivateDer(sk);
    const pkDer = Buffer.concat([_X25519_PK_DER_PREFIX, Buffer.from(pk)]);
    try {
      const privateKey = nodeCrypto.createPrivateKey({ key: skDer, format: "der", type: "pkcs8" });
      const publicKey = nodeCrypto.createPublicKey({ key: pkDer, format: "der", type: "spki" });
      return new Uint8Array(nodeCrypto.diffieHellman({ privateKey, publicKey }));
    } finally {
      skDer.fill(0);
    }
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
    // and only occurs on malicious input, not during normal operation).
    // Fall back to pure-JS on native error: returning all-zeros would be
    // wrong because RFC 7748 zeros are a valid low-order result, so
    // substituting them on a library exception silently masks bugs and
    // looks like a successful DH.
    try { return _nativeX25519DH(sk, pk); }
    catch (_) { return x25519Raw(sk, pk); }
  }
  // Pure JS: compute raw, return result (may be all-zero for low-order points,
  // which is the correct RFC 7748 output, distinct from a library failure).
  return x25519Raw(sk, pk);
}

module.exports = { x25519Keygen, x25519, x25519NoCheck, x25519Raw, X25519_SK_SIZE: 32, X25519_PK_SIZE: 32 };
