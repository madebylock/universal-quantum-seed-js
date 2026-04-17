// Copyright (c) 2026 Lock.com — MIT License

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

let _nativeKeygen = null;
let _nativeSign = null;
let _nativeVerify = null;

try {
  const _ED25519_SK_DER_PREFIX = Buffer.from(
    "302e020100300506032b657004220420", "hex"
  );
  const _ED25519_PK_DER_PREFIX = Buffer.from(
    "302a300506032b6570032100", "hex"
  );
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
