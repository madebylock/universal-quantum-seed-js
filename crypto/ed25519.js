// Copyright (c) 2026 Signer.io — MIT License

"use strict";

// Ed25519 digital signatures (RFC 8032).
//
// Pure JavaScript implementation using BigInt for field arithmetic.
// Extended coordinates (X, Y, Z, T) where x=X/Z, y=Y/Z, X*Y=Z*T.
//
// Sizes:
//     Secret key:  64 bytes (seed || public_key)
//     Public key:  32 bytes (compressed Edwards point)
//     Signature:   64 bytes (R || S)
//
// NOT constant-time. For side-channel-resistant deployments, use C/Rust.

const { sha512 } = require("./sha2");

// ── Field & Curve Constants ─────────────────────────────────────

const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n; // Group order
const D = (-121665n * modInv(121666n, P) % P + P) % P;

// Base point G (RFC 8032): y = 4/5
const Gy = 4n * modInv(5n, P) % P;
const Gx_sq = ((Gy * Gy % P - 1n + P) * modInv((D * Gy % P * Gy % P + 1n) % P, P)) % P;
let Gx = modPow(Gx_sq, (P + 3n) / 8n, P);
if ((Gx * Gx - Gx_sq) % P !== 0n) {
  Gx = (Gx * modPow(2n, (P - 1n) / 4n, P)) % P;
}
if (Gx & 1n) Gx = (P - Gx) % P;

const G = [Gx % P, Gy % P, 1n, (Gx * Gy) % P];
const ZERO = [0n, 1n, 1n, 0n];

// ── Field Helpers ───────────────────────────────────────────────

function modInv(a, m) {
  return modPow(((a % m) + m) % m, m - 2n, m);
}

function modPow(base, exp, mod) {
  base = ((base % mod) + mod) % mod;
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) result = result * base % mod;
    exp >>= 1n;
    base = base * base % mod;
  }
  return result;
}

// ── Point Arithmetic ────────────────────────────────────────────

function pointAdd(P1, Q) {
  if (P1[0] === 0n && P1[1] === 1n && P1[2] === 1n && P1[3] === 0n) return Q;
  if (Q[0] === 0n && Q[1] === 1n && Q[2] === 1n && Q[3] === 0n) return P1;

  const [X1, Y1, Z1, T1] = P1;
  const [X2, Y2, Z2, T2] = Q;

  const A = (Y1 - X1 + P) * ((Y2 - X2 + P) % P) % P;
  const B = (Y1 + X1) % P * ((Y2 + X2) % P) % P;
  const C = 2n * D * T1 % P * T2 % P;
  const DD = 2n * Z1 * Z2 % P;
  const E = (B - A + P) % P;
  const F = (DD - C + P) % P;
  const GG = (DD + C) % P;
  const H = (B + A) % P;

  return [E * F % P, GG * H % P, F * GG % P, E * H % P];
}

function pointDouble(P1) {
  if (P1[0] === 0n && P1[1] === 1n && P1[2] === 1n && P1[3] === 0n) return ZERO;

  const [X1, Y1, Z1] = P1;

  const A = X1 * X1 % P;
  const B = Y1 * Y1 % P;
  const C = 2n * Z1 * Z1 % P;
  const DD = (P - A) % P;
  const E = ((X1 + Y1) * (X1 + Y1) % P - A - B + 2n * P) % P;
  const GG = (DD + B) % P;
  const F = (GG - C + P) % P;
  const H = (DD - B + P) % P;

  return [E * F % P, GG * H % P, F * GG % P, E * H % P];
}

function pointNegate(P1) {
  return [(P - P1[0]) % P, P1[1], P1[2], (P - P1[3]) % P];
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

function scalarMultBase(k) {
  if (k === 0n) return ZERO;
  let negate = false;
  if (k < 0n) { k = -k; negate = true; }
  k = ((k % L) + L) % L;

  if (_gTable === null) buildGTable();

  let result = ZERO;
  for (let i = 0; i < _gTable.length; i++) {
    if (k & (1n << BigInt(i))) {
      result = pointAdd(result, _gTable[i]);
    }
  }

  return negate ? pointNegate(result) : result;
}

function scalarMult(k, pt) {
  if (k === 0n) return ZERO;
  if (k < 0n) { k = -k; pt = pointNegate(pt); }
  k = ((k % L) + L) % L;
  if (k === 0n) return ZERO;

  let R0 = ZERO;
  let R1 = pt;
  for (let i = BigInt(bigBitLen(k) - 1); i >= 0n; i--) {
    if ((k >> i) & 1n) {
      R0 = pointAdd(R0, R1);
      R1 = pointDouble(R1);
    } else {
      R1 = pointAdd(R0, R1);
      R0 = pointDouble(R0);
    }
  }
  return R0;
}

function bigBitLen(n) {
  if (n === 0n) return 0;
  let bits = 0;
  while (n > 0n) { n >>= 1n; bits++; }
  return bits;
}

// ── Point Encoding (RFC 8032 Section 5.1.2) ─────────────────────

function toAffine(pt) {
  const [X, Y, Z] = pt;
  if (Z === 0n) return [0n, 1n];
  const zInv = modInv(Z, P);
  return [(X * zInv % P + P) % P, (Y * zInv % P + P) % P];
}

function encodePoint(pt) {
  const [x, y] = toAffine(pt);
  const out = new Uint8Array(32);
  let yy = y;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(yy & 0xffn);
    yy >>= 8n;
  }
  if (x & 1n) out[31] |= 0x80;
  return out;
}

function decodePoint(b) {
  if (b.length !== 32) return null;

  const yBytes = new Uint8Array(b);
  const sign = (yBytes[31] & 0x80) !== 0;
  yBytes[31] &= 0x7f;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(yBytes[i]);

  if (y >= P) return null;

  // x^2 = (y^2 - 1) / (d*y^2 + 1)
  const ySq = y * y % P;
  const xSq = ((ySq - 1n + P) * modInv((D * ySq % P + 1n) % P, P)) % P;

  if (xSq === 0n) {
    if (sign) return null;
    return [0n, y % P, 1n, 0n];
  }

  let x = modPow(xSq, (P + 3n) / 8n, P);
  if ((x * x - xSq) % P !== 0n) {
    x = (x * modPow(2n, (P - 1n) / 4n, P)) % P;
    if ((x * x - xSq) % P !== 0n) return null;
  }

  if (Boolean(x & 1n) !== sign) {
    x = (P - x) % P;
  }

  // Verify on curve
  const lhs = ((P - x * x % P) + y * y) % P;
  const rhs = (1n + D * x % P * x % P * y % P * y % P) % P;
  if (lhs % P !== rhs % P) return null;

  return [x % P, y % P, 1n, (x * y) % P];
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

// ── Public API ──────────────────────────────────────────────────

function ed25519Keygen(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new Error("Ed25519 seed must be a 32-byte Uint8Array");
  }

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
  if (!(skBytes instanceof Uint8Array) || skBytes.length !== 64) {
    throw new Error("Ed25519 sk must be a 64-byte Uint8Array");
  }

  const seed = skBytes.subarray(0, 32);
  const pkBytes = skBytes.subarray(32, 64);

  const h = sha512(seed);
  const a = bytesToBigIntLE(clamp(h));
  const prefix = h.subarray(32, 64);

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

  const sig = new Uint8Array(64);
  sig.set(rBytes);
  sig.set(sBytes, 32);
  return sig;
}

function ed25519Verify(message, sigBytes, pkBytes) {
  if (sigBytes.length !== 64 || pkBytes.length !== 32) return false;

  const R = decodePoint(sigBytes.subarray(0, 32));
  const A = decodePoint(pkBytes);
  if (R === null || A === null) return false;

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

  const [lx, ly] = toAffine(lhs);
  const [rx, ry] = toAffine(rhs);
  return lx === rx && ly === ry;
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
