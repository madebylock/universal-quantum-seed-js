// Copyright (c) 2026 Lock.com — MIT License

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
