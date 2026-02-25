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
// NOT constant-time. For side-channel-resistant deployments, use C/Rust.

const P = 2n ** 255n - 19n;
const A24 = 121665n; // (A - 2) / 4 where A = 486662

// ── Helpers ─────────────────────────────────────────────────────

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

function clamp(kBytes) {
  const k = new Uint8Array(kBytes);
  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;
  return k;
}

function decodeU(uBytes) {
  const u = new Uint8Array(uBytes);
  u[31] &= 127; // Mask bit 255 per RFC 7748
  let val = 0n;
  for (let i = 31; i >= 0; i--) val = (val << 8n) | BigInt(u[i]);
  return val;
}

function encodeU(u) {
  u = ((u % P) + P) % P;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(u & 0xffn);
    u >>= 8n;
  }
  return out;
}

// ── Core Scalar Multiplication (RFC 7748 Section 5) ─────────────

function x25519Raw(kBytes, uBytes) {
  const kClamped = clamp(kBytes);
  let k = 0n;
  for (let i = 31; i >= 0; i--) k = (k << 8n) | BigInt(kClamped[i]);
  const u = decodeU(uBytes);

  let x2 = 1n, z2 = 0n;
  let x3 = u, z3 = 1n;
  let swap = 0n;

  for (let t = 254n; t >= 0n; t--) {
    const kt = (k >> t) & 1n;
    swap ^= kt;
    if (swap) {
      [x2, x3] = [x3, x2];
      [z2, z3] = [z3, z2];
    }
    swap = kt;

    const A = (x2 + z2) % P;
    const AA = A * A % P;
    const B = (x2 - z2 + P) % P;
    const BB = B * B % P;
    const E = (AA - BB + P) % P;
    const C = (x3 + z3) % P;
    const DD = (x3 - z3 + P) % P;
    const DA = DD * A % P;
    const CB = C * B % P;

    x3 = (DA + CB) % P;
    x3 = x3 * x3 % P;
    z3 = (DA - CB + P) % P;
    z3 = u * (z3 * z3 % P) % P;
    x2 = AA * BB % P;
    z2 = E * ((AA + A24 * E) % P) % P;
  }

  if (swap) {
    [x2, x3] = [x3, x2];
    [z2, z3] = [z3, z2];
  }

  return (x2 * modPow(z2, P - 2n, P)) % P;
}

// ── Public API ──────────────────────────────────────────────────

function x25519Keygen(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new Error("X25519 seed must be a 32-byte Uint8Array");
  }

  const sk = clamp(seed);
  // Base point u = 9
  const basepoint = new Uint8Array(32);
  basepoint[0] = 9;
  const u = x25519Raw(sk, basepoint);
  const pk = encodeU(u);
  return { sk, pk };
}

function x25519(sk, pk) {
  if (!(sk instanceof Uint8Array) || sk.length !== 32) {
    throw new Error("X25519 sk must be a 32-byte Uint8Array");
  }
  if (!(pk instanceof Uint8Array) || pk.length !== 32) {
    throw new Error("X25519 pk must be a 32-byte Uint8Array");
  }

  const u = x25519Raw(sk, pk);
  const result = encodeU(u);

  // Reject low-order points (all-zero output) per RFC 7748 Section 6.1
  let allZero = true;
  for (let i = 0; i < 32; i++) {
    if (result[i] !== 0) { allZero = false; break; }
  }
  if (allZero) {
    throw new Error("X25519: low-order input point (all-zero shared secret)");
  }

  return result;
}

module.exports = { x25519Keygen, x25519, X25519_SK_SIZE: 32, X25519_PK_SIZE: 32 };
