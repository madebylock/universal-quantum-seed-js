// Copyright (c) 2026 Lock.com — PolyForm Shield License 1.0.0

"use strict";

// ML-KEM-768 (Kyber) — FIPS 203 post-quantum key encapsulation mechanism.
// Pure JavaScript, zero dependencies. Direct port of the Python ml_kem.py.
//
// Key sizes:
//   Encapsulation key (EK): 1,184 bytes
//   Decapsulation key (DK): 2,400 bytes
//   Ciphertext:             1,088 bytes
//   Shared secret:             32 bytes
//
// Constant-time hardening (mirrors the Python reference):
//   Every operation on secret-dependent coefficients (the secret vector s,
//   the CBD noise, the decrypted pre-key m' and its re-encryption) is
//   branch-free and division-free. Reductions mod q use a fixed-point
//   Barrett multiply evaluated entirely in int32 with Math.imul, followed
//   by a masked conditional subtraction; the compress rounding uses the
//   same quotient estimate plus a masked +1. The JS modulo and division
//   operators compile to hardware division in the interpreter and baseline
//   tiers (data-dependent latency on many cores) and ByteEncode's per-bit
//   "if" was a branch on every bit of m', so neither appears on a secret
//   path any more.
//   Only public data may still branch: SampleNTT rejection-samples the
//   matrix from rho, which is part of the public encapsulation key, and the
//   zeta table is computed once from constants.

const { sha3_256, sha3_512, shake128, shake256, shake128Xof } = require("./sha3");

// ── ML-KEM-768 Parameters (FIPS 203 Table 2) ────────────────────

const Q = 3329;
const N = 256;
const K = 3;
const ETA1 = 2;
const ETA2 = 2;
const DU = 10;
const DV = 4;

const ML_KEM_EK_SIZE = 1184;
const ML_KEM_DK_SIZE = 2400;
const ML_KEM_CT_SIZE = 1088;
const ML_KEM_SS_SIZE = 32;
const K_PKE_DK_SIZE = 384 * K;

// ── NTT Constants ────────────────────────────────────────────────

function bitrev7(n) {
  let r = 0;
  for (let i = 0; i < 7; i++) { r = (r << 1) | (n & 1); n >>= 1; }
  return r;
}

// Primitive 512th root of unity: 17
const ROOT = 17;

// Precompute 128 zetas in bit-reversed order (public constants, computed
// once at load time; the modulo operator is acceptable here because
// nothing is secret).
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

// ── Constant-time arithmetic ─────────────────────────────────────
//
// Barrett constant: floor(2^25 / q) = 10079 (10079 * 3329 = 33,552,991,
// just below 2^25 = 33,554,432). For 0 <= x < 2^24 the estimate
// t = floor(x * 10079 / 2^25) is either floor(x / q) or one less, so
// x - t*q lies in [0, 2q) and one masked subtraction finishes the job.
//
// x * 10079 does not fit in int32, so the product is split at bit 12:
//   x = xh * 2^12 + xl
//   floor(x * 10079 / 2^25) = floor((xh*10079 + floor(xl*10079 / 2^12)) / 2^13)
// (nested floors by powers of two compose exactly). Both partial products
// stay below 2^26, so Math.imul and the unsigned shifts are exact.
//
// Every caller keeps its argument inside [0, 2^24): products of two
// residues are below q^2 < 2^24, sums of two residues are below 2q, and
// the compress numerator x*2^d + q/2 is below 2^22.

const BARRETT_MULT = 10079;

function barrettQuotient(x) {
  const xh = x >>> 12;
  const xl = x & 0xfff;
  return (Math.imul(xh, BARRETT_MULT) + (Math.imul(xl, BARRETT_MULT) >>> 12)) >>> 13;
}

// x mod q for 0 <= x < 2^24. No division, no branch.
function ctModQ(x) {
  const t = barrettQuotient(x);
  const r = x - Math.imul(t, Q);         // in [0, 2q)
  return r - (Q & ((Q - 1 - r) >> 31));  // subtract q exactly when r >= q
}

// floor(x / q) for 0 <= x < 2^22. No division, no branch.
function ctDivQ(x) {
  const t = barrettQuotient(x);
  const r = x - Math.imul(t, Q);         // in [0, 2q)
  return t + ((Q - 1 - r) >>> 31);       // +1 exactly when r >= q
}

// ── Polynomial arithmetic ────────────────────────────────────────
// All coefficients are kept in [0, q). Inputs to ntt/nttInv/multiplyNtts/
// polyAdd/polySub are residues, so every intermediate stays inside the
// ctModQ domain.

function ntt(f) {
  const a = Int32Array.from(f);
  let k = 1;
  for (let len = 128; len >= 2; len >>= 1) {
    for (let start = 0; start < 256; start += 2 * len) {
      const zeta = ZETAS[k++];
      for (let j = start; j < start + len; j++) {
        const t = ctModQ(Math.imul(zeta, a[j + len]));
        a[j + len] = ctModQ(a[j] + Q - t);
        a[j] = ctModQ(a[j] + t);
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
        a[j] = ctModQ(t + a[j + len]);
        a[j + len] = ctModQ(Math.imul(zeta, ctModQ(a[j + len] + Q - t)));
      }
    }
  }
  for (let i = 0; i < 256; i++) a[i] = ctModQ(Math.imul(a[i], N_INV));
  return a;
}

// Intermediate products are reduced before they are combined so that every
// sum handed to ctModQ stays below 2q (the same shape as the Python port).
function basecasemultiply(a0, a1, b0, b1, gamma) {
  const c0 = ctModQ(
    ctModQ(Math.imul(a0, b0))
    + ctModQ(Math.imul(ctModQ(Math.imul(a1, b1)), gamma))
  );
  const c1 = ctModQ(ctModQ(Math.imul(a0, b1)) + ctModQ(Math.imul(a1, b0)));
  return [c0, c1];
}

function multiplyNtts(f, g) {
  const h = new Int32Array(256);
  for (let i = 0; i < 64; i++) {
    const z0 = ZETAS[64 + i];
    const [c0, c1] = basecasemultiply(f[4*i], f[4*i+1], g[4*i], g[4*i+1], z0);
    h[4*i] = c0; h[4*i+1] = c1;
    // Second pair: gamma = -zeta (public constant, negated mod q)
    const [c2, c3] = basecasemultiply(f[4*i+2], f[4*i+3], g[4*i+2], g[4*i+3], ctModQ(Q - z0));
    h[4*i+2] = c2; h[4*i+3] = c3;
  }
  return h;
}

function polyAdd(a, b) {
  const c = new Int32Array(256);
  for (let i = 0; i < 256; i++) c[i] = ctModQ(a[i] + b[i]);
  return c;
}

function polySub(a, b) {
  const c = new Int32Array(256);
  // Add q before subtracting so the argument stays non-negative.
  for (let i = 0; i < 256; i++) c[i] = ctModQ(a[i] + Q - b[i]);
  return c;
}

// ── Byte encoding / decoding ────────────────────────────────────

// FIPS 203 Algorithm 5: ByteEncode_d. The branch on d is on a public
// parameter; the bit packing itself is unconditional so no control flow
// depends on the (possibly secret) coefficient values.
function byteEncode(f, d) {
  const mask = (1 << d) - 1;
  const out = new Uint8Array(32 * d);
  let bitIdx = 0;
  for (let i = 0; i < 256; i++) {
    let val = d === 12 ? ctModQ(f[i]) : (f[i] & mask);
    for (let j = 0; j < d; j++) {
      out[bitIdx >> 3] |= (val & 1) << (bitIdx & 7);
      val >>= 1;
      bitIdx++;
    }
  }
  return out;
}

// FIPS 203 Algorithm 6: ByteDecode_d. For d < 12 the value already has
// exactly d bits; for d = 12 it is reduced mod q.
function byteDecode(data, d) {
  const f = new Int32Array(256);
  for (let i = 0; i < 256; i++) {
    let val = 0;
    for (let j = 0; j < d; j++) {
      const bitIdx = i * d + j;
      const bit = (data[bitIdx >> 3] >> (bitIdx & 7)) & 1;
      val |= bit << j;
    }
    f[i] = d === 12 ? ctModQ(val) : val;
  }
  return f;
}

// ── Sampling ─────────────────────────────────────────────────────

// FIPS 203 Algorithm 7: SampleNTT. Rejection sampling on public randomness
// (rho is part of the encapsulation key), so the data-dependent loop count
// leaks nothing secret.
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

// FIPS 203 Algorithm 8: SamplePolyCBD_eta on secret PRF output. Bit
// extraction is unconditional and indexed by public positions; the
// centered difference is offset by q so the reduction argument stays
// non-negative.
function sampleCbd(data, eta) {
  const f = new Int32Array(256);
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
    f[i] = ctModQ(aSum + Q - bSum);
  }
  return f;
}

// ── Compression / decompression ──────────────────────────────────

// Compress_d(x) = round(2^d / q * x) mod 2^d for x in [0, q). The numerator
// x*2^d + q/2 is below 2^22 for d <= 10, inside the ctDivQ domain.
function compress(x, d) {
  const m = 1 << d;
  return ctDivQ((x << d) + (Q >> 1)) & (m - 1);
}

// Decompress_d(y) = round(q / 2^d * y): division by 2^d is a shift.
function decompress(y, d) {
  const m = 1 << d;
  return (Math.imul(y, Q) + (m >> 1)) >> d;
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
  let ekLen = K_PKE_DK_SIZE + 32;
  const ekPke = new Uint8Array(ekLen);
  let offset = 0;
  for (let i = 0; i < K; i++) {
    ekPke.set(byteEncode(tHat[i], 12), offset);
    offset += 384;
  }
  ekPke.set(rho, offset);

  // dk = encode(s)
  const dkPke = new Uint8Array(K_PKE_DK_SIZE);
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
  if (ek.length !== ML_KEM_EK_SIZE) return false;
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
  if (dk.length !== ML_KEM_DK_SIZE) return false;
  const ek = dk.subarray(K_PKE_DK_SIZE, K_PKE_DK_SIZE + ML_KEM_EK_SIZE);
  const hStored = dk.subarray(
    K_PKE_DK_SIZE + ML_KEM_EK_SIZE,
    K_PKE_DK_SIZE + ML_KEM_EK_SIZE + 32
  );
  return constantTimeEqual(sha3_256(ek), hStored);
}

function mlKemEkFromDk(dk) {
  if (!(dk instanceof Uint8Array)) throw new Error("dk must be a Uint8Array");
  if (!dkHashCheck(dk)) throw new Error("Decapsulation key failed FIPS 203 hash check (§7.2)");
  return new Uint8Array(dk.subarray(K_PKE_DK_SIZE, K_PKE_DK_SIZE + ML_KEM_EK_SIZE));
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
  const dk = new Uint8Array(ML_KEM_DK_SIZE);
  dk.set(dkPke);
  dk.set(ekPke, K_PKE_DK_SIZE);
  dk.set(hEk, K_PKE_DK_SIZE + ML_KEM_EK_SIZE);
  dk.set(z, K_PKE_DK_SIZE + ML_KEM_EK_SIZE + 32);

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
  if (ct.length !== ML_KEM_CT_SIZE) {
    throw new Error(`ML-KEM-768 ciphertext must be ${ML_KEM_CT_SIZE} bytes, got ${ct.length}`);
  }

  return { ct, ss: new Uint8Array(Kss) };
}

// Deterministic stand-in for m' when K-PKE decryption itself throws on
// malformed inputs. Keeps decapsulation total (FIPS 203 implicit rejection):
// the value is unpredictable to an attacker and is discarded by the
// constant-time mask below, but lets the re-encryption path run uniformly
// instead of leaking a decrypt failure via an exception.
function mlKemDecapsFallbackMPrime(ct) {
  const domain = new Uint8Array([
    0x4d,0x4c,0x2d,0x4b,0x45,0x4d,0x2d,0x37,
    0x36,0x38,0x2d,0x66,0x61,0x6c,0x6c,0x62,
    0x61,0x63,0x6b,0x2d,0x6d,0x70,0x72,0x69,
    0x6d,0x65,0x2d,0x76,0x31,0x00,0x00,0x00
  ]);
  const input = new Uint8Array(domain.length + ct.length);
  input.set(domain);
  input.set(ct, domain.length);
  return shake256(input, 32);
}

function mlKemDecaps(dk, ct) {
  if (!(dk instanceof Uint8Array)) throw new Error("dk must be a Uint8Array");
  if (!(ct instanceof Uint8Array)) throw new Error("ct must be a Uint8Array");
  if (ct.length !== ML_KEM_CT_SIZE) throw new Error(`ML-KEM-768 decaps requires ${ML_KEM_CT_SIZE}-byte CT, got ${ct.length}`);
  if (!dkHashCheck(dk)) throw new Error("Decapsulation key failed FIPS 203 hash check (§7.2)");

  const dkPke = dk.subarray(0, K_PKE_DK_SIZE);
  const ekPke = mlKemEkFromDk(dk);
  const h = dk.subarray(
    K_PKE_DK_SIZE + ML_KEM_EK_SIZE,
    K_PKE_DK_SIZE + ML_KEM_EK_SIZE + 32
  );
  const z = dk.subarray(K_PKE_DK_SIZE + ML_KEM_EK_SIZE + 32);

  let mPrime;
  let decryptOk = 1;
  try {
    mPrime = kPkeDecrypt(dkPke, ct);
  } catch (_) {
    decryptOk = 0;
    mPrime = mlKemDecapsFallbackMPrime(ct);
  }

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

  let ctPrime;
  let reencryptionOk = 1;
  try {
    ctPrime = kPkeEncrypt(ekPke, mPrime, rPrime);
  } catch (_) {
    reencryptionOk = 0;
    ctPrime = new Uint8Array(ct.length);
  }

  // Constant-time selection: avoid branch on secret comparison result.
  // Derive mask arithmetically: -1 (0xffffffff) if equal, 0 if not. A throw in
  // either K-PKE half forces the implicit-rejection branch (Kbar) rather than
  // surfacing an exception that would distinguish malformed ciphertexts.
  const implicitRejectionOk = decryptOk & reencryptionOk &
    (constantTimeEqual(ct, ctPrime) ? 1 : 0);
  const mask = (-implicitRejectionOk) & 0xff;
  const result = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    result[i] = (Kprime[i] & mask) | (Kbar[i] & (~mask & 0xff));
  }
  return result;
}

const EK_SIZE = ML_KEM_EK_SIZE;
const DK_SIZE = ML_KEM_DK_SIZE;
const CT_SIZE = ML_KEM_CT_SIZE;
const SS_SIZE = ML_KEM_SS_SIZE;

module.exports = {
  mlKemKeygen,
  mlKemEncaps,
  mlKemDecaps,
  mlKemEkFromDk,
  ML_KEM_EK_SIZE,
  ML_KEM_DK_SIZE,
  ML_KEM_CT_SIZE,
  EK_SIZE,
  DK_SIZE,
  CT_SIZE,
  SS_SIZE,
  // Constant-time reduction helpers, exported for exhaustive tests only.
  _ctModQ: ctModQ,
  _ctDivQ: ctDivQ,
};
