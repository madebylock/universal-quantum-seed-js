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

const { sha3_256, sha3_512, shake128, shake256 } = require("./sha3");

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

  let need = 960;
  let buf = shake128(xofInput, need);

  const coeffs = new Int32Array(256);
  let count = 0, pos = 0;
  while (count < 256) {
    if (pos + 2 >= buf.length) {
      need += 168;
      buf = shake128(xofInput, need);
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
  const tPart = ek.subarray(0, 384 * K);
  for (let i = 0; i < K; i++) {
    const chunk = tPart.subarray(384 * i, 384 * (i + 1));
    const reencoded = byteEncode(byteDecode(chunk, 12), 12);
    for (let j = 0; j < 384; j++) {
      if (chunk[j] !== reencoded[j]) return false;
    }
  }
  return true;
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

  return constantTimeEqual(ct, ctPrime) ? new Uint8Array(Kprime) : new Uint8Array(Kbar);
}

const EK_SIZE = 1184;
const DK_SIZE = 2400;
const CT_SIZE = 1088;
const SS_SIZE = 32;

module.exports = { mlKemKeygen, mlKemEncaps, mlKemDecaps, EK_SIZE, DK_SIZE, CT_SIZE, SS_SIZE };
