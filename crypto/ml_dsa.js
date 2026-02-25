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
//     mlKeygen(seed)              -> {sk, pk}     (seed: 32-byte Uint8Array)
//     mlSign(msg, sk, ctx, opts)  -> Uint8Array    (3,309-byte signature)
//     mlVerify(msg, sig, pk, ctx) -> bool
//
// Notes:
//     - All arithmetic uses regular JavaScript Number (q=8380417 fits in 53-bit
//       safe integers, products up to q^2 ~ 7e13 also fit).
//     - Signing defaults to hedged mode (rnd generated via CSPRNG)
//       as recommended by FIPS 204. Pass deterministic:true for reproducible
//       signatures (uses rnd=0^32).
//     - NOT constant-time: JavaScript arithmetic and branching on secret values
//       leak timing information. For deployments where side-channel attacks are
//       a concern, use a vetted constant-time C/Rust implementation instead.

const { shake128, shake256 } = require("./sha3");
const { randomBytes, zeroize } = require("./utils");

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

// JavaScript % can return negative values. This ensures result in [0, Q).
function mod(a, m) {
  const r = a % m;
  return r < 0 ? r + m : r;
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
  const coeffs = [];
  let need = 3 * N; // ~256 candidates; rejection rate is ~0.4%
  let buf = shake128(seed34, need);
  let pos = 0;
  while (coeffs.length < N) {
    if (pos + 3 > buf.length) {
      need += 3 * 64;
      buf = shake128(seed34, need);
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
  let stream = shake256(input, 512);
  const coeffs = [];
  let pos = 0;
  while (coeffs.length < N) {
    if (pos >= stream.length) {
      stream = shake256(input, stream.length + 256);
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
  let buf = shake256(cTilde, 8 + TAU); // First 8 bytes for sign bits, then rejection samples
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
        buf = shake256(cTilde, buf.length + 256);
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
    if (sign === 1) {
      c[j] = Q - 1; // -1 mod q
    } else {
      c[j] = 1;
    }
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
  let r0 = rPos % (1 << D);
  if (r0 > (1 << (D - 1))) {
    r0 -= (1 << D);
  }
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
  if (r0 > GAMMA2) {
    r0 -= 2 * GAMMA2;
  }
  let r1;
  if (rPos - r0 === Q - 1) {
    r1 = 0;
    r0 -= 1;
  } else {
    r1 = (rPos - r0) / (2 * GAMMA2) | 0;
  }
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
  return r1 === v1 ? 0 : 1;
}

/**
 * Recover correct high bits using hint (Algorithm 39).
 * If h=0, return high_bits(r). If h=1, adjust by +-1.
 */
function useHint(h, r) {
  const m = ((Q - 1) / (2 * GAMMA2)) | 0; // = 16 for ML-DSA-65
  const [r1, r0] = decompose(r);
  if (h === 0) return r1;
  if (r0 > 0) return (r1 + 1) % m;
  return mod(r1 - 1, m);
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
    if (rnd.length !== 32) {
      throw new Error("rnd must be 32 bytes, got " + rnd.length);
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
  let rndBytes;
  if (rnd != null) {
    rndBytes = rnd;
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

    // 6g: Check z norm bound
    let reject = false;
    for (let i = 0; i < L && !reject; i++) {
      for (let j = 0; j < N; j++) {
        let val = z[i][j];
        if (val > (Q >> 1)) val = Q - val;
        if (val >= GAMMA1 - BETA) {
          reject = true;
          break;
        }
      }
    }
    if (reject) continue;

    // 6h: Check ||r0||_inf < gamma2 - beta
    for (let i = 0; i < K && !reject; i++) {
      for (let j = 0; j < N; j++) {
        const lb = lowBits(wMinusCs2[i][j]);
        if (Math.abs(lb) >= GAMMA2 - BETA) {
          reject = true;
          break;
        }
      }
    }
    if (reject) continue;

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
    if (hintCount > OMEGA) continue;

    // 6j: Check ct0 norm bound
    reject = false;
    for (let i = 0; i < K && !reject; i++) {
      for (let j = 0; j < N; j++) {
        let val = ct0Inv[i][j];
        if (val > (Q >> 1)) val = Q - val;
        if (val >= GAMMA2) {
          reject = true;
          break;
        }
      }
    }
    if (reject) continue;

    // Success -- encode signature
    const sig = sigEncode(cTilde, z, h);

    // Best-effort cleanup of secret intermediates
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
  let pkDiff = 0;
  for (let i = 0; i < pkBytes.length; i++) pkDiff |= pkBytes[i] ^ pkReencoded[i];
  if (pkDiff !== 0) return false;

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

  // Constant-ish time comparison (not truly constant-time in JS)
  if (cTilde.length !== cTildeCheck.length) return false;
  let diff = 0;
  for (let i = 0; i < cTilde.length; i++) {
    diff |= cTilde[i] ^ cTildeCheck[i];
  }
  return diff === 0;
}

/**
 * ML-DSA-65 pure signing (Algorithm 2, FIPS 204).
 *
 * Builds M' = 0x00 || len(ctx) || ctx || message, then calls the
 * internal signing algorithm. This is the FIPS 204 "pure" mode.
 *
 * Defaults to hedged signing (FIPS 204 recommended). Pass
 * deterministic:true for reproducible signatures.
 *
 * @param {Uint8Array} message - Arbitrary-length message bytes.
 * @param {Uint8Array} sk - 4,032-byte secret key from mlKeygen.
 * @param {Uint8Array} [ctx=new Uint8Array(0)] - Optional context string (0-255 bytes).
 * @param {Object} [opts] - Options: {deterministic: bool, rnd: Uint8Array|null}.
 * @returns {Uint8Array} Signature bytes (3,309 bytes for ML-DSA-65).
 */
function mlSign(message, sk, ctx, opts) {
  if (ctx === undefined || ctx === null) ctx = new Uint8Array(0);
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
 * ML-DSA-65 pure verification (Algorithm 3, FIPS 204).
 *
 * Builds M' = 0x00 || len(ctx) || ctx || message, then calls the
 * internal verification algorithm. This is the FIPS 204 "pure" mode.
 *
 * @param {Uint8Array} message - Original message bytes.
 * @param {Uint8Array} sig - Signature bytes from mlSign.
 * @param {Uint8Array} pk - Public key bytes from mlKeygen.
 * @param {Uint8Array} [ctx=new Uint8Array(0)] - Optional context string.
 * @returns {boolean} True if the signature is valid, false otherwise.
 */
function mlVerify(message, sig, pk, ctx) {
  if (ctx === undefined || ctx === null) ctx = new Uint8Array(0);
  if (ctx.length > 255) return false;
  const mPrime = concatBytes(
    new Uint8Array([0x00, ctx.length]),
    ctx,
    message
  );
  return mlVerifyInternal(mPrime, sig, pk);
}

module.exports = {
  mlKeygen,
  mlSign,
  mlVerify,
  // Expose sizes for callers
  PK_SIZE,
  SK_SIZE,
  SIG_SIZE,
};
