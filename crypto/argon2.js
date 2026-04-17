// Copyright (c) 2026 Lock.com — MIT License

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
