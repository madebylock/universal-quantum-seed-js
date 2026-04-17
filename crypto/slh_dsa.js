// Copyright (c) 2026 Lock.com — MIT License

"use strict";

/**
 * SLH-DSA-SHAKE-128s (SPHINCS+) — FIPS 205 post-quantum digital signature.
 *
 * Pure JavaScript implementation of the Stateless Hash-Based Digital Signature
 * Standard at parameter set SLH-DSA-SHAKE-128s.
 *
 * Security relies solely on the collision resistance of SHAKE-256 — no
 * lattice assumptions required. This is the most conservative post-quantum choice.
 *
 * Key sizes:
 *     Public key:  32 bytes
 *     Secret key:  64 bytes
 *     Signature:   7,856 bytes
 *
 * Security: NIST Level 1 (128-bit post-quantum security).
 * Assumption: Hash function (SHAKE-256) security only.
 *
 * Reference: NIST FIPS 205 (August 2024).
 *
 * Public API:
 *     slhKeygen(seed)              -> { sk, pk }
 *     slhSign(msg, sk, opts?)       -> Uint8Array sig (7856 bytes)
 *     slhVerify(msg, sig, pk)      -> bool
 *
 * Notes:
 *     - Messages are byte-aligned (Uint8Array). Bit-level granularity is not
 *       supported.
 *     - Signing defaults to hedged mode (addrnd generated via CSPRNG)
 *       as recommended by FIPS 205. Pass deterministic=true for the deterministic
 *       variant (uses PK.seed as opt_rand).
 *     - Best-effort constant-time: all control flow is branchless.
 *       Hash computations (SHAKE-256) are fixed-time for same-length inputs.
 *       For deployments where hardware side-channel attacks are a concern,
 *       use a vetted constant-time C/Rust implementation instead.
 */

const { shake256 } = require("./sha3");
const { randomBytes, toBytes, constantTimeEqual } = require("./utils");

// ── SLH-DSA-SHAKE-128s Parameters (FIPS 205 Table 2) ─────────────

const _N = 16;             // Security parameter (hash output bytes)
const _FULL_H = 63;        // Total tree height
const _D = 7;              // Number of hypertree layers
const _HP = (_FULL_H / _D) | 0; // = 9, height of each XMSS tree
const _A = 12;             // FORS tree height
const _K = 14;             // Number of FORS trees
const _LG_W = 4;           // Winternitz parameter log2
const _W = 1 << _LG_W;    // = 16, Winternitz parameter

// WOTS+ constants
// len1 = ceil(8*n / lg_w) = ceil(128/4) = 32 message blocks
const _LEN1 = ((8 * _N + _LG_W - 1) / _LG_W) | 0; // = 32
// len2 = floor(log_w(len1*(w-1))) + 1 = floor(log_16(480)) + 1 = 3
const _LEN2 = 3;
const _LEN = _LEN1 + _LEN2; // = 35, total WOTS+ chains

// Message digest output sizes
const _MD_BYTES = ((_K * _A + 7) / 8) | 0;                      // = 21
const _IDX_TREE_BYTES = ((_FULL_H - _HP + 7) / 8) | 0;         // = 7
const _IDX_LEAF_BYTES = ((_HP + 7) / 8) | 0;                    // = 2
const _M = _MD_BYTES + _IDX_TREE_BYTES + _IDX_LEAF_BYTES;       // = 30

// Signature / key sizes
// SIG = R(n) + SIG_FORS(k*(1+a)*n) + SIG_HT(d*(hp+len)*n)
//     = 16 + 14*13*16 + 7*(9+35)*16 = 16 + 2912 + 4928 = 7856
const _SIG_SIZE = _N + _K * (1 + _A) * _N + _D * (_HP + _LEN) * _N; // = 7856
const _PK_SIZE = 2 * _N;  // = 32
const _SK_SIZE = 4 * _N;  // = 64


// ── ADRS (Address) Structure ──────────────────────────────────────
// 32-byte structured address identifying each node in the tree hierarchy.

// ADRS field offsets (FIPS 205 Section 4.2)
const _ADRS_LAYER = 0;    // Bytes 0-3: layer address
const _ADRS_TREE = 4;     // Bytes 4-15: tree address (96 bits)
const _ADRS_TYPE = 16;    // Bytes 16-19: address type
const _ADRS_WORD1 = 20;   // Bytes 20-23: type-specific word 1
const _ADRS_WORD2 = 24;   // Bytes 24-27: type-specific word 2
const _ADRS_WORD3 = 28;   // Bytes 28-31: type-specific word 3

// Address types
const _ADRS_TYPE_WOTS_HASH = 0;
const _ADRS_TYPE_WOTS_PK = 1;
const _ADRS_TYPE_TREE = 2;
const _ADRS_TYPE_FORS_TREE = 3;
const _ADRS_TYPE_FORS_ROOTS = 4;
const _ADRS_TYPE_WOTS_PRF = 5;
const _ADRS_TYPE_FORS_PRF = 6;


/**
 * Create a new zero-initialized ADRS.
 * @returns {Uint8Array} 32-byte address structure
 */
function _adrs_new() {
  return new Uint8Array(32);
}

/**
 * Set the 32-bit layer address at bytes 0-3.
 * @param {Uint8Array} adrs
 * @param {number} layer
 */
function _adrs_set_layer(adrs, layer) {
  new DataView(adrs.buffer, adrs.byteOffset).setUint32(_ADRS_LAYER, layer, false);
}

/**
 * Set 96-bit tree address (bytes 4-15) — toByte(tree, 12).
 * tree is a BigInt since it can be up to 54 bits (exceeds Number.MAX_SAFE_INTEGER).
 * @param {Uint8Array} adrs
 * @param {bigint} tree
 */
function _adrs_set_tree(adrs, tree) {
  for (let i = 11; i >= 0; i--) {
    adrs[_ADRS_TREE + (11 - i)] = Number((tree >> BigInt(i * 8)) & 0xffn);
  }
}

/**
 * Set the address type at bytes 16-19 and clear type-specific words (bytes 20-31).
 * @param {Uint8Array} adrs
 * @param {number} type_val
 */
function _adrs_set_type(adrs, type_val) {
  new DataView(adrs.buffer, adrs.byteOffset).setUint32(_ADRS_TYPE, type_val, false);
  // Clear remaining words when type changes
  for (let i = 20; i < 32; i++) adrs[i] = 0;
}

/**
 * Set keypair address at bytes 20-23.
 * @param {Uint8Array} adrs
 * @param {number} kp
 */
function _adrs_set_keypair(adrs, kp) {
  new DataView(adrs.buffer, adrs.byteOffset).setUint32(_ADRS_WORD1, kp, false);
}

/**
 * Set chain address at bytes 24-27.
 * @param {Uint8Array} adrs
 * @param {number} chain
 */
function _adrs_set_chain(adrs, chain) {
  new DataView(adrs.buffer, adrs.byteOffset).setUint32(_ADRS_WORD2, chain, false);
}

/**
 * Set hash address at bytes 28-31.
 * @param {Uint8Array} adrs
 * @param {number} hash_idx
 */
function _adrs_set_hash(adrs, hash_idx) {
  new DataView(adrs.buffer, adrs.byteOffset).setUint32(_ADRS_WORD3, hash_idx, false);
}

/**
 * Set tree height at bytes 24-27.
 * @param {Uint8Array} adrs
 * @param {number} height
 */
function _adrs_set_tree_height(adrs, height) {
  new DataView(adrs.buffer, adrs.byteOffset).setUint32(_ADRS_WORD2, height, false);
}

/**
 * Set tree index at bytes 28-31.
 * @param {Uint8Array} adrs
 * @param {number} index
 */
function _adrs_set_tree_index(adrs, index) {
  new DataView(adrs.buffer, adrs.byteOffset).setUint32(_ADRS_WORD3, index, false);
}

/**
 * Copy an ADRS.
 * @param {Uint8Array} adrs
 * @returns {Uint8Array}
 */
function _adrs_copy(adrs) {
  return new Uint8Array(adrs);
}

/**
 * Read a 32-bit big-endian unsigned integer from adrs at offset.
 * @param {Uint8Array} adrs
 * @param {number} offset
 * @returns {number}
 */
function _adrs_get_u32(adrs, offset) {
  return new DataView(adrs.buffer, adrs.byteOffset).getUint32(offset, false);
}


// ── Helper: concatenate Uint8Arrays ───────────────────────────────

/**
 * Concatenate multiple Uint8Arrays into one.
 * @param  {...Uint8Array} arrays
 * @returns {Uint8Array}
 */
function concat(...arrays) {
  let totalLen = 0;
  for (let i = 0; i < arrays.length; i++) totalLen += arrays[i].length;
  const out = new Uint8Array(totalLen);
  let off = 0;
  for (let i = 0; i < arrays.length; i++) {
    out.set(arrays[i], off);
    off += arrays[i].length;
  }
  return out;
}

/**
 * Constant-time comparison of two Uint8Arrays.
 * Delegates to the shared tiered implementation in utils.js:
 *   Tier 1: Node.js crypto.timingSafeEqual (C-backed)
 *   Tier 2: Inline WASM ct_equal (browser, no JIT variation)
 *   Tier 3: Pure JS XOR-accumulate fallback
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
function bytesEqual(a, b) {
  return constantTimeEqual(a, b);
}

/**
 * Constant-time conditional swap for Merkle tree traversals.
 * When bit=0: returns [a, b] (no swap).
 * When bit=1: returns [b, a] (swap).
 * bit MUST be 0 or 1.
 * @param {number} bit
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {Uint8Array} concatenation left||right
 */
function ctSwapConcat(bit, a, b) {
  const n = a.length;
  const out = new Uint8Array(n * 2);
  // mask is 0x00 when bit=0, 0xFF when bit=1
  const mask = (-bit) & 0xFF;
  for (let i = 0; i < n; i++) {
    const diff = a[i] ^ b[i];
    const sel = diff & mask;
    out[i] = a[i] ^ sel;         // left: a when bit=0, b when bit=1
    out[n + i] = b[i] ^ sel;     // right: b when bit=0, a when bit=1
  }
  return out;
}

/**
 * Read big-endian integer from byte array as BigInt.
 * @param {Uint8Array} data
 * @returns {bigint}
 */
function bytesToBigInt(data) {
  let val = 0n;
  for (let i = 0; i < data.length; i++) {
    val = (val << 8n) | BigInt(data[i]);
  }
  return val;
}

/**
 * Read big-endian integer from byte array as Number.
 * Only safe for values that fit within Number.MAX_SAFE_INTEGER.
 * @param {Uint8Array} data
 * @returns {number}
 */
function bytesToNumber(data) {
  let val = 0;
  for (let i = 0; i < data.length; i++) {
    val = val * 256 + data[i];
  }
  return val;
}

/**
 * Convert a non-negative integer to big-endian byte array of given length.
 * @param {number} val
 * @param {number} len
 * @returns {Uint8Array}
 */
function numberToBytes(val, len) {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = val & 0xff;
    val = Math.floor(val / 256);
  }
  return out;
}


// ── Tweakable Hash Functions (SHAKE-256 based) ────────────────────

/**
 * Tweakable hash F: SHAKE-256(PK.seed || ADRS || msg, n).
 * Single-block input (msg is n bytes).
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
function _F(pk_seed, adrs, msg) {
  return shake256(concat(pk_seed, adrs, msg), _N);
}

/**
 * Tweakable hash H: SHAKE-256(PK.seed || ADRS || m1||m2, n).
 * Two-block input (m1_m2 is 2n bytes).
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @param {Uint8Array} m1_m2
 * @returns {Uint8Array}
 */
function _H(pk_seed, adrs, m1_m2) {
  return shake256(concat(pk_seed, adrs, m1_m2), _N);
}

/**
 * Tweakable hash T_l for variable-length input.
 * SHAKE-256(PK.seed || ADRS || msg, n). msg is len*n bytes.
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
function _T_l(pk_seed, adrs, msg) {
  return shake256(concat(pk_seed, adrs, msg), _N);
}

/**
 * Pseudorandom function: SHAKE-256(PK.seed || ADRS || SK.seed, n).
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} adrs
 * @returns {Uint8Array}
 */
function _PRF(pk_seed, sk_seed, adrs) {
  return shake256(concat(pk_seed, adrs, sk_seed), _N);
}

/**
 * Message PRF: SHAKE-256(SK.prf || opt_rand || msg, n).
 * @param {Uint8Array} sk_prf
 * @param {Uint8Array} opt_rand
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
function _PRF_msg(sk_prf, opt_rand, msg) {
  return shake256(concat(sk_prf, opt_rand, msg), _N);
}

/**
 * Message hash: SHAKE-256(R || PK.seed || PK.root || msg, m).
 * @param {Uint8Array} R
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} pk_root
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
function _H_msg(R, pk_seed, pk_root, msg) {
  return shake256(concat(R, pk_seed, pk_root, msg), _M);
}


// ── WOTS+ One-Time Signatures ─────────────────────────────────────

/**
 * Apply hash chain: F^steps starting from F^start.
 * Algorithm 5, FIPS 205.
 * @param {Uint8Array} X - Starting value (n bytes)
 * @param {number} start - Starting index
 * @param {number} steps - Number of chain steps
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs - Mutable, will be modified
 * @returns {Uint8Array}
 */
function _wots_chain(X, start, steps, pk_seed, adrs) {
  let tmp = X;
  for (let i = start; i < start + steps; i++) {
    _adrs_set_hash(adrs, i);
    tmp = _F(pk_seed, adrs, tmp);
  }
  return tmp;
}

/**
 * Generate WOTS+ public key (Algorithm 6, FIPS 205).
 * Returns the compressed public key (n bytes).
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @returns {Uint8Array}
 */
function _wots_keygen(sk_seed, pk_seed, adrs) {
  const sk_adrs = _adrs_copy(adrs);
  _adrs_set_type(sk_adrs, _ADRS_TYPE_WOTS_PRF);
  _adrs_set_keypair(sk_adrs, _adrs_get_u32(adrs, _ADRS_WORD1));

  const parts = [];
  for (let i = 0; i < _LEN; i++) {
    _adrs_set_chain(sk_adrs, i);
    const sk = _PRF(pk_seed, sk_seed, sk_adrs);
    const chain_adrs = _adrs_copy(adrs);
    _adrs_set_chain(chain_adrs, i);
    parts.push(_wots_chain(sk, 0, _W - 1, pk_seed, chain_adrs));
  }

  const wots_pk_adrs = _adrs_copy(adrs);
  _adrs_set_type(wots_pk_adrs, _ADRS_TYPE_WOTS_PK);
  _adrs_set_keypair(wots_pk_adrs, _adrs_get_u32(adrs, _ADRS_WORD1));
  return _T_l(pk_seed, wots_pk_adrs, concat(...parts));
}

/**
 * WOTS+ signing (Algorithm 7, FIPS 205).
 * msg is n bytes. Returns signature (_LEN * n bytes).
 * @param {Uint8Array} msg
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @returns {Uint8Array}
 */
function _wots_sign(msg, sk_seed, pk_seed, adrs) {
  // Convert message to base-w representation
  const msg_base_w = _base_w(msg, _LEN1);

  let csum = 0;
  for (let i = 0; i < msg_base_w.length; i++) {
    csum += _W - 1 - msg_base_w[i];
  }
  csum <<= (8 - ((_LEN2 * _LG_W) % 8)) % 8;
  const csum_len = ((_LEN2 * _LG_W + 7) / 8) | 0;
  const csum_bytes = numberToBytes(csum, csum_len);
  const csum_base_w = _base_w(csum_bytes, _LEN2);
  for (let i = 0; i < csum_base_w.length; i++) {
    msg_base_w.push(csum_base_w[i]);
  }

  const sk_adrs = _adrs_copy(adrs);
  _adrs_set_type(sk_adrs, _ADRS_TYPE_WOTS_PRF);
  _adrs_set_keypair(sk_adrs, _adrs_get_u32(adrs, _ADRS_WORD1));

  const parts = [];
  for (let i = 0; i < _LEN; i++) {
    _adrs_set_chain(sk_adrs, i);
    const sk = _PRF(pk_seed, sk_seed, sk_adrs);
    const chain_adrs = _adrs_copy(adrs);
    _adrs_set_chain(chain_adrs, i);
    parts.push(_wots_chain(sk, 0, msg_base_w[i], pk_seed, chain_adrs));
  }
  return concat(...parts);
}

/**
 * Recover WOTS+ public key from signature (Algorithm 8, FIPS 205).
 * @param {Uint8Array} sig - WOTS+ signature (_LEN * n bytes)
 * @param {Uint8Array} msg - Message (n bytes)
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @returns {Uint8Array}
 */
function _wots_pk_from_sig(sig, msg, pk_seed, adrs) {
  const msg_base_w = _base_w(msg, _LEN1);

  let csum = 0;
  for (let i = 0; i < msg_base_w.length; i++) {
    csum += _W - 1 - msg_base_w[i];
  }
  csum <<= (8 - ((_LEN2 * _LG_W) % 8)) % 8;
  const csum_len = ((_LEN2 * _LG_W + 7) / 8) | 0;
  const csum_bytes = numberToBytes(csum, csum_len);
  const csum_base_w = _base_w(csum_bytes, _LEN2);
  for (let i = 0; i < csum_base_w.length; i++) {
    msg_base_w.push(csum_base_w[i]);
  }

  const parts = [];
  for (let i = 0; i < _LEN; i++) {
    const chain_adrs = _adrs_copy(adrs);
    _adrs_set_chain(chain_adrs, i);
    const sig_i = sig.subarray(i * _N, (i + 1) * _N);
    parts.push(_wots_chain(sig_i, msg_base_w[i], _W - 1 - msg_base_w[i], pk_seed, chain_adrs));
  }

  const wots_pk_adrs = _adrs_copy(adrs);
  _adrs_set_type(wots_pk_adrs, _ADRS_TYPE_WOTS_PK);
  _adrs_set_keypair(wots_pk_adrs, _adrs_get_u32(adrs, _ADRS_WORD1));
  return _T_l(pk_seed, wots_pk_adrs, concat(...parts));
}

/**
 * Convert byte string to base-w representation.
 * For w=16 (lg_w=4): each byte yields 2 nibbles, high nibble first.
 * @param {Uint8Array} data
 * @param {number} out_len
 * @returns {number[]}
 */
function _base_w(data, out_len) {
  const result = [];
  for (let b = 0; b < data.length; b++) {
    result.push((data[b] >> 4) & 0x0f);
    result.push(data[b] & 0x0f);
    if (result.length >= out_len) break;
  }
  return result.slice(0, out_len);
}


// ── XMSS (Merkle Tree Signatures) ─────────────────────────────────

/**
 * Compute XMSS tree node at position i, height z (Algorithm 9, FIPS 205).
 * Recursive: leaves are WOTS+ public keys, internal nodes are H(left||right).
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} pk_seed
 * @param {number} i - Node index
 * @param {number} z - Node height
 * @param {Uint8Array} adrs
 * @returns {Uint8Array}
 */
function _xmss_node(sk_seed, pk_seed, i, z, adrs) {
  if (z === 0) {
    // Leaf: WOTS+ public key
    const wots_adrs = _adrs_copy(adrs);
    _adrs_set_type(wots_adrs, _ADRS_TYPE_WOTS_HASH);
    _adrs_set_keypair(wots_adrs, i);
    return _wots_keygen(sk_seed, pk_seed, wots_adrs);
  } else {
    // Internal node: hash of children
    const left = _xmss_node(sk_seed, pk_seed, 2 * i, z - 1, adrs);
    const right = _xmss_node(sk_seed, pk_seed, 2 * i + 1, z - 1, adrs);
    const node_adrs = _adrs_copy(adrs);
    _adrs_set_type(node_adrs, _ADRS_TYPE_TREE);
    _adrs_set_tree_height(node_adrs, z);
    _adrs_set_tree_index(node_adrs, i);
    return _H(pk_seed, node_adrs, concat(left, right));
  }
}

/**
 * XMSS tree signing (Algorithm 10, FIPS 205).
 * Returns [sig_wots, auth_path] where auth_path is hp * n bytes.
 * idx is the leaf index to sign with.
 * @param {Uint8Array} msg
 * @param {Uint8Array} sk_seed
 * @param {number} idx - Leaf index
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @returns {[Uint8Array, Uint8Array]} [sig_wots, auth_path]
 */
function _xmss_sign(msg, sk_seed, idx, pk_seed, adrs) {
  // WOTS+ signature of the message
  const wots_adrs = _adrs_copy(adrs);
  _adrs_set_type(wots_adrs, _ADRS_TYPE_WOTS_HASH);
  _adrs_set_keypair(wots_adrs, idx);
  const sig = _wots_sign(msg, sk_seed, pk_seed, wots_adrs);

  // Authentication path: sibling nodes from leaf to root
  const auth_parts = [];
  let cur_idx = idx;
  for (let j = 0; j < _HP; j++) {
    const sibling = cur_idx ^ 1; // Sibling index at this level
    auth_parts.push(_xmss_node(sk_seed, pk_seed, sibling, j, adrs));
    cur_idx >>= 1;
  }
  return [sig, concat(...auth_parts)];
}


// ── Hypertree ──────────────────────────────────────────────────────

/**
 * Hypertree signing (Algorithm 11, FIPS 205).
 * Signs msg at position (idx_tree, idx_leaf) through D layers.
 * Returns HT signature: D * (WOTS_sig + auth_path).
 *
 * idx_tree is a BigInt (up to 54 bits).
 * @param {Uint8Array} msg
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} pk_seed
 * @param {bigint} idx_tree
 * @param {number} idx_leaf
 * @returns {Uint8Array}
 */
function _ht_sign(msg, sk_seed, pk_seed, idx_tree, idx_leaf) {
  let adrs = _adrs_new();
  _adrs_set_layer(adrs, 0);
  _adrs_set_tree(adrs, idx_tree);

  let [sig_tmp, auth_tmp] = _xmss_sign(msg, sk_seed, idx_leaf, pk_seed, adrs);
  const sig_parts = [sig_tmp, auth_tmp];

  let root = _xmss_root_from_sig(idx_leaf, sig_tmp, auth_tmp, msg, pk_seed, adrs);

  for (let j = 1; j < _D; j++) {
    idx_leaf = Number(idx_tree & BigInt((1 << _HP) - 1));
    idx_tree >>= BigInt(_HP);
    adrs = _adrs_new();
    _adrs_set_layer(adrs, j);
    _adrs_set_tree(adrs, idx_tree);
    [sig_tmp, auth_tmp] = _xmss_sign(root, sk_seed, idx_leaf, pk_seed, adrs);
    sig_parts.push(sig_tmp, auth_tmp);
    if (j < _D - 1) {
      root = _xmss_root_from_sig(idx_leaf, sig_tmp, auth_tmp, root, pk_seed, adrs);
    }
  }

  return concat(...sig_parts);
}

/**
 * Hypertree verification (Algorithm 12, FIPS 205).
 * Returns true if the HT signature is valid.
 *
 * idx_tree is a BigInt (up to 54 bits).
 * @param {Uint8Array} msg
 * @param {Uint8Array} sig_ht
 * @param {Uint8Array} pk_seed
 * @param {bigint} idx_tree
 * @param {number} idx_leaf
 * @param {Uint8Array} pk_root
 * @returns {boolean}
 */
function _ht_verify(msg, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root) {
  let adrs = _adrs_new();
  _adrs_set_layer(adrs, 0);
  _adrs_set_tree(adrs, idx_tree);

  let offset = 0;
  let sig_tmp = sig_ht.subarray(offset, offset + _LEN * _N);
  offset += _LEN * _N;
  let auth_tmp = sig_ht.subarray(offset, offset + _HP * _N);
  offset += _HP * _N;

  let node = _xmss_root_from_sig(idx_leaf, sig_tmp, auth_tmp, msg, pk_seed, adrs);

  for (let j = 1; j < _D; j++) {
    idx_leaf = Number(idx_tree & BigInt((1 << _HP) - 1));
    idx_tree >>= BigInt(_HP);
    adrs = _adrs_new();
    _adrs_set_layer(adrs, j);
    _adrs_set_tree(adrs, idx_tree);

    sig_tmp = sig_ht.subarray(offset, offset + _LEN * _N);
    offset += _LEN * _N;
    auth_tmp = sig_ht.subarray(offset, offset + _HP * _N);
    offset += _HP * _N;

    node = _xmss_root_from_sig(idx_leaf, sig_tmp, auth_tmp, node, pk_seed, adrs);
  }

  return bytesEqual(node, pk_root);
}

/**
 * Compute XMSS root from a signature and authentication path.
 * Algorithm 10b / verification helper (FIPS 205).
 * @param {number} idx
 * @param {Uint8Array} sig - WOTS+ signature
 * @param {Uint8Array} auth - Authentication path
 * @param {Uint8Array} msg
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @returns {Uint8Array}
 */
function _xmss_root_from_sig(idx, sig, auth, msg, pk_seed, adrs) {
  // Recover WOTS+ public key
  const wots_adrs = _adrs_copy(adrs);
  _adrs_set_type(wots_adrs, _ADRS_TYPE_WOTS_HASH);
  _adrs_set_keypair(wots_adrs, idx);
  let node = _wots_pk_from_sig(sig, msg, pk_seed, wots_adrs);

  // Walk up the tree using auth path (branchless byte-order swap)
  const tree_adrs = _adrs_copy(adrs);
  _adrs_set_type(tree_adrs, _ADRS_TYPE_TREE);
  for (let j = 0; j < _HP; j++) {
    _adrs_set_tree_height(tree_adrs, j + 1);
    _adrs_set_tree_index(tree_adrs, idx >> (j + 1));
    const auth_j = auth.subarray(j * _N, (j + 1) * _N);
    // Branchless: bit==0 -> H(node||auth), bit==1 -> H(auth||node)
    const bit = (idx >> j) & 1;
    node = _H(pk_seed, tree_adrs, ctSwapConcat(bit, node, auth_j));
  }
  return node;
}


// ── FORS (Forest of Random Subsets) ───────────────────────────────

/**
 * Generate FORS secret value at index idx.
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @param {number} idx
 * @returns {Uint8Array}
 */
function _fors_keygen(sk_seed, pk_seed, adrs, idx) {
  const fors_adrs = _adrs_copy(adrs);
  _adrs_set_type(fors_adrs, _ADRS_TYPE_FORS_PRF);
  _adrs_set_keypair(fors_adrs, _adrs_get_u32(adrs, _ADRS_WORD1));
  _adrs_set_tree_index(fors_adrs, idx);
  return _PRF(pk_seed, sk_seed, fors_adrs);
}

/**
 * Compute FORS tree node at position i, height z (Algorithm 15, FIPS 205).
 * Expects adrs already has type=FORS_TREE and keypair address set.
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @param {number} i
 * @param {number} z
 * @returns {Uint8Array}
 */
function _fors_tree_node(sk_seed, pk_seed, adrs, i, z) {
  if (z === 0) {
    const sk = _fors_keygen(sk_seed, pk_seed, adrs, i);
    const node_adrs = _adrs_copy(adrs);
    _adrs_set_tree_height(node_adrs, 0);
    _adrs_set_tree_index(node_adrs, i);
    return _F(pk_seed, node_adrs, sk);
  }

  const left = _fors_tree_node(sk_seed, pk_seed, adrs, 2 * i, z - 1);
  const right = _fors_tree_node(sk_seed, pk_seed, adrs, 2 * i + 1, z - 1);
  const node_adrs = _adrs_copy(adrs);
  _adrs_set_tree_height(node_adrs, z);
  _adrs_set_tree_index(node_adrs, i);
  return _H(pk_seed, node_adrs, concat(left, right));
}

/**
 * FORS signing (Algorithm 16, FIPS 205).
 * md: message digest bytes to split into k a-bit indices.
 * Returns: FORS signature (k * (1 + a) * n bytes).
 * @param {Uint8Array} md
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @returns {Uint8Array}
 */
function _fors_sign(md, sk_seed, pk_seed, adrs) {
  const indices = _md_to_indices(md);

  const sig_parts = [];
  for (let i = 0; i < _K; i++) {
    const idx = indices[i];
    // Secret value at global leaf index i*2^a + idx
    sig_parts.push(_fors_keygen(sk_seed, pk_seed, adrs, (i << _A) + idx));
    // Authentication path: sibling at each level j
    for (let j = 0; j < _A; j++) {
      const s = (idx >> j) ^ 1;                       // floor(idx/2^j) xor 1
      const auth_idx = (i << (_A - j)) + s;           // i*2^(a-j) + s
      sig_parts.push(_fors_tree_node(sk_seed, pk_seed, adrs, auth_idx, j));
    }
  }
  return concat(...sig_parts);
}

/**
 * Recover FORS public key from signature (Algorithm 17, FIPS 205).
 * Expects adrs already has type=FORS_TREE and keypair address set.
 * @param {Uint8Array} sig_fors
 * @param {Uint8Array} md
 * @param {Uint8Array} pk_seed
 * @param {Uint8Array} adrs
 * @returns {Uint8Array}
 */
function _fors_pk_from_sig(sig_fors, md, pk_seed, adrs) {
  const indices = _md_to_indices(md);
  const roots_parts = [];

  let off = 0;
  for (let i = 0; i < _K; i++) {
    const idx = indices[i];

    const sk = sig_fors.subarray(off, off + _N);
    off += _N;

    // Global leaf index in the forest
    let tree_index = (i << _A) + idx;

    // Leaf node
    let node_adrs = _adrs_copy(adrs);
    _adrs_set_tree_height(node_adrs, 0);
    _adrs_set_tree_index(node_adrs, tree_index);
    let node = _F(pk_seed, node_adrs, sk);

    // Walk up the tree (branchless byte-order swap + parent index)
    for (let j = 0; j < _A; j++) {
      const auth_j = sig_fors.subarray(off, off + _N);
      off += _N;

      const parent_adrs = _adrs_copy(adrs);
      _adrs_set_tree_height(parent_adrs, j + 1);
      const bit = (idx >> j) & 1;
      // Branchless parent index: bit==0 -> tree_index>>1,
      // bit==1 -> (tree_index-1)>>1
      tree_index = (tree_index - bit) >> 1;
      _adrs_set_tree_index(parent_adrs, tree_index);
      // Branchless byte-order swap
      node = _H(pk_seed, parent_adrs, ctSwapConcat(bit, node, auth_j));
    }

    roots_parts.push(node);
  }

  // Compress the k roots into FORS public key
  const fors_pk_adrs = _adrs_copy(adrs);
  _adrs_set_type(fors_pk_adrs, _ADRS_TYPE_FORS_ROOTS);
  _adrs_set_keypair(fors_pk_adrs, _adrs_get_u32(adrs, _ADRS_WORD1));
  return _T_l(pk_seed, fors_pk_adrs, concat(...roots_parts));
}

/**
 * Split message digest into k indices of a bits each.
 * Uses BigInt since md can be up to 21 bytes (168 bits).
 * @param {Uint8Array} md
 * @returns {number[]}
 */
function _md_to_indices(md) {
  const indices = [];
  const bits = bytesToBigInt(md.subarray(0, _MD_BYTES));
  const total_bits = _MD_BYTES * 8;
  const mask = BigInt((1 << _A) - 1);
  for (let i = 0; i < _K; i++) {
    const shift = total_bits - (i + 1) * _A;
    let idx;
    if (shift >= 0) {
      idx = Number((bits >> BigInt(shift)) & mask);
    } else {
      idx = Number((bits << BigInt(-shift)) & mask);
    }
    indices.push(idx);
  }
  return indices;
}


// ── Top-Level API ──────────────────────────────────────────────────

/**
 * SLH-DSA-SHAKE-128s key generation (Algorithm 21, FIPS 205).
 *
 * @param {Uint8Array} seed - 48-byte seed = SK.seed(16) || SK.prf(16) || PK.seed(16)
 * @returns {{ sk: Uint8Array, pk: Uint8Array }} sk: 64-byte secret key, pk: 32-byte public key
 */
function slhKeygen(seed) {
  if (!(seed instanceof Uint8Array)) {
    throw new Error("seed must be a Uint8Array");
  }
  if (seed.length !== 3 * _N) {
    throw new Error(`seed must be ${3 * _N} bytes, got ${seed.length}`);
  }

  const sk_seed = seed.subarray(0, _N);        // 16 bytes
  const sk_prf = seed.subarray(_N, 2 * _N);    // 16 bytes
  const pk_seed = seed.subarray(2 * _N, 3 * _N); // 16 bytes

  // Compute root of the top XMSS tree
  const adrs = _adrs_new();
  _adrs_set_layer(adrs, _D - 1);
  _adrs_set_tree(adrs, 0n);
  const pk_root = _xmss_node(sk_seed, pk_seed, 0, _HP, adrs);

  const sk = concat(sk_seed, sk_prf, pk_seed, pk_root);
  const pk = concat(pk_seed, pk_root);
  return { sk, pk };
}

/**
 * SLH-DSA-SHAKE-128s internal signing (Algorithm 23, FIPS 205).
 *
 * Signs pre-processed message M' directly. Use slhSign() for the
 * pure FIPS 205 API with context string support.
 *
 * @param {Uint8Array} message - Pre-processed message M'
 * @param {Uint8Array} sk_bytes - 64-byte secret key
 * @param {Uint8Array|null} [addrnd=null] - Explicit n-byte randomness (overrides modes)
 * @param {boolean} [deterministic=false] - If true and addrnd is null, use PK.seed (deterministic)
 * @returns {Uint8Array} Signature (7856 bytes)
 */
function _slh_sign_internal(message, sk_bytes, addrnd, deterministic) {
  if (sk_bytes.length !== _SK_SIZE) {
    throw new Error(`secret key must be ${_SK_SIZE} bytes, got ${sk_bytes.length}`);
  }
  if (addrnd != null) {
    if (addrnd.length !== _N) {
      throw new Error(`addrnd must be ${_N} bytes, got ${addrnd.length}`);
    }
  }

  const sk_seed = sk_bytes.subarray(0, _N);
  const sk_prf = sk_bytes.subarray(_N, 2 * _N);
  const pk_seed = sk_bytes.subarray(2 * _N, 3 * _N);
  const pk_root = sk_bytes.subarray(3 * _N, 4 * _N);

  // Step 1: Randomizer R (deterministic or hedged, FIPS 205 Section 10.2.1)
  let opt_rand;
  if (addrnd != null) {
    opt_rand = addrnd;
  } else if (deterministic) {
    opt_rand = pk_seed;
  } else {
    opt_rand = randomBytes(_N);
  }
  const R = _PRF_msg(sk_prf, opt_rand, message);

  // Step 2: Hash message to get digest
  const digest = _H_msg(R, pk_seed, pk_root, message);

  // Step 3: Split digest into (md, idx_tree, idx_leaf)
  const md = digest.subarray(0, _MD_BYTES);
  const idx_tree_bytes = digest.subarray(_MD_BYTES, _MD_BYTES + _IDX_TREE_BYTES);
  const idx_leaf_bytes = digest.subarray(_MD_BYTES + _IDX_TREE_BYTES);

  // idx_tree can be up to 54 bits — use BigInt
  let idx_tree = bytesToBigInt(idx_tree_bytes);
  // Mask to valid tree range: h - h/d = 54 bits
  idx_tree &= (1n << BigInt(_FULL_H - _HP)) - 1n;

  let idx_leaf = bytesToNumber(idx_leaf_bytes);
  idx_leaf &= (1 << _HP) - 1;

  // Step 4: FORS signature
  const fors_adrs = _adrs_new();
  _adrs_set_layer(fors_adrs, 0);
  _adrs_set_tree(fors_adrs, idx_tree);
  _adrs_set_type(fors_adrs, _ADRS_TYPE_FORS_TREE);
  _adrs_set_keypair(fors_adrs, idx_leaf);
  const sig_fors = _fors_sign(md, sk_seed, pk_seed, fors_adrs);

  // Step 5: FORS public key (input to hypertree)
  const pk_fors = _fors_pk_from_sig(sig_fors, md, pk_seed, fors_adrs);

  // Step 6: Hypertree signature
  const sig_ht = _ht_sign(pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf);

  // Assemble signature: R || SIG_FORS || SIG_HT
  return concat(R, sig_fors, sig_ht);
}

/**
 * SLH-DSA-SHAKE-128s internal verification (Algorithm 25, FIPS 205).
 *
 * Verifies pre-processed message M' directly. Use slhVerify() for the
 * pure FIPS 205 API with context string support.
 *
 * @param {Uint8Array} message - Pre-processed message M'
 * @param {Uint8Array} sig_bytes - Signature (7856 bytes)
 * @param {Uint8Array} pk_bytes - 32-byte public key
 * @returns {boolean}
 */
function _slh_verify_internal(message, sig_bytes, pk_bytes) {
  if (pk_bytes.length !== _PK_SIZE) return false;
  if (sig_bytes.length !== _SIG_SIZE) return false;

  const pk_seed = pk_bytes.subarray(0, _N);
  const pk_root = pk_bytes.subarray(_N, 2 * _N);

  // Parse signature
  let offset = 0;
  const R = sig_bytes.subarray(offset, offset + _N);
  offset += _N;
  const fors_sig_size = _K * (1 + _A) * _N;
  const sig_fors = sig_bytes.subarray(offset, offset + fors_sig_size);
  offset += fors_sig_size;
  const sig_ht = sig_bytes.subarray(offset);

  // Recompute message digest
  const digest = _H_msg(R, pk_seed, pk_root, message);
  const md = digest.subarray(0, _MD_BYTES);
  const idx_tree_bytes = digest.subarray(_MD_BYTES, _MD_BYTES + _IDX_TREE_BYTES);
  const idx_leaf_bytes = digest.subarray(_MD_BYTES + _IDX_TREE_BYTES);

  // idx_tree can be up to 54 bits — use BigInt
  let idx_tree = bytesToBigInt(idx_tree_bytes);
  idx_tree &= (1n << BigInt(_FULL_H - _HP)) - 1n;

  let idx_leaf = bytesToNumber(idx_leaf_bytes);
  idx_leaf &= (1 << _HP) - 1;

  // Recover FORS public key
  const fors_adrs = _adrs_new();
  _adrs_set_layer(fors_adrs, 0);
  _adrs_set_tree(fors_adrs, idx_tree);
  _adrs_set_type(fors_adrs, _ADRS_TYPE_FORS_TREE);
  _adrs_set_keypair(fors_adrs, idx_leaf);
  const pk_fors = _fors_pk_from_sig(sig_fors, md, pk_seed, fors_adrs);

  // Verify hypertree signature
  return _ht_verify(pk_fors, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root);
}

/**
 * SLH-DSA-SHAKE-128s standard signing — signs raw message bytes directly.
 *
 * This is the interoperable API that matches ACVP/KAT test vectors and
 * other SLH-DSA implementations. The message is passed to the internal
 * algorithm without any preprocessing.
 *
 * @param {Uint8Array} message - Arbitrary-length message bytes
 * @param {Uint8Array} sk - 64-byte secret key from slhKeygen
 * @param {{ deterministic?: boolean, addrnd?: Uint8Array }} [opts={}] - Options
 * @returns {Uint8Array} Signature bytes (7,856 bytes)
 */
function slhSign(message, sk, opts) {
  message = toBytes(message);
  if (opts === undefined || opts === null) opts = {};
  return _slh_sign_internal(
    message,
    sk,
    opts.addrnd != null ? opts.addrnd : null,
    !!opts.deterministic
  );
}

/**
 * SLH-DSA-SHAKE-128s standard verification — verifies against raw message.
 *
 * @param {Uint8Array} message - Original message bytes
 * @param {Uint8Array} sig - Signature from slhSign
 * @param {Uint8Array} pk - 32-byte public key from slhKeygen
 * @returns {boolean} True if valid, false otherwise
 */
function slhVerify(message, sig, pk) {
  message = toBytes(message);
  return _slh_verify_internal(message, sig, pk);
}

/**
 * SLH-DSA-SHAKE-128s signing with FIPS 205 context prefix.
 *
 * Builds M' = 0x00 || len(ctx) || ctx || message, then calls the
 * internal signing algorithm. Use slhSign() for the standard
 * interoperable API (no context prefix).
 *
 * @param {Uint8Array} message - Arbitrary-length message bytes
 * @param {Uint8Array} sk - 64-byte secret key from slhKeygen
 * @param {Uint8Array} [ctx=new Uint8Array(0)] - Context string (0-255 bytes)
 * @param {{ deterministic?: boolean, addrnd?: Uint8Array }} [opts={}] - Options
 * @returns {Uint8Array} Signature bytes (7,856 bytes)
 */
function slhSignWithContext(message, sk, ctx, opts) {
  message = toBytes(message);
  if (ctx === undefined || ctx === null) ctx = new Uint8Array(0);
  else ctx = toBytes(ctx);
  if (opts === undefined || opts === null) opts = {};
  if (ctx.length > 255) {
    throw new Error(`context string must be <= 255 bytes, got ${ctx.length}`);
  }
  const m_prime = concat(
    new Uint8Array([0x00, ctx.length]),
    ctx,
    message
  );
  return _slh_sign_internal(
    m_prime,
    sk,
    opts.addrnd != null ? opts.addrnd : null,
    !!opts.deterministic
  );
}

/**
 * SLH-DSA-SHAKE-128s verification with FIPS 205 context prefix.
 *
 * Use slhVerify() for the standard interoperable API (no context prefix).
 *
 * @param {Uint8Array} message - Original message bytes
 * @param {Uint8Array} sig - Signature from slhSignWithContext
 * @param {Uint8Array} pk - 32-byte public key from slhKeygen
 * @param {Uint8Array} [ctx=new Uint8Array(0)] - Context string
 * @returns {boolean} True if valid, false otherwise
 */
function slhVerifyWithContext(message, sig, pk, ctx) {
  message = toBytes(message);
  if (ctx === undefined || ctx === null) ctx = new Uint8Array(0);
  else ctx = toBytes(ctx);
  if (ctx.length > 255) return false;
  const m_prime = concat(
    new Uint8Array([0x00, ctx.length]),
    ctx,
    message
  );
  return _slh_verify_internal(m_prime, sig, pk);
}

/**
 * Async wrapper for slhSign — yields to the event loop before computation
 * so browser UIs don't freeze. SLH-DSA signing is particularly heavy.
 */
function slhSignAsync(message, sk, opts) {
  return new Promise(function (resolve, reject) {
    setTimeout(function () {
      try { resolve(slhSign(message, sk, opts)); }
      catch (e) { reject(e); }
    }, 0);
  });
}

/**
 * Async wrapper for slhVerify — yields to the event loop before computation.
 */
function slhVerifyAsync(message, sig, pk) {
  return new Promise(function (resolve, reject) {
    setTimeout(function () {
      try { resolve(slhVerify(message, sig, pk)); }
      catch (e) { reject(e); }
    }, 0);
  });
}


module.exports = {
  slhKeygen,
  slhSign,
  slhVerify,
  slhSignWithContext,
  slhVerifyWithContext,
  slhSignAsync,
  slhVerifyAsync,

  // Expose sizes for consumers
  SIG_SIZE: _SIG_SIZE,
  PK_SIZE: _PK_SIZE,
  SK_SIZE: _SK_SIZE,
  SEED_SIZE: 3 * _N,
};
