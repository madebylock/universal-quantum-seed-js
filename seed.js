// Copyright (c) 2026 Signer.io — MIT License

"use strict";

// Universal Quantum Seed — Core API (JavaScript port of seed.py)
//
// Generates cryptographically secure seeds using 256 visual icons (8 bits each).
// - 24 words = 22 random + 2 checksum = 176 bits entropy
// - 36 words = 34 random + 2 checksum = 272 bits entropy

const { sha256, sha512, hmacSha256, hmacSha512, hkdfExpand, pbkdf2Sha512, pbkdf2Sha512Async } = require("./crypto/sha2");
const { constantTimeEqual } = require("./crypto/utils");
const { LOOKUP, LANGUAGES, DARK_VISUALS } = require("./words");

const { argon2id } = require("./crypto/argon2");

const VERSION = "1.0";

// 256 base English words — one per icon position (0-255)
const BASE_WORDS = [
  "eye", "ear", "nose", "mouth", "tongue", "bone", "tooth", "skull",
  "heart", "brain", "baby", "foot", "muscle", "hand", "leg", "dog",
  "cat", "horse", "cow", "pig", "goat", "rabbit", "mouse", "tiger",
  "wolf", "bear", "deer", "elephant", "bat", "camel", "zebra", "giraffe",
  "fox", "lion", "monkey", "panda", "llama", "squirrel", "chicken", "bird",
  "duck", "penguin", "peacock", "owl", "eagle", "snake", "frog", "turtle",
  "crocodile", "lizard", "fish", "octopus", "crab", "whale", "dolphin", "shark",
  "snail", "ant", "bee", "butterfly", "worm", "spider", "scorpion", "sun",
  "moon", "star", "earth", "fire", "water", "snow", "cloud", "rain",
  "rainbow", "wind", "thunder", "volcano", "tornado", "comet", "wave", "desert",
  "island", "mountain", "rock", "diamond", "feather", "tree", "cactus", "flower",
  "leaf", "mushroom", "wood", "mango", "apple", "banana", "grape", "orange",
  "melon", "peach", "strawberry", "pineapple", "cherry", "lemon", "coconut", "cucumber",
  "seed", "corn", "carrot", "onion", "potato", "pepper", "tomato", "garlic",
  "peanut", "bread", "cheese", "egg", "meat", "rice", "cake", "snack",
  "sweet", "honey", "milk", "coffee", "tea", "wine", "beer", "juice",
  "salt", "fork", "spoon", "bowl", "knife", "bottle", "soup", "pan",
  "key", "lock", "bell", "hammer", "axe", "gear", "magnet", "sword",
  "bow", "shield", "bomb", "compass", "hook", "thread", "needle", "scissors",
  "pencil", "house", "castle", "temple", "bridge", "factory", "door", "window",
  "tent", "beach", "bank", "tower", "statue", "wheel", "boat", "train",
  "car", "bike", "plane", "rocket", "helicopter", "ambulance", "fuel", "track",
  "map", "drum", "guitar", "violin", "piano", "paint", "book", "music",
  "mask", "camera", "microphone", "headset", "movie", "dress", "coat", "pants",
  "glove", "shirt", "shoes", "hat", "flag", "cross", "circle", "triangle",
  "square", "check", "alert", "sleep", "magic", "message", "blood", "repeat",
  "dna", "germ", "pill", "doctor", "microscope", "galaxy", "flask", "atom",
  "satellite", "battery", "telescope", "tv", "radio", "phone", "bulb", "keyboard",
  "chair", "bed", "candle", "mirror", "ladder", "basket", "vase", "shower",
  "razor", "soap", "computer", "trash", "umbrella", "money", "prayer", "toy",
  "crown", "ring", "dice", "piece", "coin", "calendar", "boxing", "swimming",
  "game", "soccer", "ghost", "alien", "robot", "angel", "dragon", "clock",
];

const BASE = {};
BASE_WORDS.forEach((w, i) => { BASE[i] = w; });

// Domain separator
const DOMAIN = new TextEncoder().encode("universal-seed-v1");

// KDF parameters
const PBKDF2_ITERATIONS = 600000;

// Argon2id parameters (OWASP recommended for high-value targets)
const ARGON2_TIME = 3;         // iterations
const ARGON2_MEMORY = 65536;   // 64 MiB
const ARGON2_PARALLEL = 4;     // lanes
const ARGON2_HASHLEN = 64;     // output bytes

// Build sorted keys for binary search
const SORTED_KEYS = Object.keys(LOOKUP).sort();

// Build inner-word index for multi-word entries
const INNER_WORDS = [];
for (const k of Object.keys(LOOKUP)) {
  const parts = k.split(/\s+/);
  if (parts.length > 1) {
    for (let i = 1; i < parts.length; i++) {
      INNER_WORDS.push([parts[i], k]);
    }
  }
}
INNER_WORDS.sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
const INNER_WORD_KEYS = INNER_WORDS.map(iw => iw[0]);

// Zero-width and invisible characters regex
const INVISIBLE_CHARS = /[\u200b\u200c\u200d\u200e\u200f\u00ad\u034f\u061c\ufeff\u2060\u2061\u2062\u2063\u2064\u180e]/g;

// Article suffixes (Scandinavian, Romanian, Icelandic)
const ARTICLE_SUFFIXES = ["inn", "i\u00f0", "ul", "in", "le", "en", "et", "a"];

// Latin diacritic replacements
const LATIN_REPLACEMENTS = {
  "\u00df": "ss", "\u00f8": "o", "\u00e6": "ae", "\u0153": "oe",
  "\u00f0": "d", "\u00fe": "th", "\u0142": "l", "\u0111": "d",
};

// ── Utility ─────────────────────────────────────────────────────

const _enc = new TextEncoder();

function toBytes(data) {
  if (data instanceof Uint8Array) return data;
  if (typeof data === "string") return _enc.encode(data);
  if (Array.isArray(data)) return new Uint8Array(data);
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  throw new Error("unsupported input type");
}

function concatBytes(...arrays) {
  let totalLen = 0;
  for (const a of arrays) totalLen += a.length;
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const a of arrays) {
    result.set(a instanceof Uint8Array ? a : toBytes(a), offset);
    offset += a.length;
  }
  return result;
}

function randomBytes(n) {
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.getRandomValues) {
    const buf = new Uint8Array(n);
    globalThis.crypto.getRandomValues(buf);
    return buf;
  }
  const nodeCrypto = require("crypto");
  return new Uint8Array(nodeCrypto.randomBytes(n));
}

function timingNs() {
  if (typeof process !== "undefined" && process.hrtime && process.hrtime.bigint) {
    return Number(process.hrtime.bigint());
  }
  return Math.floor(performance.now() * 1e6);
}

/** Best-effort zeroing of sensitive buffers. Not guaranteed by JS GC, but reduces exposure. */
function zeroize(buf) {
  if (buf instanceof Uint8Array) buf.fill(0);
  else if (Array.isArray(buf)) buf.fill(0);
}

function packLE_BB(a, b) { return new Uint8Array([a & 0xff, b & 0xff]); }
function packLE_I(n) { return new Uint8Array([n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]); }
function packLE_Q(n) {
  const buf = new Uint8Array(8);
  for (let i = 0; i < 8; i++) { buf[i] = n & 0xff; n = Math.floor(n / 256); }
  return buf;
}

// ── Normalization ───────────────────────────────────────────────

function normalize(word) {
  let w = word.trim();
  w = w.replace(INVISIBLE_CHARS, "");
  w = w.normalize("NFKC");
  return w.toLowerCase();
}

function detectScript(word) {
  const counts = {};
  for (const c of word) {
    if (!/\p{L}/u.test(c)) continue;
    // Use Unicode property escapes for script detection
    if (/\p{Script=Latin}/u.test(c)) counts.latin = (counts.latin || 0) + 1;
    else if (/\p{Script=Greek}/u.test(c)) counts.greek = (counts.greek || 0) + 1;
    else if (/\p{Script=Cyrillic}/u.test(c)) counts.cyrillic = (counts.cyrillic || 0) + 1;
    else if (/\p{Script=Arabic}/u.test(c)) counts.arabic = (counts.arabic || 0) + 1;
    else if (/\p{Script=Hebrew}/u.test(c)) counts.hebrew = (counts.hebrew || 0) + 1;
  }
  if (Object.keys(counts).length === 0) return "other";
  return Object.entries(counts).sort((a, b) => b[1] - a[1])[0][0];
}

const SAFE_STRIP_SCRIPTS = new Set(["latin", "greek", "arabic", "hebrew", "cyrillic"]);

function stripDiacritics(word) {
  const script = detectScript(word);
  if (!SAFE_STRIP_SCRIPTS.has(script)) return word;

  let result = word;

  if (script === "latin") {
    for (const [old, repl] of Object.entries(LATIN_REPLACEMENTS)) {
      result = result.split(old).join(repl);
    }
  }

  if (script === "cyrillic") {
    result = result.split("\u0451").join("\u0435").split("\u0401").join("\u0415");
  }

  // NFD decompose and remove combining marks (category Mn)
  const nfkd = result.normalize("NFKD");
  let stripped = "";
  for (const c of nfkd) {
    // Combining marks are in Unicode category Mn (Nonspacing_Mark)
    if (!/\p{Mn}/u.test(c)) stripped += c;
  }
  return stripped.normalize("NFC");
}

function normalizeEmoji(text) {
  let e = text.trim();
  e = e.replace(/\ufe0e|\ufe0f/g, "");
  e = e.replace(INVISIBLE_CHARS, "");
  return e;
}

// ── Resolution ──────────────────────────────────────────────────

function resolveOne(word, strict = false) {
  const key = normalize(word);

  // Numeric index
  if (/^\d+$/.test(key)) {
    const n = parseInt(key, 10);
    if (n >= 0 && n <= 255) return n;
  }

  let result = LOOKUP[key];
  if (result !== undefined) return result;

  // Emoji-normalized
  const eKey = normalizeEmoji(word);
  if (eKey && eKey !== key) {
    result = LOOKUP[eKey];
    if (result !== undefined) return result;
  }

  if (strict) return null;

  // Diacritic-stripped
  const stripped = stripDiacritics(key);
  if (stripped !== key) {
    result = LOOKUP[stripped];
    if (result !== undefined) return result;
  }

  const candidate = stripped !== key ? stripped : key;

  // Arabic al- prefix
  if (candidate.startsWith("\u0627\u0644")) {
    result = LOOKUP[candidate.slice(2)];
    if (result !== undefined) return result;
  }

  // Hebrew ha- prefix
  if (candidate.startsWith("\u05d4")) {
    result = LOOKUP[candidate.slice(1)];
    if (result !== undefined) return result;
  }

  // French/Italian l' prefix
  for (const apo of ["'", "\u2019", "\u02bc"]) {
    const prefix = "l" + apo;
    if (candidate.startsWith(prefix)) {
      result = LOOKUP[candidate.slice(prefix.length)];
      if (result !== undefined) return result;
      break;
    }
  }

  // Article suffixes
  if (detectScript(candidate) === "latin" && candidate.length > 3) {
    for (const suffix of ARTICLE_SUFFIXES) {
      if (candidate.endsWith(suffix) && candidate.length - suffix.length >= 2) {
        result = LOOKUP[candidate.slice(0, -suffix.length)];
        if (result !== undefined) return result;
      }
    }
  }

  return null;
}

function resolve(words, strict = false) {
  if (typeof words === "string") return resolveOne(words, strict);

  const indexes = [];
  const errors = [];
  for (let i = 0; i < words.length; i++) {
    const idx = resolveOne(words[i], strict);
    if (idx !== null) indexes.push(idx);
    else errors.push([i, words[i]]);
  }
  return { indexes, errors };
}

// ── Search ──────────────────────────────────────────────────────

function binarySearchLeft(arr, key) {
  let lo = 0, hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (arr[mid] < key) lo = mid + 1; else hi = mid;
  }
  return lo;
}

function searchSorted(sortedKeys, lookup, key, limit, seenIndexes) {
  const lo = binarySearchLeft(sortedKeys, key);
  const results = [];
  for (let i = lo; i < sortedKeys.length && results.length < limit; i++) {
    const k = sortedKeys[i];
    if (!k.startsWith(key)) break;
    const idx = lookup[k];
    if (seenIndexes.has(idx)) continue;
    seenIndexes.add(idx);
    results.push([k, idx]);
  }
  return results;
}

function search(prefix, limit = 10) {
  const key = normalize(prefix);
  if (!key) return [];

  // Numeric prefix
  if (/^\d+$/.test(key)) {
    const results = [];
    for (let idx = 0; idx < 256 && results.length < limit; idx++) {
      if (String(idx).startsWith(key)) {
        results.push([BASE[idx] || String(idx), idx]);
      }
    }
    return results;
  }

  const seenIndexes = new Set();

  // English base words first
  const englishFirst = [];
  for (let idx = 0; idx < 256; idx++) {
    const base = BASE[idx];
    if (base && base.toLowerCase().startsWith(key)) {
      englishFirst.push([base.toLowerCase(), idx]);
      seenIndexes.add(idx);
    }
  }
  englishFirst.sort((a, b) => a[0] < b[0] ? -1 : 1);

  let results = englishFirst.slice(0, limit);
  let remaining = limit - results.length;

  // Primary binary search
  if (remaining > 0) {
    results = results.concat(searchSorted(SORTED_KEYS, LOOKUP, key, remaining, seenIndexes));
    remaining = limit - results.length;
  }

  // Article prefix stripping
  if (remaining > 0) {
    let altKey = null;
    for (const apo of ["'", "\u2019", "\u02bc"]) {
      if (key.startsWith("l" + apo)) { altKey = key.slice(("l" + apo).length); break; }
    }
    if (!altKey && key.startsWith("\u0627\u0644")) altKey = key.slice(2);
    if (!altKey && key.startsWith("\u05d4") && key.length > 1) altKey = key.slice(1);
    if (altKey) {
      results = results.concat(searchSorted(SORTED_KEYS, LOOKUP, altKey, remaining, seenIndexes));
      remaining = limit - results.length;
    }
  }

  // Inner-word matching
  if (remaining > 0) {
    const lo = binarySearchLeft(INNER_WORD_KEYS, key);
    for (let i = lo; i < INNER_WORD_KEYS.length && remaining > 0; i++) {
      if (!INNER_WORD_KEYS[i].startsWith(key)) break;
      const fullKey = INNER_WORDS[i][1];
      const idx = LOOKUP[fullKey];
      if (seenIndexes.has(idx)) continue;
      seenIndexes.add(idx);
      results.push([fullKey, idx]);
      remaining--;
    }
  }

  // Substring matching
  if (remaining > 0 && key.length >= 2) {
    for (const fullKey of SORTED_KEYS) {
      if (remaining <= 0) break;
      if (fullKey.includes(key)) {
        const idx = LOOKUP[fullKey];
        if (seenIndexes.has(idx)) continue;
        seenIndexes.add(idx);
        results.push([fullKey, idx]);
        remaining--;
      }
    }
  }

  return results;
}

// ── Mouse Entropy ───────────────────────────────────────────────

class MouseEntropy {
  constructor() {
    this._samples = 0;
    this._lastX = null;
    this._lastY = null;
    this._lastT = null;
    this._pool = [];
    this._pool.push(...DOMAIN, ...toBytes("-mouse-entropy"));
  }

  addSample(x, y) {
    const t = timingNs();
    if (x === this._lastX && y === this._lastY) return false;

    this._pool.push(...packLE_I(x), ...packLE_I(y), ...packLE_Q(t));

    if (this._lastX !== null) {
      const dx = x - this._lastX;
      const dy = y - this._lastY;
      const dt = t - this._lastT;
      this._pool.push(...packLE_I(dx), ...packLE_I(dy), ...packLE_Q(dt));
    }

    this._lastX = x; this._lastY = y; this._lastT = t;
    this._samples++;
    return true;
  }

  get bitsCollected() { return this._samples * 2; }
  get sampleCount() { return this._samples; }

  digest() { return sha512(new Uint8Array(this._pool)); }

  reset() {
    this._samples = 0; this._lastX = null; this._lastY = null; this._lastT = null;
    this._pool = [];
    this._pool.push(...DOMAIN, ...toBytes("-mouse-entropy"));
  }
}

// ── Entropy Collection ──────────────────────────────────────────

function cpuJitterEntropy() {
  const parts = [DOMAIN, toBytes("-cpu-jitter")];
  for (let s = 0; s < 64; s++) {
    const t1 = timingNs();
    let x = 0;
    for (let j = 0; j < 100; j++) {
      x ^= (x << 3) ^ (j * 7) ^ (x >>> 5);
      x = x & 0xffffffff;
    }
    const t2 = timingNs();
    parts.push(packLE_Q(t2 - t1), packLE_Q(t2));
  }
  return sha512(concatBytes(...parts));
}

function collectEntropy(nBytes, extraEntropy) {
  const parts = [];

  // Source 1+2: CSPRNG
  parts.push(randomBytes(64));
  parts.push(randomBytes(64));

  // Source 3: Timing jitter
  for (let i = 0; i < 32; i++) parts.push(packLE_Q(timingNs()));

  // Source 4: Process ID
  const pid = typeof process !== "undefined" ? process.pid || 0 : 0;
  parts.push(packLE_I(pid));

  // Source 5: CPU jitter
  parts.push(cpuJitterEntropy());

  // Source 6+7: Additional randomness from CSPRNG (thread/hw RNG not available in JS)
  parts.push(randomBytes(64));
  parts.push(randomBytes(32));

  if (extraEntropy) parts.push(toBytes(extraEntropy));

  const pool = concatBytes(...parts);

  // HKDF-Extract: condense the entropy pool into a PRK
  const prk = hmacSha512(DOMAIN, pool);

  // HKDF-Expand: stretch to arbitrary output length
  const info = concatBytes(DOMAIN, toBytes("-entropy"));
  return hkdfExpand(prk, info, nBytes);
}

// ── Checksum ────────────────────────────────────────────────────

function computeChecksum(indexes) {
  const key = concatBytes(DOMAIN, toBytes("-checksum"));
  const digest = hmacSha256(key, new Uint8Array(indexes));
  return [digest[0], digest[1]];
}

function verifyChecksum(seed) {
  const indexes = toIndexes(seed);
  if (indexes.length !== 24 && indexes.length !== 36) return false;
  const data = indexes.slice(0, -2);
  const expected = computeChecksum(data);
  return constantTimeEqual(
    new Uint8Array([indexes[indexes.length - 2], indexes[indexes.length - 1]]),
    new Uint8Array(expected)
  );
}

// ── Index Conversion ────────────────────────────────────────────

function toIndexes(seed) {
  if (!seed || !seed.length) throw new Error("seed must not be empty");

  // Accept string phrases: split on whitespace into word array
  if (typeof seed === "string") {
    seed = seed.trim().split(/\s+/).filter(Boolean);
    if (seed.length === 0) throw new Error("seed must not be empty");
  }

  const first = seed[0];
  if (Array.isArray(first) || (typeof first === "object" && first !== null && "index" in first)) {
    return seed.map((item, i) => {
      const idx = Array.isArray(item) ? item[0] : item.index;
      if (!Number.isInteger(idx) || idx < 0 || idx > 255) {
        throw new Error(`seed index out of range at position ${i}: ${idx}`);
      }
      return idx;
    });
  }
  if (typeof first === "number") {
    for (const v of seed) {
      if (!Number.isInteger(v) || v < 0 || v > 255) {
        throw new Error(`seed index out of range: ${v}`);
      }
    }
    return [...seed];
  }
  // Resolve words
  const { indexes, errors } = resolve([...seed], true);
  if (errors.length > 0) {
    const bad = errors.map(([i, w]) => `'${w}' (pos ${i})`).join(", ");
    throw new Error(`could not resolve: ${bad}`);
  }
  return indexes;
}

// ── Key Derivation ──────────────────────────────────────────────

function getSeed(words, passphrase = "") {
  const indexes = toIndexes(words);
  if (indexes.length !== 24 && indexes.length !== 36) {
    throw new Error(`seed must be 24 or 36 words, got ${indexes.length}`);
  }

  const data = indexes.slice(0, -2);
  const expected = computeChecksum(data);
  if (!constantTimeEqual(
    new Uint8Array([indexes[indexes.length - 2], indexes[indexes.length - 1]]),
    new Uint8Array(expected)
  )) {
    throw new Error("invalid seed checksum");
  }

  // Step 1: Position-tagged payload
  const payloadParts = [];
  for (let pos = 0; pos < data.length; pos++) {
    payloadParts.push(packLE_BB(pos, data[pos]));
  }
  if (passphrase) payloadParts.push(toBytes(passphrase.normalize("NFKC")));
  const payload = concatBytes(...payloadParts);

  // Step 2: HKDF-Extract
  const prk = hmacSha512(DOMAIN, payload);
  zeroize(payload);

  // Step 3: Chained KDF — PBKDF2-SHA512 → Argon2id (defense in depth)
  const salt = concatBytes(DOMAIN, toBytes("-stretch"));
  const stage1 = pbkdf2Sha512(prk, concatBytes(salt, toBytes("-pbkdf2")), PBKDF2_ITERATIONS, 64);
  zeroize(prk);
  const stretched = argon2id(
    stage1,
    concatBytes(salt, toBytes("-argon2id")),
    ARGON2_TIME, ARGON2_MEMORY, ARGON2_PARALLEL, ARGON2_HASHLEN
  );
  zeroize(stage1);

  // Step 4: HKDF-Expand
  const master = hkdfExpand(stretched, concatBytes(DOMAIN, toBytes("-master")), 64);
  zeroize(stretched);
  return master;
}

async function getSeedAsync(words, passphrase = "") {
  const indexes = toIndexes(words);
  if (indexes.length !== 24 && indexes.length !== 36) {
    throw new Error(`seed must be 24 or 36 words, got ${indexes.length}`);
  }

  const data = indexes.slice(0, -2);
  const expected = computeChecksum(data);
  if (!constantTimeEqual(
    new Uint8Array([indexes[indexes.length - 2], indexes[indexes.length - 1]]),
    new Uint8Array(expected)
  )) {
    throw new Error("invalid seed checksum");
  }

  const payloadParts = [];
  for (let pos = 0; pos < data.length; pos++) {
    payloadParts.push(packLE_BB(pos, data[pos]));
  }
  if (passphrase) payloadParts.push(toBytes(passphrase.normalize("NFKC")));
  const payload = concatBytes(...payloadParts);

  const prk = hmacSha512(DOMAIN, payload);
  zeroize(payload);

  // Chained KDF: PBKDF2-SHA512 → Argon2id (defense in depth)
  const salt = concatBytes(DOMAIN, toBytes("-stretch"));

  // Stage 1: PBKDF2-SHA512
  const stage1 = await pbkdf2Sha512Async(prk, concatBytes(salt, toBytes("-pbkdf2")), PBKDF2_ITERATIONS, 64);
  zeroize(prk);

  // Stage 2: Argon2id on top of PBKDF2 output
  const stretched = argon2id(
    stage1,
    concatBytes(salt, toBytes("-argon2id")),
    ARGON2_TIME, ARGON2_MEMORY, ARGON2_PARALLEL, ARGON2_HASHLEN
  );
  zeroize(stage1);

  const master = hkdfExpand(stretched, concatBytes(DOMAIN, toBytes("-master")), 64);
  zeroize(stretched);
  return master;
}

function getProfile(masterKey, profilePassword) {
  if (!profilePassword) return masterKey;
  const payload = concatBytes(DOMAIN, toBytes("-profile"), toBytes(profilePassword));
  const derived = hmacSha512(masterKey, payload);
  zeroize(payload);
  return derived;
}

// ── Quantum Key Derivation ──────────────────────────────────────

const QUANTUM_SEED_SIZES = {
  "ml-dsa-65": 32,
  "slh-dsa-shake-128s": 48,
  "ml-kem-768": 64,
  // Hybrid classical + post-quantum (defense in depth)
  "hybrid-dsa-65": 64,        // Ed25519 seed (32B) + ML-DSA-65 seed (32B)
  "hybrid-kem-768": 96,       // X25519 seed (32B) + ML-KEM-768 seed (64B d||z)
};

function getQuantumSeed(masterKey, algorithm = "ml-dsa-65", keyIndex = 0) {
  masterKey = toBytes(masterKey);
  if (masterKey.length !== 64) throw new Error(`masterKey must be 64 bytes, got ${masterKey.length}`);
  const size = QUANTUM_SEED_SIZES[algorithm];
  if (size === undefined) {
    throw new Error(`Unknown quantum algorithm: '${algorithm}'. Supported: ${Object.keys(QUANTUM_SEED_SIZES).join(", ")}`);
  }
  const info = concatBytes(DOMAIN, toBytes("-quantum-"), toBytes(algorithm), packLE_I(keyIndex));
  return hkdfExpand(masterKey, info, size);
}

function generateQuantumKeypair(masterKey, algorithm = "ml-dsa-65", keyIndex = 0) {
  const quantumSeed = getQuantumSeed(masterKey, algorithm, keyIndex);
  if (algorithm === "ml-dsa-65") {
    const { mlKeygen } = require("./crypto/ml_dsa");
    return mlKeygen(quantumSeed);
  } else if (algorithm === "slh-dsa-shake-128s") {
    const { slhKeygen } = require("./crypto/slh_dsa");
    return slhKeygen(quantumSeed);
  } else if (algorithm === "ml-kem-768") {
    const { mlKemKeygen } = require("./crypto/ml_kem");
    return mlKemKeygen(quantumSeed);
  } else if (algorithm === "hybrid-dsa-65") {
    const { hybridDsaKeygen } = require("./crypto/hybrid_dsa");
    return hybridDsaKeygen(quantumSeed);
  } else if (algorithm === "hybrid-kem-768") {
    const { hybridKemKeygen } = require("./crypto/hybrid_kem");
    const { ek, dk } = hybridKemKeygen(quantumSeed);
    return { sk: dk, pk: ek }; // (secret=dk, public=ek) to match (sk, pk) convention
  }
  throw new Error(`Unknown quantum algorithm: '${algorithm}'`);
}

// ── Word Generation ─────────────────────────────────────────────

function generateWords(wordCount = 36, extraEntropy = null, language = null) {
  if (wordCount !== 24 && wordCount !== 36) {
    throw new Error("wordCount must be 24 or 36");
  }

  const dataCount = wordCount - 2;
  let wordMap = BASE;
  if (language && language !== "english") {
    const lang = LANGUAGES[language];
    if (!lang) throw new Error(`Unknown language: '${language}'`);
    wordMap = {};
    for (const [idx, word] of Object.entries(lang.words)) {
      wordMap[parseInt(idx)] = word;
    }
  }

  // Validate entropy (simplified: single test)
  for (let attempt = 0; attempt < 10; attempt++) {
    const testSample = collectEntropy(1024, extraEntropy);
    const tests = testEntropy(testSample);
    const allPass = Object.values(tests).every(t => t.pass);
    if (allPass) {
      const entropy = collectEntropy(dataCount, extraEntropy);
      const indexes = [...entropy];
      indexes.push(...computeChecksum(indexes));
      return indexes.map((idx, pos) => ({ index: idx, word: wordMap[idx] || String(idx) }));
    }
  }
  throw new Error("Entropy failed validation 10 times -- RNG may be compromised.");
}

// ── Fingerprint ─────────────────────────────────────────────────

function getFingerprint(seed, passphrase = "") {
  const indexes = toIndexes(seed);
  if (indexes.length !== 24 && indexes.length !== 36) {
    throw new Error(`seed must be 24 or 36 words, got ${indexes.length}`);
  }
  const data = indexes.slice(0, -2);

  let key;
  if (passphrase) {
    key = getSeed(indexes, passphrase);
  } else {
    const parts = [];
    for (let pos = 0; pos < data.length; pos++) {
      parts.push(packLE_BB(pos, data[pos]));
    }
    key = hmacSha512(DOMAIN, concatBytes(...parts));
  }

  const hex = Array.from(key.subarray(0, 4), b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  return hex;
}

// ── Entropy Bits ────────────────────────────────────────────────

function getEntropyBits(wordCount, passphrase = "") {
  const seedBits = (wordCount - 2) * 8;
  if (!passphrase) return seedBits;

  let hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false, hasUnicode = false;
  for (const c of passphrase) {
    if (/[a-z]/.test(c)) hasLower = true;
    else if (/[A-Z]/.test(c)) hasUpper = true;
    else if (/\d/.test(c)) hasDigit = true;
    else if (c.charCodeAt(0) > 127) hasUnicode = true;
    else if (/[^a-zA-Z0-9]/.test(c)) hasSymbol = true;
  }

  let pool = 0;
  if (hasLower) pool += 26;
  if (hasUpper) pool += 26;
  if (hasDigit) pool += 10;
  if (hasSymbol) pool += 33;
  if (hasUnicode) pool += 100;
  if (pool === 0) return seedBits;

  return seedBits + Math.log2(pool) * passphrase.length;
}

// ── KDF Info ────────────────────────────────────────────────────

function kdfInfo() {
  return `PBKDF2-SHA512 (${PBKDF2_ITERATIONS.toLocaleString()} rounds) + Argon2id (mem=${ARGON2_MEMORY}KB, t=${ARGON2_TIME}, p=${ARGON2_PARALLEL})`;
}

// ── Entropy Testing ─────────────────────────────────────────────

function testEntropy(data) {
  const nBits = data.length * 8;
  const bits = [];
  for (const byte of data) {
    for (let bp = 7; bp >= 0; bp--) bits.push((byte >> bp) & 1);
  }

  const results = {};

  // Monobit
  const ones = bits.reduce((s, b) => s + b, 0);
  const sScore = Math.abs(2 * ones - nBits) / Math.sqrt(nBits);
  results.monobit = { pass: sScore < 2.576, onesRatio: ones / nBits, zScore: sScore };

  // Chi-squared
  const observed = new Array(256).fill(0);
  for (const byte of data) observed[byte]++;
  const expected = data.length / 256;
  const chi2 = observed.reduce((s, o) => s + (o - expected) ** 2 / expected, 0);
  results.chi_squared = { pass: chi2 < 310.5, chi2 };

  // Runs
  const pi = ones / nBits;
  let runsPass, runsZ;
  if (Math.abs(pi - 0.5) >= 2 / Math.sqrt(nBits)) {
    runsPass = false; runsZ = Infinity;
  } else {
    let runs = 1;
    for (let i = 1; i < nBits; i++) { if (bits[i] !== bits[i - 1]) runs++; }
    const expectedRuns = 2 * nBits * pi * (1 - pi) + 1;
    const stdRuns = 2 * Math.sqrt(2 * nBits) * pi * (1 - pi);
    runsZ = stdRuns === 0 ? Infinity : Math.abs(runs - expectedRuns) / stdRuns;
    runsPass = runsZ < 2.576;
  }
  results.runs = { pass: runsPass, zScore: runsZ };

  // Autocorrelation
  let autocorrPass = true, worstZ = 0;
  for (let d = 1; d <= 16; d++) {
    let matches = 0;
    for (let i = 0; i < nBits - d; i++) { if (bits[i] === bits[i + d]) matches++; }
    const total = nBits - d;
    const z = Math.abs(2 * matches - total) / Math.sqrt(total);
    if (z > worstZ) worstZ = z;
    if (z >= 3.42) autocorrPass = false;
  }
  results.autocorrelation = { pass: autocorrPass, worstZ };

  return results;
}

function verifyRandomness(sampleBytes = null, sampleSize = 2048, numSamples = 5) {
  const samples = sampleBytes ? [toBytes(sampleBytes)] :
    Array.from({ length: numSamples }, () => collectEntropy(sampleSize));

  const allResults = samples.map((data, si) => ({ sample: si, tests: testEntropy(data) }));

  const testNames = ["monobit", "chi_squared", "runs", "autocorrelation"];
  let overallPass = true;
  const testSummary = [];

  for (const name of testNames) {
    const failedCount = allResults.filter(r => !r.tests[name].pass).length;
    const majorityFailed = failedCount > allResults.length / 2;
    if (majorityFailed) overallPass = false;
    testSummary.push({ test: name, pass: !majorityFailed });
  }

  return { pass: overallPass, tests: testSummary, samples: allResults };
}

// ── Languages ───────────────────────────────────────────────────

function getLanguages() {
  const results = [["english", "English"]];
  for (const code of Object.keys(LANGUAGES).sort()) {
    if (code === "english") continue;
    results.push([code, LANGUAGES[code].label]);
  }
  return results;
}

// ── Exports ─────────────────────────────────────────────────────

module.exports = {
  VERSION,
  generateWords,
  resolve,
  search,
  getLanguages,
  verifyChecksum,
  getSeed,
  getSeedAsync,
  getProfile,
  getFingerprint,
  getEntropyBits,
  getQuantumSeed,
  generateQuantumKeypair,
  MouseEntropy,
  verifyRandomness,
  kdfInfo,
  DARK_VISUALS,
  BASE_WORDS,
};
