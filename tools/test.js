// Copyright (c) 2026 Lock.com — MIT License

"use strict";

// Basic test harness — round-trip tests, edge cases, and cross-checks.
// Run with: node tools/test.js

const crypto = require("../crypto");
const { toBytes, randomBytes, constantTimeEqual } = require("../crypto/utils");

let passed = 0;
let failed = 0;

function assert(cond, msg) {
  if (cond) {
    passed++;
  } else {
    failed++;
    console.error("  FAIL:", msg);
  }
}

function section(name) {
  console.log(`\n── ${name} ──`);
}

// ── Ed25519 ───────────────────────────────────────────────────────

section("Ed25519");

(() => {
  const seed = randomBytes(32);
  const { sk, pk } = crypto.ed25519Keygen(seed);
  assert(sk.length === 64, "sk should be 64 bytes");
  assert(pk.length === 32, "pk should be 32 bytes");

  // Round-trip sign/verify with Uint8Array
  const msg = new TextEncoder().encode("hello ed25519");
  const sig = crypto.ed25519Sign(msg, sk);
  assert(sig.length === 64, "sig should be 64 bytes");
  assert(crypto.ed25519Verify(msg, sig, pk), "valid sig should verify");

  // Verify with string message (toBytes normalization)
  const sig2 = crypto.ed25519Sign("hello ed25519", sk);
  assert(crypto.ed25519Verify("hello ed25519", sig2, pk), "string message should work");

  // Tampered message should fail
  assert(!crypto.ed25519Verify(new TextEncoder().encode("tampered"), sig, pk), "tampered msg should fail");

  // Tampered signature should fail
  const badSig = new Uint8Array(sig);
  badSig[0] ^= 0xff;
  assert(!crypto.ed25519Verify(msg, badSig, pk), "tampered sig should fail");

  // Wrong key should fail
  const { pk: pk2 } = crypto.ed25519Keygen(randomBytes(32));
  assert(!crypto.ed25519Verify(msg, sig, pk2), "wrong key should fail");

  // Cross-check with Node.js crypto if available
  try {
    const nodeCrypto = require("crypto");
    const skDer = Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.from(seed),
    ]);
    const privateKey = nodeCrypto.createPrivateKey({ key: skDer, format: "der", type: "pkcs8" });
    const nativeSig = nodeCrypto.sign(null, Buffer.from(msg), privateKey);
    // Our verify should accept native-generated signatures
    assert(crypto.ed25519Verify(msg, new Uint8Array(nativeSig), pk), "native sig should verify");
    console.log("  Ed25519 cross-check with Node.js crypto: OK");
  } catch (_) {
    console.log("  Ed25519 cross-check: skipped (native not available)");
  }

  console.log("  Ed25519 round-trip: OK");
})();

// ── X25519 ────────────────────────────────────────────────────────

section("X25519");

(() => {
  const seedA = randomBytes(32);
  const seedB = randomBytes(32);
  const alice = crypto.x25519Keygen(seedA);
  const bob = crypto.x25519Keygen(seedB);

  assert(alice.sk.length === 32, "sk should be 32 bytes");
  assert(alice.pk.length === 32, "pk should be 32 bytes");

  const ssA = crypto.x25519(alice.sk, bob.pk);
  const ssB = crypto.x25519(bob.sk, alice.pk);
  assert(constantTimeEqual(ssA, ssB), "shared secrets should match");

  // Cross-check with Node.js crypto if available
  try {
    const nodeCrypto = require("crypto");
    const skDer = Buffer.concat([
      Buffer.from("302e020100300506032b656e04220420", "hex"),
      Buffer.from(alice.sk),
    ]);
    const pkDer = Buffer.concat([
      Buffer.from("302a300506032b656e032100", "hex"),
      Buffer.from(bob.pk),
    ]);
    const privateKey = nodeCrypto.createPrivateKey({ key: skDer, format: "der", type: "pkcs8" });
    const publicKey = nodeCrypto.createPublicKey({ key: pkDer, format: "der", type: "spki" });
    const nativeSs = nodeCrypto.diffieHellman({ privateKey, publicKey });
    assert(constantTimeEqual(ssA, new Uint8Array(nativeSs)), "shared secret should match native");
    console.log("  X25519 cross-check with Node.js crypto: OK");
  } catch (_) {
    console.log("  X25519 cross-check: skipped (native not available)");
  }

  console.log("  X25519 key exchange: OK");
})();

// ── ML-DSA-65 ─────────────────────────────────────────────────────

section("ML-DSA-65");

(() => {
  const seed = randomBytes(32);
  const { sk, pk } = crypto.mlKeygen(seed);
  assert(sk.length === 4032, "sk should be 4032 bytes");
  assert(pk.length === 1952, "pk should be 1952 bytes");

  // Round-trip with Uint8Array message (raw/interoperable API)
  const msg = new TextEncoder().encode("hello ml-dsa");
  const sig = crypto.mlSign(msg, sk);
  assert(sig.length === 3309, "sig should be 3309 bytes");
  assert(crypto.mlVerify(msg, sig, pk), "valid sig should verify");

  // String message (toBytes normalization)
  const sig2 = crypto.mlSign("hello ml-dsa", sk);
  assert(crypto.mlVerify("hello ml-dsa", sig2, pk), "string message should work");

  // Context string (FIPS 204 pure mode via mlSignWithContext)
  const ctx = new TextEncoder().encode("test-ctx");
  const sigCtx = crypto.mlSignWithContext(msg, sk, ctx);
  assert(crypto.mlVerifyWithContext(msg, sigCtx, pk, ctx), "ctx sig should verify with same ctx");
  assert(!crypto.mlVerifyWithContext(msg, sigCtx, pk), "ctx sig should fail without ctx");

  // String context
  const sigCtx2 = crypto.mlSignWithContext(msg, sk, "test-ctx");
  assert(crypto.mlVerifyWithContext(msg, sigCtx2, pk, "test-ctx"), "string ctx should work");

  // Raw signature should NOT verify under context mode (and vice versa)
  assert(!crypto.mlVerifyWithContext(msg, sig, pk, ctx), "raw sig should fail under context verification");
  assert(!crypto.mlVerify(msg, sigCtx, pk), "context sig should fail under raw verification");

  // Deterministic mode
  const sigDet1 = crypto.mlSign(msg, sk, { deterministic: true });
  const sigDet2 = crypto.mlSign(msg, sk, { deterministic: true });
  assert(constantTimeEqual(sigDet1, sigDet2), "deterministic sigs should be identical");

  // Tampered
  assert(!crypto.mlVerify(new TextEncoder().encode("tampered"), sig, pk), "tampered msg should fail");

  console.log("  ML-DSA-65 round-trip: OK");
})();

// ── ML-DSA-65 Async ───────────────────────────────────────────────

section("ML-DSA-65 Async");

let asyncDone = false;

(async () => {
  try {
    const seed = randomBytes(32);
    const { sk, pk } = crypto.mlKeygen(seed);
    const msg = new TextEncoder().encode("hello ml-dsa-async");

    const sig = await crypto.mlSignAsync(msg, sk);
    assert(sig.length === 3309, "async sig should be 3309 bytes");

    const valid = await crypto.mlVerifyAsync(msg, sig, pk);
    assert(valid, "async verify should pass");

    const invalid = await crypto.mlVerifyAsync(new TextEncoder().encode("tampered"), sig, pk);
    assert(!invalid, "async verify should fail on tampered msg");

    console.log("  ML-DSA-65 Async: OK");
  } catch (e) {
    console.error("  FAIL: ML-DSA async exception:", e.message);
    failed++;
  }
  asyncDone = true;
})();

// ── ML-KEM-768 ────────────────────────────────────────────────────

section("ML-KEM-768");

(() => {
  const seed = randomBytes(64);
  const { ek, dk } = crypto.mlKemKeygen(seed);
  assert(ek.length === 1184, "ek should be 1184 bytes");
  assert(dk.length === 2400, "dk should be 2400 bytes");

  // Encaps/Decaps round-trip
  const { ct, ss: ssEnc } = crypto.mlKemEncaps(ek);
  assert(ct.length === 1088, "ct should be 1088 bytes");
  assert(ssEnc.length === 32, "ss should be 32 bytes");

  const ssDec = crypto.mlKemDecaps(dk, ct);
  assert(constantTimeEqual(ssEnc, ssDec), "encaps/decaps shared secrets should match");

  // Deterministic encaps
  const rnd = randomBytes(32);
  const r1 = crypto.mlKemEncaps(ek, rnd);
  const r2 = crypto.mlKemEncaps(ek, rnd);
  assert(constantTimeEqual(r1.ct, r2.ct), "deterministic encaps should produce same ct");
  assert(constantTimeEqual(r1.ss, r2.ss), "deterministic encaps should produce same ss");

  // Tampered ciphertext should produce different (implicit rejection) ss
  const badCt = new Uint8Array(ct);
  badCt[0] ^= 0xff;
  const ssBad = crypto.mlKemDecaps(dk, badCt);
  assert(!constantTimeEqual(ssEnc, ssBad), "tampered ct should produce different ss (implicit rejection)");

  console.log("  ML-KEM-768 round-trip: OK");
})();

// ── Hybrid DSA ────────────────────────────────────────────────────

section("Hybrid Ed25519 + ML-DSA-65");

(() => {
  const seed = randomBytes(64);
  const { sk, pk } = crypto.hybridDsaKeygen(seed);
  assert(sk.length === 4096, "sk should be 4096 bytes");
  assert(pk.length === 1984, "pk should be 1984 bytes");

  const msg = new TextEncoder().encode("hello hybrid");
  const sig = crypto.hybridDsaSign(msg, sk);
  assert(sig.length === 3373, "sig should be 3373 bytes");
  assert(crypto.hybridDsaVerify(msg, sig, pk), "valid sig should verify");

  // String message
  assert(crypto.hybridDsaVerify("hello hybrid", crypto.hybridDsaSign("hello hybrid", sk), pk),
    "string message should work");

  // Tampered
  assert(!crypto.hybridDsaVerify(new TextEncoder().encode("tampered"), sig, pk), "tampered should fail");

  // Verify stripping resistance: neither component should work standalone
  const edSig = sig.subarray(0, 64);
  const mlSig = sig.subarray(64);
  const edPk = pk.subarray(0, 32);
  const mlPk = pk.subarray(32);
  assert(!crypto.ed25519Verify(msg, edSig, edPk), "Ed25519 component should not verify standalone (domain-prefixed)");
  assert(!crypto.mlVerify(msg, mlSig, mlPk), "ML-DSA component should not verify standalone (domain-prefixed)");

  console.log("  Hybrid DSA round-trip: OK");
})();

// ── Hybrid KEM ────────────────────────────────────────────────────

section("Hybrid X25519 + ML-KEM-768");

(() => {
  const seed = randomBytes(96);
  const { ek, dk } = crypto.hybridKemKeygen(seed);
  assert(ek.length === 1216, "ek should be 1216 bytes");
  assert(dk.length === 2432, "dk should be 2432 bytes");

  const { ct, ss: ssEnc } = crypto.hybridKemEncaps(ek);
  assert(ct.length === 1120, "ct should be 1120 bytes");
  assert(ssEnc.length === 32, "ss should be 32 bytes");

  const ssDec = crypto.hybridKemDecaps(dk, ct);
  assert(constantTimeEqual(ssEnc, ssDec), "encaps/decaps shared secrets should match");

  // Tampered X25519 part of ciphertext — should not throw
  const badCt = new Uint8Array(ct);
  badCt[0] ^= 0xff; // tamper X25519 ephemeral pk
  try {
    const ssBad = crypto.hybridKemDecaps(dk, badCt);
    assert(!constantTimeEqual(ssEnc, ssBad), "tampered ct should produce different ss");
    console.log("  Hybrid KEM tampered X25519: OK (no throw)");
  } catch (e) {
    assert(false, "hybridKemDecaps should not throw on tampered X25519: " + e.message);
  }

  console.log("  Hybrid KEM round-trip: OK");
})();

// ── SHA-3 / SHAKE ─────────────────────────────────────────────────

section("SHA-3 / SHAKE");

(() => {
  // Empty input hash (known answer)
  const h = crypto.sha3_256(new Uint8Array(0));
  assert(h.length === 32, "sha3-256 should return 32 bytes");

  // String input (toBytes in sha3)
  const h2 = crypto.sha3_256("abc");
  assert(h2.length === 32, "sha3-256 of string should work");

  // ArrayBuffer input
  const abuf = new ArrayBuffer(3);
  new Uint8Array(abuf).set([0x61, 0x62, 0x63]); // "abc"
  const h3 = crypto.sha3_256(abuf);
  assert(constantTimeEqual(h2, h3), "sha3-256 of ArrayBuffer should match string");

  // SHAKE determinism
  const s1 = crypto.shake256(new Uint8Array([1, 2, 3]), 64);
  const s2 = crypto.shake256(new Uint8Array([1, 2, 3]), 64);
  assert(constantTimeEqual(s1, s2), "SHAKE should be deterministic");

  // SHAKE prefix consistency: shake256(data, 64) prefix should match shake256(data, 128)
  const long = crypto.shake256(new Uint8Array([1, 2, 3]), 128);
  assert(constantTimeEqual(s1, long.subarray(0, 64)), "SHAKE output should be prefix-consistent");

  console.log("  SHA-3/SHAKE: OK");
})();

// ── Argon2id ────────────────────────────────────────────────────

section("Argon2id");

(() => {
  // Basic round-trip: argon2id should return hashLen bytes
  const password = new TextEncoder().encode("password");
  const salt = new TextEncoder().encode("saltsalt"); // 8 bytes min
  const hash = crypto.argon2id(password, salt, 1, 64, 1, 32);
  assert(hash instanceof Uint8Array, "argon2id should return Uint8Array");
  assert(hash.length === 32, "argon2id hash should be 32 bytes");

  // Deterministic: same input -> same output
  const hash2 = crypto.argon2id(password, salt, 1, 64, 1, 32);
  assert(constantTimeEqual(hash, hash2), "argon2id should be deterministic");

  // Different password -> different hash
  const hash3 = crypto.argon2id(new TextEncoder().encode("other"), salt, 1, 64, 1, 32);
  assert(!constantTimeEqual(hash, hash3), "different password should produce different hash");

  // Input validation
  try { crypto.argon2id(password, salt, 0, 64, 1, 32); assert(false, "timeCost=0 should throw"); }
  catch (_) { assert(true, "timeCost=0 throws"); }

  try { crypto.argon2id(password, salt, 1, 4, 1, 32); assert(false, "memoryCost=4 should throw"); }
  catch (_) { assert(true, "memoryCost too low throws"); }

  try { crypto.argon2id(password, new Uint8Array(4), 1, 64, 1, 32); assert(false, "short salt should throw"); }
  catch (_) { assert(true, "short salt throws"); }

  console.log("  Argon2id: OK");
})();

// ── PBKDF2 Validation ────────────────────────────────────────────

section("PBKDF2 Validation");

(() => {
  // Input validation
  try { crypto.pbkdf2Sha512("pass", "salt", 0, 32); assert(false, "iterations=0 should throw"); }
  catch (_) { assert(true, "iterations=0 throws"); }

  try { crypto.pbkdf2Sha512("pass", "salt", 1, 0); assert(false, "dkLen=0 should throw"); }
  catch (_) { assert(true, "dkLen=0 throws"); }

  try { crypto.pbkdf2Sha512("pass", "salt", -1, 32); assert(false, "iterations=-1 should throw"); }
  catch (_) { assert(true, "iterations=-1 throws"); }

  // Basic round-trip
  const dk = crypto.pbkdf2Sha512("password", "salt", 1, 64);
  assert(dk instanceof Uint8Array && dk.length === 64, "pbkdf2 should return 64 bytes");

  console.log("  PBKDF2 validation: OK");
})();

// ── toBytes normalization ─────────────────────────────────────────

section("toBytes normalization");

(() => {
  // String
  const a = toBytes("hello");
  assert(a instanceof Uint8Array, "string -> Uint8Array");
  assert(a.length === 5, "string length correct");

  // Array
  const b = toBytes([1, 2, 3]);
  assert(b instanceof Uint8Array, "array -> Uint8Array");
  assert(b[0] === 1 && b[1] === 2 && b[2] === 3, "array values correct");

  // Uint8Array passthrough
  const c = new Uint8Array([4, 5]);
  assert(toBytes(c) === c, "Uint8Array should pass through");

  // ArrayBuffer
  const abuf = new ArrayBuffer(3);
  new Uint8Array(abuf).set([10, 20, 30]);
  const d = toBytes(abuf);
  assert(d instanceof Uint8Array && d[0] === 10 && d[1] === 20 && d[2] === 30, "ArrayBuffer should convert");

  // ArrayBuffer view
  const buf = new ArrayBuffer(4);
  new Uint8Array(buf)[0] = 42;
  const e = toBytes(new DataView(buf));
  assert(e instanceof Uint8Array && e[0] === 42, "ArrayBuffer view should convert");

  // Unsupported type
  try {
    toBytes(123);
    assert(false, "number should throw");
  } catch (_) {
    assert(true, "number throws");
  }

  console.log("  toBytes: OK");
})();

// ── Helpers ───────────────────────────────────────────────────────

function hexToBytes(hex) {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) b[i / 2] = parseInt(hex.substr(i, 2), 16);
  return b;
}
function bytesToHex(b) {
  return Array.from(b).map(x => x.toString(16).padStart(2, "0")).join("");
}

// ── X25519 Pure JS Fallback (RFC 7748 Test Vectors) ──────────────

section("X25519 Pure JS (RFC 7748)");

(() => {
  const { x25519Raw } = require("../crypto/x25519");

  // RFC 7748 Section 5.2 — Alice
  const aliceSk = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  const alicePkExpected = hexToBytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
  const basepoint = new Uint8Array(32);
  basepoint[0] = 9;
  const alicePk = x25519Raw(aliceSk, basepoint);
  assert(bytesToHex(alicePk) === bytesToHex(alicePkExpected),
    "RFC 7748 Alice pk: got " + bytesToHex(alicePk));

  // RFC 7748 Section 5.2 — Bob
  const bobSk = hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
  const bobPkExpected = hexToBytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
  const bobPk = x25519Raw(bobSk, basepoint);
  assert(bytesToHex(bobPk) === bytesToHex(bobPkExpected),
    "RFC 7748 Bob pk: got " + bytesToHex(bobPk));

  // Shared secret (Alice sk * Bob pk) == (Bob sk * Alice pk)
  const ssExpected = hexToBytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
  const ssAB = x25519Raw(aliceSk, bobPk);
  const ssBA = x25519Raw(bobSk, alicePk);
  assert(bytesToHex(ssAB) === bytesToHex(ssExpected),
    "RFC 7748 shared secret A*B: got " + bytesToHex(ssAB));
  assert(bytesToHex(ssBA) === bytesToHex(ssExpected),
    "RFC 7748 shared secret B*A: got " + bytesToHex(ssBA));

  // RFC 7748 Section 6.1 — iteration test (1 iteration)
  let k = new Uint8Array(32); k[0] = 9;
  let u = new Uint8Array(32); u[0] = 9;
  const iter1Expected = "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079";
  const r = x25519Raw(k, u);
  assert(bytesToHex(r) === iter1Expected,
    "RFC 7748 iteration 1: got " + bytesToHex(r));

  // RFC 7748 Section 6.1 — iteration test (1000 iterations)
  k = new Uint8Array(32); k[0] = 9;
  u = new Uint8Array(32); u[0] = 9;
  const iter1000Expected = "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51";
  for (let i = 0; i < 1000; i++) {
    const out = x25519Raw(k, u);
    u = k;
    k = out;
  }
  assert(bytesToHex(k) === iter1000Expected,
    "RFC 7748 iteration 1000: got " + bytesToHex(k));

  // Cross-check: x25519Raw vs native x25519 (random keys)
  for (let i = 0; i < 5; i++) {
    const sk = randomBytes(32);
    const native = crypto.x25519Keygen(sk);
    const pureJs = x25519Raw(sk, basepoint);
    assert(constantTimeEqual(native.pk, pureJs),
      `x25519Raw vs native keygen mismatch (trial ${i + 1})`);
  }

  console.log("  X25519 pure JS (RFC 7748): OK");
})();

// ── SHA-256 Known-Answer Tests (NIST) ────────────────────────────

section("SHA-256 Known-Answer (NIST)");

(() => {
  // SHA-256("") = e3b0c442...
  const h0 = crypto.sha256(new Uint8Array(0));
  assert(bytesToHex(h0) === "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "SHA-256 empty: " + bytesToHex(h0));

  // SHA-256("abc") = ba7816bf...
  const h1 = crypto.sha256(new TextEncoder().encode("abc"));
  assert(bytesToHex(h1) === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "SHA-256 abc: " + bytesToHex(h1));

  // SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
  const h2 = crypto.sha256(new TextEncoder().encode(
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
  assert(bytesToHex(h2) === "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    "SHA-256 two-block: " + bytesToHex(h2));

  console.log("  SHA-256 NIST vectors: OK");
})();

// ── SHA-512 Known-Answer Tests (NIST) ────────────────────────────

section("SHA-512 Known-Answer (NIST)");

(() => {
  // SHA-512("") = cf83e135...
  const h0 = crypto.sha512(new Uint8Array(0));
  assert(bytesToHex(h0) === "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    "SHA-512 empty: " + bytesToHex(h0));

  // SHA-512("abc") = ddaf35a1...
  const h1 = crypto.sha512(new TextEncoder().encode("abc"));
  assert(bytesToHex(h1) === "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    "SHA-512 abc: " + bytesToHex(h1));

  console.log("  SHA-512 NIST vectors: OK");
})();

// ── HMAC Known-Answer Tests (RFC 4231) ───────────────────────────

section("HMAC Known-Answer (RFC 4231)");

(() => {
  // Test Case 2: Key = "Jefe", Data = "what do ya want for nothing?"
  const key = new TextEncoder().encode("Jefe");
  const data = new TextEncoder().encode("what do ya want for nothing?");

  const hmac256 = crypto.hmacSha256(key, data);
  assert(bytesToHex(hmac256) === "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    "HMAC-SHA-256 TC2: " + bytesToHex(hmac256));

  const hmac512 = crypto.hmacSha512(key, data);
  assert(bytesToHex(hmac512) === "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
    "HMAC-SHA-512 TC2: " + bytesToHex(hmac512));

  // Test Case 1: Key = 20 bytes of 0x0b, Data = "Hi There"
  const key1 = new Uint8Array(20).fill(0x0b);
  const data1 = new TextEncoder().encode("Hi There");
  const hmac256_1 = crypto.hmacSha256(key1, data1);
  assert(bytesToHex(hmac256_1) === "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    "HMAC-SHA-256 TC1: " + bytesToHex(hmac256_1));

  console.log("  HMAC RFC 4231 vectors: OK");
})();

// ── SHA-3 Known-Answer Tests (NIST) ─────────────────────────────

section("SHA-3 Known-Answer (NIST)");

(() => {
  // SHA3-256("") = a7ffc6f8...
  const h0 = crypto.sha3_256(new Uint8Array(0));
  assert(bytesToHex(h0) === "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    "SHA3-256 empty: " + bytesToHex(h0));

  // SHA3-256("abc") = 3a985da7...
  const h1 = crypto.sha3_256(new TextEncoder().encode("abc"));
  assert(bytesToHex(h1) === "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    "SHA3-256 abc: " + bytesToHex(h1));

  // SHA3-512("abc") = b751850b...
  const h2 = crypto.sha3_512(new TextEncoder().encode("abc"));
  assert(bytesToHex(h2) === "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
    "SHA3-512 abc: " + bytesToHex(h2));

  console.log("  SHA-3 NIST vectors: OK");
})();

// ── SHAKE Known-Answer Tests ────────────────────────────────────

section("SHAKE Known-Answer");

(() => {
  // SHAKE-256("", 32) = 46b9dd2b...
  const s0 = crypto.shake256(new Uint8Array(0), 32);
  assert(bytesToHex(s0) === "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
    "SHAKE-256 empty/32: " + bytesToHex(s0));

  // SHAKE-128("", 32) = 7f9c2ba4...
  const s1 = crypto.shake128(new Uint8Array(0), 32);
  assert(bytesToHex(s1) === "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
    "SHAKE-128 empty/32: " + bytesToHex(s1));

  // SHAKE-256("abc", 32) = 483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739
  const s2 = crypto.shake256(new TextEncoder().encode("abc"), 32);
  assert(bytesToHex(s2) === "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739",
    "SHAKE-256 abc/32: " + bytesToHex(s2));

  console.log("  SHAKE vectors: OK");
})();

// ── Ed25519 Known-Answer Tests (RFC 8032) ────────────────────────

section("Ed25519 Known-Answer (RFC 8032)");

(() => {
  // Test Vector 1: empty message
  const seed1 = hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  const pkExpected1 = hexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  const sigExpected1 = hexToBytes("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

  const kp1 = crypto.ed25519Keygen(seed1);
  assert(bytesToHex(kp1.pk) === bytesToHex(pkExpected1),
    "Ed25519 TV1 pk: " + bytesToHex(kp1.pk));

  const sig1 = crypto.ed25519Sign(new Uint8Array(0), kp1.sk);
  assert(bytesToHex(sig1) === bytesToHex(sigExpected1),
    "Ed25519 TV1 sig: " + bytesToHex(sig1));
  assert(crypto.ed25519Verify(new Uint8Array(0), sig1, kp1.pk), "Ed25519 TV1 verify");

  // Test Vector 2: single byte 0x72
  const seed2 = hexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
  const pkExpected2 = hexToBytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
  const sigExpected2 = hexToBytes("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

  const kp2 = crypto.ed25519Keygen(seed2);
  assert(bytesToHex(kp2.pk) === bytesToHex(pkExpected2),
    "Ed25519 TV2 pk: " + bytesToHex(kp2.pk));

  const sig2 = crypto.ed25519Sign(new Uint8Array([0x72]), kp2.sk);
  assert(bytesToHex(sig2) === bytesToHex(sigExpected2),
    "Ed25519 TV2 sig: " + bytesToHex(sig2));
  assert(crypto.ed25519Verify(new Uint8Array([0x72]), sig2, kp2.pk), "Ed25519 TV2 verify");

  // Test Vector 3: two bytes (from RFC 8032 Section 7.1)
  const seed3 = hexToBytes("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
  const pkExpected3 = hexToBytes("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
  const msg3 = hexToBytes("af82");
  const sigExpected3 = hexToBytes("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");

  const kp3 = crypto.ed25519Keygen(seed3);
  assert(bytesToHex(kp3.pk) === bytesToHex(pkExpected3),
    "Ed25519 TV3 pk: " + bytesToHex(kp3.pk));

  const sig3 = crypto.ed25519Sign(msg3, kp3.sk);
  assert(bytesToHex(sig3) === bytesToHex(sigExpected3),
    "Ed25519 TV3 sig: " + bytesToHex(sig3));
  assert(crypto.ed25519Verify(msg3, sig3, kp3.pk), "Ed25519 TV3 verify");

  console.log("  Ed25519 RFC 8032 vectors: OK");
})();

// ── HKDF Known-Answer Tests (RFC 5869) ──────────────────────────

section("HKDF Known-Answer (RFC 5869)");

(() => {
  // RFC 5869 Test Case 1 (SHA-256)
  const ikm1 = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  const salt1 = hexToBytes("000102030405060708090a0b0c");
  const info1 = hexToBytes("f0f1f2f3f4f5f6f7f8f9");
  const prk1 = crypto.hkdfExtractSha256(salt1, ikm1);
  assert(bytesToHex(prk1) === "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
    "HKDF-Extract TC1: " + bytesToHex(prk1));
  const okm1 = crypto.hkdfExpandSha256(prk1, info1, 42);
  assert(bytesToHex(okm1) === "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    "HKDF-Expand TC1: " + bytesToHex(okm1));

  console.log("  HKDF RFC 5869 vectors: OK");
})();

// ── Hybrid KEM Cross-check ──────────────────────────────────────

section("Hybrid KEM Pure JS Cross-check");

(() => {
  const { x25519Raw } = require("../crypto/x25519");

  // Verify that the hybrid KEM's X25519 component uses the correct curve
  // by checking that x25519Raw(seed, basepoint) matches native keygen
  for (let i = 0; i < 3; i++) {
    const seed = randomBytes(96);
    const { ek, dk } = crypto.hybridKemKeygen(seed);
    const { ct, ss: ssEnc } = crypto.hybridKemEncaps(ek);
    const ssDec = crypto.hybridKemDecaps(dk, ct);
    assert(constantTimeEqual(ssEnc, ssDec), `Hybrid KEM round-trip ${i + 1}`);

    // Verify the X25519 public key portion of ek matches x25519Raw
    const x25519Seed = seed.subarray(0, 32);
    const bp = new Uint8Array(32); bp[0] = 9;
    const pureJsPk = x25519Raw(x25519Seed, bp);
    const ekX25519Pk = ek.subarray(0, 32);
    assert(constantTimeEqual(pureJsPk, ekX25519Pk),
      `Hybrid KEM X25519 pk matches pure JS (trial ${i + 1})`);
  }

  console.log("  Hybrid KEM pure JS cross-check: OK");
})();

// ── constantTimeEqual Tests ─────────────────────────────────────

section("constantTimeEqual");

(() => {
  // Equal arrays
  const a = new Uint8Array([1, 2, 3, 4, 5]);
  const b = new Uint8Array([1, 2, 3, 4, 5]);
  assert(constantTimeEqual(a, b), "equal arrays");

  // Different arrays
  const c = new Uint8Array([1, 2, 3, 4, 6]);
  assert(!constantTimeEqual(a, c), "different arrays");

  // Different lengths
  const d = new Uint8Array([1, 2, 3]);
  assert(!constantTimeEqual(a, d), "different lengths");

  // Empty arrays
  assert(constantTimeEqual(new Uint8Array(0), new Uint8Array(0)), "empty arrays");

  // Single byte difference at end
  const e = new Uint8Array(256);
  const f = new Uint8Array(256);
  e[255] = 1;
  assert(!constantTimeEqual(e, f), "single byte diff at end");

  console.log("  constantTimeEqual: OK");
})();

// ── Forced Pure JS Fallback Tests ───────────────────────────────

section("Forced Pure JS Fallback (child process)");

let fallbackDone = false;

(() => {
  const { execSync } = require("child_process");
  const fs = require("fs");
  const path = require("path");
  const cryptoDir = path.resolve(__dirname, "..", "crypto").replace(/\\/g, "/");
  const utilsPath = path.join(cryptoDir, "utils").replace(/\\/g, "/");
  const x25519Path = path.join(cryptoDir, "x25519").replace(/\\/g, "/");

  // Write the fallback test script to a temp file (avoids Windows shell escaping)
  const tmpFile = path.join(__dirname, "_fallback_test_tmp.js");
  const script = `"use strict";
const Module = require("module");
const origResolve = Module._resolveFilename;
Module._resolveFilename = function(request) {
  if (request === "crypto") throw new Error("blocked for fallback testing");
  return origResolve.apply(this, arguments);
};

const crypto = require("${cryptoDir}");
const { constantTimeEqual } = require("${utilsPath}");
const { x25519Raw } = require("${x25519Path}");

function hexToBytes(hex) {
  var b = new Uint8Array(hex.length / 2);
  for (var i = 0; i < hex.length; i += 2) b[i / 2] = parseInt(hex.substr(i, 2), 16);
  return b;
}
function bytesToHex(b) {
  return Array.from(b).map(function(x) { return x.toString(16).padStart(2, "0"); }).join("");
}

var p = 0, f = 0;
function check(cond, msg) { if (cond) p++; else { f++; console.error("FAIL:", msg); } }

// SHA-256 (NIST)
check(bytesToHex(crypto.sha256(new Uint8Array(0))) ===
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256 empty");
check(bytesToHex(crypto.sha256(new TextEncoder().encode("abc"))) ===
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256 abc");

// SHA-512 (NIST)
check(bytesToHex(crypto.sha512(new Uint8Array(0))) ===
  "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "sha512 empty");
check(bytesToHex(crypto.sha512(new TextEncoder().encode("abc"))) ===
  "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", "sha512 abc");

// HMAC-SHA-256/512 (RFC 4231 TC2)
var key = new TextEncoder().encode("Jefe");
var data = new TextEncoder().encode("what do ya want for nothing?");
check(bytesToHex(crypto.hmacSha256(key, data)) ===
  "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "hmac-sha256 tc2");
check(bytesToHex(crypto.hmacSha512(key, data)) ===
  "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737", "hmac-sha512 tc2");

// SHA3-256 (NIST)
check(bytesToHex(crypto.sha3_256(new Uint8Array(0))) ===
  "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", "sha3-256 empty");
check(bytesToHex(crypto.sha3_256(new TextEncoder().encode("abc"))) ===
  "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", "sha3-256 abc");

// SHAKE-256
check(bytesToHex(crypto.shake256(new Uint8Array(0), 32)) ===
  "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f", "shake256 empty/32");

// X25519 pure JS (RFC 7748 Section 5.2)
var bp = new Uint8Array(32); bp[0] = 9;
var aliceSk = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
var alicePk = x25519Raw(aliceSk, bp);
check(bytesToHex(alicePk) === "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", "x25519 alice pk");
var bobSk = hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
var ss = x25519Raw(aliceSk, x25519Raw(bobSk, bp));
check(bytesToHex(ss) === "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", "x25519 shared secret");

// Ed25519 (keygen + sign + verify)
var seed1 = hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
var kp1 = crypto.ed25519Keygen(seed1);
check(bytesToHex(kp1.pk) === "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "ed25519 tv1 pk");
var sig1 = crypto.ed25519Sign(new Uint8Array(0), kp1.sk);
check(bytesToHex(sig1) === "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", "ed25519 tv1 sig");
check(crypto.ed25519Verify(new Uint8Array(0), sig1, kp1.pk), "ed25519 tv1 verify");

// X25519 key exchange (public API, forced fallback)
var kpA = crypto.x25519Keygen(hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
var kpB = crypto.x25519Keygen(hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
var ssA = crypto.x25519(kpA.sk, kpB.pk);
var ssB = crypto.x25519(kpB.sk, kpA.pk);
check(constantTimeEqual(ssA, ssB), "x25519 key exchange fallback");
check(bytesToHex(ssA) === "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", "x25519 shared secret via public API");

// Hybrid KEM round-trip (fallback)
var kemSeed = new Uint8Array(96);
for (var i = 0; i < 96; i++) kemSeed[i] = (i * 7 + 13) & 0xff;
var kemKp = crypto.hybridKemKeygen(kemSeed);
var kemEnc = crypto.hybridKemEncaps(kemKp.ek);
var kemDec = crypto.hybridKemDecaps(kemKp.dk, kemEnc.ct);
check(constantTimeEqual(kemEnc.ss, kemDec), "hybrid KEM fallback round-trip");

// PBKDF2-SHA-512
var dk = crypto.pbkdf2Sha512(new TextEncoder().encode("password"),
  new TextEncoder().encode("saltsalt"), 1, 32);
check(dk.length === 32, "pbkdf2 fallback returns 32 bytes");
var dk2 = crypto.pbkdf2Sha512(new TextEncoder().encode("password"),
  new TextEncoder().encode("saltsalt"), 1, 32);
check(constantTimeEqual(dk, dk2), "pbkdf2 fallback deterministic");

// HKDF-SHA-256 (RFC 5869 TC1)
var ikm = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
var salt = hexToBytes("000102030405060708090a0b0c");
var info = hexToBytes("f0f1f2f3f4f5f6f7f8f9");
var prk = crypto.hkdfExtractSha256(salt, ikm);
check(bytesToHex(prk) === "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", "hkdf-extract fallback");
var okm = crypto.hkdfExpandSha256(prk, info, 42);
check(bytesToHex(okm) === "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", "hkdf-expand fallback");

console.log(JSON.stringify({ passed: p, failed: f }));
process.exit(f > 0 ? 1 : 0);
`;

  fs.writeFileSync(tmpFile, script, "utf-8");

  try {
    const result = execSync(`node "${tmpFile}"`, {
      timeout: 120000,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    });

    // Parse the last line as JSON
    const lines = result.trim().split("\n");
    const stats = JSON.parse(lines[lines.length - 1]);
    assert(stats.failed === 0,
      `Fallback tests: ${stats.failed} failed (${stats.passed} passed)`);
    console.log(`  Forced fallback: ${stats.passed} passed, ${stats.failed} failed`);
  } catch (e) {
    const stderr = e.stderr ? e.stderr.toString().trim() : "";
    const stdout = e.stdout ? e.stdout.toString().trim() : "";
    if (stdout) console.log("  " + stdout.split("\n").join("\n  "));
    if (stderr) console.log("  STDERR: " + stderr.split("\n").join("\n  STDERR: "));
    assert(false, "Forced fallback child process failed");
  } finally {
    try { fs.unlinkSync(tmpFile); } catch (_) {}
  }

  fallbackDone = true;
})();

// ── AES-256-GCM (NIST SP 800-38D) ────────────────────────────────

section("AES-256-GCM");

(() => {
  function hexToBytes(hex) {
    if (!hex || hex.length === 0) return new Uint8Array(0);
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
  }

  function bytesToHex(bytes) {
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      hex += ("0" + bytes[i].toString(16)).slice(-2);
    }
    return hex;
  }

  // NIST Test Case 13: AES-256, empty plaintext, empty AAD
  const k13 = hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
  const n13 = hexToBytes("000000000000000000000000");
  const ct13 = crypto.aesGcmEncrypt(k13, n13, new Uint8Array(0));
  assert(bytesToHex(ct13) === "530f8afbc74536b9a963b4f1c4cb738b",
    "AES-GCM NIST test case 13 encrypt");
  const pt13 = crypto.aesGcmDecrypt(k13, n13, ct13);
  assert(pt13.length === 0, "AES-GCM NIST test case 13 decrypt");

  // NIST Test Case 14: AES-256, 16-byte zero plaintext, no AAD
  const pt14 = hexToBytes("00000000000000000000000000000000");
  const ct14 = crypto.aesGcmEncrypt(k13, n13, pt14);
  assert(bytesToHex(ct14) === "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919",
    "AES-GCM NIST test case 14 encrypt");
  const dec14 = crypto.aesGcmDecrypt(k13, n13, ct14);
  assert(bytesToHex(dec14) === "00000000000000000000000000000000",
    "AES-GCM NIST test case 14 decrypt");

  // NIST Test Case 16: AES-256, 60-byte plaintext, 20-byte AAD
  const k16 = hexToBytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
  const n16 = hexToBytes("cafebabefacedbaddecaf888");
  const pt16 = hexToBytes(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" +
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
  );
  const aad16 = hexToBytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
  const expected16 =
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa" +
    "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662" +
    "76fc6ece0f4e1768cddf8853bb2d551b";
  const ct16 = crypto.aesGcmEncrypt(k16, n16, pt16, aad16);
  assert(bytesToHex(ct16) === expected16, "AES-GCM NIST test case 16 encrypt");
  const dec16 = crypto.aesGcmDecrypt(k16, n16, ct16, aad16);
  assert(bytesToHex(dec16) === bytesToHex(pt16), "AES-GCM NIST test case 16 decrypt");

  // Round-trip with random data
  const rKey = randomBytes(32);
  const rNonce = randomBytes(12);
  const rPt = randomBytes(1000);
  const rAad = randomBytes(50);
  const rCt = crypto.aesGcmEncrypt(rKey, rNonce, rPt, rAad);
  assert(rCt.length === rPt.length + 16, "AES-GCM random round-trip ciphertext length");
  const rDec = crypto.aesGcmDecrypt(rKey, rNonce, rCt, rAad);
  let rMatch = rDec.length === rPt.length;
  for (let i = 0; i < rPt.length && rMatch; i++) rMatch = rDec[i] === rPt[i];
  assert(rMatch, "AES-GCM random round-trip decrypt matches");

  // Tampered ciphertext must be rejected
  const tCt = new Uint8Array(rCt);
  tCt[0] ^= 0xff;
  let tamperRejected = false;
  try { crypto.aesGcmDecrypt(rKey, rNonce, tCt, rAad); } catch (_) { tamperRejected = true; }
  assert(tamperRejected, "AES-GCM rejects tampered ciphertext");

  // Tampered tag must be rejected
  const tTag = new Uint8Array(rCt);
  tTag[tTag.length - 1] ^= 0x01;
  let tagRejected = false;
  try { crypto.aesGcmDecrypt(rKey, rNonce, tTag, rAad); } catch (_) { tagRejected = true; }
  assert(tagRejected, "AES-GCM rejects tampered tag");

  // Wrong key must be rejected
  const wrongKey = randomBytes(32);
  let wrongKeyRejected = false;
  try { crypto.aesGcmDecrypt(wrongKey, rNonce, rCt, rAad); } catch (_) { wrongKeyRejected = true; }
  assert(wrongKeyRejected, "AES-GCM rejects wrong key");

  // Empty plaintext
  const eCt = crypto.aesGcmEncrypt(rKey, rNonce, new Uint8Array(0));
  assert(eCt.length === 16, "AES-GCM empty plaintext produces 16-byte tag");
  const eDec = crypto.aesGcmDecrypt(rKey, rNonce, eCt);
  assert(eDec.length === 0, "AES-GCM empty plaintext round-trip");

  // Invalid key size
  let badKeyRejected = false;
  try { crypto.aesGcmEncrypt(new Uint8Array(16), rNonce, rPt); } catch (_) { badKeyRejected = true; }
  assert(badKeyRejected, "AES-GCM rejects 16-byte key");

  // Invalid nonce size
  let badNonceRejected = false;
  try { crypto.aesGcmEncrypt(rKey, new Uint8Array(8), rPt); } catch (_) { badNonceRejected = true; }
  assert(badNonceRejected, "AES-GCM rejects 8-byte nonce");
})();

// ── Summary ───────────────────────────────────────────────────────

// Wait for async tests to complete before printing summary
function printSummary() {
  if (!asyncDone || !fallbackDone) { setTimeout(printSummary, 100); return; }
  console.log(`\n═══════════════════════════════════════`);
  console.log(`  ${passed} passed, ${failed} failed`);
  console.log(`═══════════════════════════════════════\n`);
  process.exit(failed > 0 ? 1 : 0);
}
setTimeout(printSummary, 100);
