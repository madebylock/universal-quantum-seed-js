// Copyright (c) 2026 Lock.com -- MIT License

"use strict";

// Cross-implementation KATs shared with the Python package.
// Run with: node tools/kat-test.js

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const uqs = require("..");

const katPath = path.join(__dirname, "..", "kat", "seed_v1.json");
const sidecarPath = katPath + ".sha256";
const katBytesRaw = fs.readFileSync(katPath);

// Canonicalize like the Python sidecar verifier does: strip BOM, then
// normalize CRLF / lone CR to LF. Any future edit to seed_v1.json must
// be paired with an updated sidecar.
function canonicalize(buf) {
  let start = 0;
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    start = 3;
  }
  const out = [];
  for (let i = start; i < buf.length; i++) {
    const b = buf[i];
    if (b === 0x0d) {
      if (buf[i + 1] === 0x0a) continue;
      out.push(0x0a);
    } else {
      out.push(b);
    }
  }
  return Buffer.from(out);
}

const actualHash = crypto
  .createHash("sha256")
  .update(canonicalize(katBytesRaw))
  .digest("hex");
const sidecarHash = fs.readFileSync(sidecarPath, "utf8").trim().split(/\s+/)[0].toLowerCase();
const kat = JSON.parse(katBytesRaw.toString("utf8"));

let passed = 0;
let failed = 0;

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function assert(cond, msg) {
  if (cond) {
    passed++;
  } else {
    failed++;
    console.error("  FAIL:", msg);
  }
}

assert(actualHash === sidecarHash, "KAT sidecar matches seed_v1.json contents");
assert(kat.version === 1, "KAT version");
assert(kat.domain === "universal-seed-v1", "KAT domain");

for (const vector of kat.vectors) {
  assert(vector.indexes.length === vector.word_count, `${vector.id}: word count`);

  // Vectors flagged `expect_invalid_checksum` exist to lock the negative
  // path of verifyChecksum; they don't carry derived seed material.
  if (vector.expect_invalid_checksum) {
    assert(!uqs.verifyChecksum(vector.indexes), `${vector.id}: invalid checksum`);
    continue;
  }
  assert(uqs.verifyChecksum(vector.indexes), `${vector.id}: checksum`);

  const master = uqs.getSeed(vector.indexes, vector.passphrase);
  assert(hex(master) === vector.master_seed_hex, `${vector.id}: master seed`);
  assert(
    hex(uqs.getProfile(master, "")) === vector.default_profile_hex,
    `${vector.id}: default profile`
  );
  assert(
    hex(uqs.getProfile(master, vector.profile)) === vector.named_profile_hex,
    `${vector.id}: named profile`
  );
  assert(
    uqs.getFingerprint(vector.indexes, vector.passphrase) === vector.fingerprint,
    `${vector.id}: fingerprint`
  );
}

console.log(`UQS seed KATs: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
