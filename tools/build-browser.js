#!/usr/bin/env node
// build-browser.js — Bundle universal-quantum-seed-js for the browser
//
// Usage: node tools/build-browser.js
//
// Produces:
//   dist/uqs.js     — browser-ready IIFE, exposes globalThis.UQS
//   dist/uqs.min.js — minified version (if terser is available, otherwise skipped)

"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const DIST = path.join(ROOT, "dist");

// Module files in dependency order.
// Each entry: [requirePath, filePath]
// requirePath is what other files use in require("./crypto/sha2") etc.
const MODULES = [
  ["./crypto/utils",       "crypto/utils.js"],
  ["./crypto/field25519",  "crypto/field25519.js"],
  ["./crypto/sha2",        "crypto/sha2.js"],
  ["./crypto/sha3",        "crypto/sha3.js"],
  ["./crypto/argon2",      "crypto/argon2.js"],
  ["./crypto/ed25519",     "crypto/ed25519.js"],
  ["./crypto/x25519",      "crypto/x25519.js"],
  ["./crypto/ml_dsa",      "crypto/ml_dsa.js"],
  ["./crypto/ml_kem",      "crypto/ml_kem.js"],
  ["./crypto/slh_dsa",     "crypto/slh_dsa.js"],
  ["./crypto/hybrid_dsa",  "crypto/hybrid_dsa.js"],
  ["./crypto/hybrid_kem",  "crypto/hybrid_kem.js"],
  ["./crypto/aes_gcm",     "crypto/aes_gcm.js"],
  ["./crypto",             "crypto/index.js"],
  ["./words",              "words.js"],
  ["./seed",               "seed.js"],
  [".",                    "index.js"],
];

function readModule(filePath) {
  return fs.readFileSync(path.join(ROOT, filePath), "utf-8");
}

function build() {
  const parts = [];

  // Read VERSION from seed.js
  const seedSrc = readModule("seed.js");
  const versionMatch = seedSrc.match(/const\s+VERSION\s*=\s*"([^"]+)"/);
  const version = versionMatch ? versionMatch[1] : "unknown";

  // IIFE header
  parts.push(`// Universal Quantum Seed v${version} — Browser Bundle
// https://github.com/madebylock/universal-quantum-seed-js
// MIT License — (c) 2026 Lock.com
//
// Usage:
//   <script src="uqs.js"><\/script>
//   const { generateWords, getSeed, getSeedAsync, resolve } = UQS;
//
// Or as ES module:
//   import UQS from "./uqs.js";

(function(globalThis) {
"use strict";

// ── Module registry ────────────────────────────────────────────
const _modules = {};
const _cache = {};

function _resolve(base, id) {
  // Strip .js suffix
  id = id.replace(/\\.js$/, "");
  // Absolute or package require (e.g. "crypto") — return as-is
  if (!id.startsWith(".")) return id;
  // Resolve relative path against base directory
  var parts = (base + "/" + id).split("/");
  var out = [];
  for (var i = 0; i < parts.length; i++) {
    if (parts[i] === "." || parts[i] === "") continue;
    if (parts[i] === "..") { out.pop(); continue; }
    out.push(parts[i]);
  }
  return out.length ? "./" + out.join("/") : ".";
}

function _requireFrom(base) {
  return function require(id) {
    var key = _resolve(base, id);
    if (_cache[key]) return _cache[key].exports;
    if (_modules[key]) {
      var mod = { exports: {} };
      _cache[key] = mod;
      _modules[key](mod, mod.exports, _requireFrom(_dirs[key]));
      return mod.exports;
    }
    // Node built-ins (crypto, fs, etc.) — throw so try-catch fallbacks work
    throw new Error("Cannot find module '" + id + "'");
  };
}

// Module directories for relative require resolution
var _dirs = {};

`);

  // Register each module with its directory context
  for (const [reqPath, filePath] of MODULES) {
    const src = readModule(filePath);
    // Compute the directory of this file (e.g. "crypto/sha2.js" → "./crypto")
    const dir = "./" + filePath.replace(/\\/g, "/").split("/").slice(0, -1).join("/");
    parts.push(`// ── ${filePath} ──`);
    parts.push(`_dirs["${reqPath}"] = "${dir || "."}";`);
    parts.push(`_modules["${reqPath}"] = function(module, exports, require) {`);
    parts.push(src);
    parts.push(`};\n`);
  }

  // IIFE footer: resolve the main module and expose as UQS
  parts.push(`
// ── Expose API ─────────────────────────────────────────────────
var UQS = _requireFrom(".")(".");

// ESM default export support (for bundlers that detect it)
UQS.default = UQS;

if (typeof globalThis !== "undefined") globalThis.UQS = UQS;
if (typeof window !== "undefined") window.UQS = UQS;
if (typeof self !== "undefined") self.UQS = UQS;

// Support: <script type="module"> import
if (typeof module !== "undefined" && module.exports) {
  module.exports = UQS;
}

})(typeof globalThis !== "undefined" ? globalThis : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : this);
`);

  return parts.join("\n");
}

// ── Main ───────────────────────────────────────────────────────
if (!fs.existsSync(DIST)) fs.mkdirSync(DIST, { recursive: true });

const bundle = build();
const outPath = path.join(DIST, "uqs.js");
fs.writeFileSync(outPath, bundle);

const stats = fs.statSync(outPath);
const sizeKB = (stats.size / 1024).toFixed(0);
console.log(`  dist/uqs.js  ${sizeKB} KB`);

// Try minification with terser (optional)
try {
  const { minify } = require("terser");
  console.log("  Minifying with terser...");
  minify(bundle, {
    ecma: 2020,
    compress: { passes: 2 },
    mangle: { toplevel: false },
    output: { comments: /^!|MIT|License|Copyright/i },
  }).then(result => {
    if (result.code) {
      const minPath = path.join(DIST, "uqs.min.js");
      fs.writeFileSync(minPath, result.code);
      const minStats = fs.statSync(minPath);
      console.log(`  dist/uqs.min.js  ${(minStats.size / 1024).toFixed(0)} KB`);
    }
  });
} catch (_) {
  console.log("  (terser not installed — skipping minification)");
}
