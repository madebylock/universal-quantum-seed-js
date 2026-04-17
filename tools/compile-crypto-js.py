#!/usr/bin/env python3
# Copyright (c) 2026 Lock.com — MIT License

"""
Build a crypto-only browser bundle (no wordlists).

Strips wordlists, word resolution, search, and language data from the bundle.
Keeps all cryptographic primitives, key derivation, and entropy.

Output: dist/uqs-crypto.js

Usage: python tools/compile-crypto-js.py
"""

import os
import re
import sys

if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SCRIPT_DIR)
DIST = os.path.join(ROOT, "dist")

# ── Configuration ────────────────────────────────────────────────

SECTION_RE = re.compile(r"^// ── (.+?) ─+$")

# seed.js sections to remove entirely
EXCLUDE_SECTIONS = {"Normalization", "Resolution", "Search", "Word Generation", "Languages"}

# Header-level patterns to skip (before first section marker)
EXCLUDE_HEADER = [
    'require("./words")',
    "const BASE_WORDS",
    "const BASE =",
    "BASE_WORDS.forEach",
    "// Build sorted keys",
    "const SORTED_KEYS",
    "// Build inner-word",
    "const INNER_WORDS",
    "for (const k of Object.keys(LOOKUP)",
    "INNER_WORDS.sort",
    "const INNER_WORD_KEYS",
    "// Zero-width and invisible",
    "const INVISIBLE_CHARS",
    "// Article suffixes",
    "const ARTICLE_SUFFIXES",
    "// Latin diacritic",
    "const LATIN_REPLACEMENTS",
]

# Crypto modules in dependency order
CRYPTO_MODULES = [
    ("./crypto/utils",      "crypto/utils.js"),
    ("./crypto/field25519", "crypto/field25519.js"),
    ("./crypto/sha2",       "crypto/sha2.js"),
    ("./crypto/sha3",       "crypto/sha3.js"),
    ("./crypto/argon2",     "crypto/argon2.js"),
    ("./crypto/ed25519",    "crypto/ed25519.js"),
    ("./crypto/x25519",     "crypto/x25519.js"),
    ("./crypto/ml_dsa",     "crypto/ml_dsa.js"),
    ("./crypto/ml_kem",     "crypto/ml_kem.js"),
    ("./crypto/slh_dsa",    "crypto/slh_dsa.js"),
    ("./crypto/hybrid_dsa", "crypto/hybrid_dsa.js"),
    ("./crypto/hybrid_kem", "crypto/hybrid_kem.js"),
    ("./crypto/aes_gcm",    "crypto/aes_gcm.js"),
    ("./crypto",            "crypto/index.js"),
]

# ── Replacement fragments ────────────────────────────────────────

# toIndexes without word resolution (crypto-only build accepts numeric indexes only)
TOINDEXES_CRYPTO = '''\
function toIndexes(seed) {
  if (!seed || !seed.length) throw new Error("seed must not be empty");

  // Accept string of space-separated numeric indexes
  if (typeof seed === "string") {
    seed = seed.trim().split(/\\s+/).filter(Boolean);
    if (seed.length === 0) throw new Error("seed must not be empty");
    const nums = seed.map(Number);
    if (nums.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) return nums;
    throw new Error("crypto-only build: pass numeric indexes (0-255), not words");
  }

  const first = seed[0];
  if (Array.isArray(first) || (typeof first === "object" && first !== null && "index" in first)) {
    return seed.map((item, i) => {
      const idx = Array.isArray(item) ? item[0] : item.index;
      if (!Number.isInteger(idx) || idx < 0 || idx > 255) {
        throw new Error("seed index out of range at position " + i + ": " + idx);
      }
      return idx;
    });
  }
  if (typeof first === "number") {
    for (const v of seed) {
      if (!Number.isInteger(v) || v < 0 || v > 255) {
        throw new Error("seed index out of range: " + v);
      }
    }
    return [...seed];
  }
  throw new Error("crypto-only build: pass numeric indexes (0-255), not words");
}'''

# Exports for the crypto-only seed module
EXPORTS_CRYPTO = '''\
module.exports = {
  VERSION,
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
};'''

# Top-level index for the crypto-only bundle
INDEX_CRYPTO = '''\
// Auto-generated crypto-only index
"use strict";

const seed = require("./seed");
const crypto = require("./crypto");

module.exports = {
  // Key Derivation
  getSeed: seed.getSeed,
  getSeedAsync: seed.getSeedAsync,
  getProfile: seed.getProfile,
  getFingerprint: seed.getFingerprint,
  getEntropyBits: seed.getEntropyBits,
  verifyChecksum: seed.verifyChecksum,

  // Post-Quantum Key Derivation
  getQuantumSeed: seed.getQuantumSeed,
  generateQuantumKeypair: seed.generateQuantumKeypair,

  // ML-DSA-65 (FIPS 204)
  mlKeygen: crypto.mlKeygen,
  mlSign: crypto.mlSign,
  mlVerify: crypto.mlVerify,
  mlSignWithContext: crypto.mlSignWithContext,
  mlVerifyWithContext: crypto.mlVerifyWithContext,
  mlSignAsync: crypto.mlSignAsync,
  mlVerifyAsync: crypto.mlVerifyAsync,

  // SLH-DSA-SHAKE-128s (FIPS 205)
  slhKeygen: crypto.slhKeygen,
  slhSign: crypto.slhSign,
  slhVerify: crypto.slhVerify,
  slhSignWithContext: crypto.slhSignWithContext,
  slhVerifyWithContext: crypto.slhVerifyWithContext,
  slhSignAsync: crypto.slhSignAsync,
  slhVerifyAsync: crypto.slhVerifyAsync,

  // ML-KEM-768 (FIPS 203)
  mlKemKeygen: crypto.mlKemKeygen,
  mlKemEncaps: crypto.mlKemEncaps,
  mlKemDecaps: crypto.mlKemDecaps,

  // Ed25519 (RFC 8032)
  ed25519Keygen: crypto.ed25519Keygen,
  ed25519Sign: crypto.ed25519Sign,
  ed25519Verify: crypto.ed25519Verify,

  // X25519 (RFC 7748)
  x25519Keygen: crypto.x25519Keygen,
  x25519: crypto.x25519,

  // Hybrid Ed25519 + ML-DSA-65
  hybridDsaKeygen: crypto.hybridDsaKeygen,
  hybridDsaSign: crypto.hybridDsaSign,
  hybridDsaVerify: crypto.hybridDsaVerify,

  // Hybrid X25519 + ML-KEM-768
  hybridKemKeygen: crypto.hybridKemKeygen,
  hybridKemEncaps: crypto.hybridKemEncaps,
  hybridKemDecaps: crypto.hybridKemDecaps,

  // Argon2id (RFC 9106) + Blake2b
  argon2id: crypto.argon2id,
  blake2b: crypto.blake2b,

  // AES-256-GCM (NIST SP 800-38D)
  aesGcmEncrypt: crypto.aesGcmEncrypt,
  aesGcmDecrypt: crypto.aesGcmDecrypt,
  aesGcmEncryptAsync: crypto.aesGcmEncryptAsync,
  aesGcmDecryptAsync: crypto.aesGcmDecryptAsync,

  // Hash Functions
  sha3_256: crypto.sha3_256,
  sha3_512: crypto.sha3_512,
  shake128: crypto.shake128,
  shake256: crypto.shake256,
  sha256: crypto.sha256,
  sha512: crypto.sha512,
  hmacSha256: crypto.hmacSha256,
  hmacSha512: crypto.hmacSha512,
  hkdfExpand: crypto.hkdfExpand,
  hkdfExpandSha256: crypto.hkdfExpandSha256,
  hkdfExtractSha256: crypto.hkdfExtractSha256,
  pbkdf2Sha512: crypto.pbkdf2Sha512,
  pbkdf2Sha512Async: crypto.pbkdf2Sha512Async,

  // Entropy & Testing
  MouseEntropy: seed.MouseEntropy,
  verifyRandomness: seed.verifyRandomness,
  kdfInfo: seed.kdfInfo,

  // Constants
  VERSION: seed.VERSION,
};'''


# ── Helpers ──────────────────────────────────────────────────────

def read_file(rel):
    with open(os.path.join(ROOT, rel), "r", encoding="utf-8") as f:
        return f.read()


def matches_exclude(line_stripped):
    """Check if a line matches any header-exclude pattern."""
    for pat in EXCLUDE_HEADER:
        if pat in line_stripped:
            return True
    return False


def brace_depth(line):
    """Net bracket depth change in a line."""
    d = 0
    for ch in line:
        if ch in "{[(":
            d += 1
        elif ch in "}])":
            d -= 1
    return d


def skip_block(lines, i):
    """Skip a (possibly multi-line) statement starting at line i. Returns next line index."""
    depth = brace_depth(lines[i])
    # Single-line statement
    if depth <= 0 and lines[i].rstrip().endswith(";"):
        return i + 1
    # Multi-line: track bracket depth
    while depth > 0 and i + 1 < len(lines):
        i += 1
        depth += brace_depth(lines[i])
    return i + 1


# ── Strip seed.js ────────────────────────────────────────────────

def strip_seed():
    """Produce a crypto-only version of seed.js."""
    lines = read_file("seed.js").split("\n")

    # Phase 1: Process header (everything before first section marker)
    header = []
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if SECTION_RE.match(stripped):
            break
        if matches_exclude(stripped):
            i = skip_block(lines, i)
            continue
        header.append(lines[i])
        i += 1

    # Phase 2: Split remaining lines into named sections
    sections = []
    name = None
    body = []
    while i < len(lines):
        stripped = lines[i].strip()
        m = SECTION_RE.match(stripped)
        if m:
            if name is not None:
                sections.append((name, "\n".join(body)))
            name = m.group(1)
            body = [lines[i]]
        else:
            body.append(lines[i])
        i += 1
    if name:
        sections.append((name, "\n".join(body)))

    # Phase 3: Assemble — keep only non-excluded sections, patch special ones
    parts = ["\n".join(header)]
    for name, text in sections:
        if name in EXCLUDE_SECTIONS:
            continue
        if name == "Index Conversion":
            parts.append("")
            parts.append("// ── Index Conversion ────────────────────────────────────────────")
            parts.append("")
            parts.append(TOINDEXES_CRYPTO)
            continue
        if name == "Exports":
            parts.append("")
            parts.append("// ── Exports ─────────────────────────────────────────────────────")
            parts.append("")
            parts.append(EXPORTS_CRYPTO)
            continue
        parts.append(text)

    return "\n".join(parts)


# ── IIFE Bundle ──────────────────────────────────────────────────

IIFE_HEADER = """\
// Universal Quantum Seed v{version} — Crypto-Only Bundle
// https://github.com/madebylock/universal-quantum-seed-js
// MIT License — (c) 2026 Lock.com
//
// Crypto-only build: all cryptographic primitives + key derivation.
// No wordlists, no word resolution, no language data (~75% smaller).
//
// Usage:
//   <script src="uqs-crypto.js"><\\/script>
//   const {{ mlKeygen, ed25519Sign, getSeed }} = UQS;
//
// Or as ES module:
//   import UQS from "./uqs-crypto.js";

(function(globalThis) {{
"use strict";

// ── Module registry ────────────────────────────────────────────
const _modules = {{}};
const _cache = {{}};

function _resolve(base, id) {{
  id = id.replace(/\\.js$/, "");
  if (!id.startsWith(".")) return id;
  var parts = (base + "/" + id).split("/");
  var out = [];
  for (var i = 0; i < parts.length; i++) {{
    if (parts[i] === "." || parts[i] === "") continue;
    if (parts[i] === "..") {{ out.pop(); continue; }}
    out.push(parts[i]);
  }}
  return out.length ? "./" + out.join("/") : ".";
}}

function _requireFrom(base) {{
  return function require(id) {{
    var key = _resolve(base, id);
    if (_cache[key]) return _cache[key].exports;
    if (_modules[key]) {{
      var mod = {{ exports: {{}} }};
      _cache[key] = mod;
      _modules[key](mod, mod.exports, _requireFrom(_dirs[key]));
      return mod.exports;
    }}
    throw new Error("Cannot find module '" + id + "'");
  }};
}}

var _dirs = {{}};

"""

IIFE_FOOTER = """
// ── Expose API ─────────────────────────────────────────────────
var UQS = _requireFrom(".")(".");

UQS.default = UQS;

if (typeof globalThis !== "undefined") globalThis.UQS = UQS;
if (typeof window !== "undefined") window.UQS = UQS;
if (typeof self !== "undefined") self.UQS = UQS;

if (typeof module !== "undefined" && module.exports) {
  module.exports = UQS;
}

})(typeof globalThis !== "undefined" ? globalThis : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : this);
"""


def build():
    """Build the crypto-only IIFE bundle."""
    seed_src = read_file("seed.js")
    m = re.search(r'const\s+VERSION\s*=\s*"([^"]+)"', seed_src)
    version = m.group(1) if m else "unknown"

    parts = [IIFE_HEADER.format(version=version)]

    # Register crypto modules
    for req_path, file_path in CRYPTO_MODULES:
        src = read_file(file_path)
        dir_path = "./" + "/".join(file_path.replace("\\", "/").split("/")[:-1])
        parts.append(f'// ── {file_path} ──')
        parts.append(f'_dirs["{req_path}"] = "{dir_path or "."}";')
        parts.append(f'_modules["{req_path}"] = function(module, exports, require) {{')
        parts.append(src)
        parts.append("};\n")

    # Register stripped seed.js
    seed_stripped = strip_seed()
    parts.append('// ── seed.js (crypto-only) ──')
    parts.append('_dirs["./seed"] = ".";')
    parts.append('_modules["./seed"] = function(module, exports, require) {')
    parts.append(seed_stripped)
    parts.append("};\n")

    # Register crypto-only index
    parts.append('// ── index.js (crypto-only) ──')
    parts.append('_dirs["."] = ".";')
    parts.append('_modules["."] = function(module, exports, require) {')
    parts.append(INDEX_CRYPTO)
    parts.append("};\n")

    parts.append(IIFE_FOOTER)

    return "\n".join(parts)


# ── Main ─────────────────────────────────────────────────────────

def main():
    os.makedirs(DIST, exist_ok=True)

    print("Building crypto-only bundle...\n")

    total_src = 0
    for _, fp in CRYPTO_MODULES:
        size = os.path.getsize(os.path.join(ROOT, fp))
        total_src += size
        print(f"  {fp:<30s} {size // 1024:>4d} KB")

    seed_size = os.path.getsize(os.path.join(ROOT, "seed.js"))
    total_src += seed_size
    print(f"  {'seed.js (stripped)':<30s} {seed_size // 1024:>4d} KB")

    bundle = build()

    out_path = os.path.join(DIST, "uqs-crypto.js")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(bundle)

    size_kb = os.path.getsize(out_path) / 1024

    # Compare with full bundle if it exists
    full_path = os.path.join(DIST, "uqs.js")
    full_size = os.path.getsize(full_path) / 1024 if os.path.exists(full_path) else 0

    print(f"\n{'=' * 60}")
    print(f"  dist/uqs-crypto.js  {size_kb:.0f} KB")
    if full_size:
        saved = full_size - size_kb
        pct = (saved / full_size) * 100
        print(f"  dist/uqs.js         {full_size:.0f} KB  (full bundle)")
        print(f"  Saved: {saved:.0f} KB ({pct:.0f}% smaller)")
    print(f"\nExcluded: wordlists, word resolution, search, 42 languages")
    print(f"Included: all crypto + key derivation + entropy")

    return True


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
