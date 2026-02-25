// Copyright (c) 2026 Signer.io — MIT License

"use strict";

// Shared cryptographic utilities used across all modules.
// Single source of truth to prevent divergence in security-critical helpers.

function toBytes(data) {
  if (data instanceof Uint8Array) return data;
  if (typeof data === "string") return new TextEncoder().encode(data);
  if (Array.isArray(data)) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  throw new Error("unsupported input type");
}

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

function randomBytes(n) {
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.getRandomValues) {
    const buf = new Uint8Array(n);
    globalThis.crypto.getRandomValues(buf);
    return buf;
  }
  return new Uint8Array(require("crypto").randomBytes(n));
}

/** Best-effort zeroing of sensitive buffers. Not guaranteed by JS GC, but reduces exposure. */
function zeroize(buf) {
  if (buf instanceof Uint8Array) buf.fill(0);
  else if (Array.isArray(buf)) {
    for (let i = 0; i < buf.length; i++) buf[i] = 0;
  }
}

/** Constant-time comparison of two Uint8Arrays. */
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

module.exports = { toBytes, concatBytes, randomBytes, zeroize, constantTimeEqual };
