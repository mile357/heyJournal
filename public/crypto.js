/**
 * heyJo — Zero-Knowledge Client-Side Cryptography Engine
 *
 * Dual-backend AES-256-GCM + PBKDF2-HMAC-SHA256 implementation:
 * 1. Uses native browser Web Crypto API (`crypto.subtle`) whenever available
 *    (HTTPS, localhost, 127.0.0.1).
 * 2. Transparently falls back to an audited, NIST-compliant pure-JS
 *    implementation (FIPS 180-4 SHA-256, RFC 2898 PBKDF2, FIPS 197 AES-256,
 *    NIST SP 800-38D GCM) when accessed over plain LAN HTTP (e.g. sslip.io).
 *
 * Both backends produce 100% bit-for-bit compatible wire payloads so a vault
 * created on HTTP decrypts seamlessly on HTTPS and vice versa.
 */

export const DEFAULT_KDF_ITERATIONS = 600000;
export const RECOVERY_KDF_ITERATIONS = 150000;
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
// Standard Crockford Base32 alphabet (exactly 32 chars; omits I, L, O, U)
const RECOVERY_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function utf8Encode(str) {
  if (typeof TextEncoder !== "undefined") {
    return new TextEncoder().encode(str);
  }
  const encoded = unescape(encodeURIComponent(str));
  const out = new Uint8Array(encoded.length);
  for (let i = 0; i < encoded.length; i++) out[i] = encoded.charCodeAt(i);
  return out;
}

function utf8Decode(bytes) {
  if (typeof TextDecoder !== "undefined") {
    return new TextDecoder().decode(bytes);
  }
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return decodeURIComponent(escape(s));
}

const textEncoder = { encode: utf8Encode };
const textDecoder = { decode: utf8Decode };

export function isNativeWebCryptoAvailable() {
  return Boolean(
    typeof globalThis !== "undefined" &&
      globalThis.crypto &&
      globalThis.crypto.subtle &&
      typeof globalThis.crypto.subtle.importKey === "function" &&
      typeof globalThis.crypto.subtle.encrypt === "function"
  );
}

export function getCryptoBackendLabel() {
  return isNativeWebCryptoAvailable() ? "Web Crypto API (Native)" : "Pure-JS AES-256-GCM (HTTP Fallback)";
}

export function generateRandomBytes(length) {
  const out = new Uint8Array(length);
  if (typeof globalThis !== "undefined" && globalThis.crypto && typeof globalThis.crypto.getRandomValues === "function") {
    globalThis.crypto.getRandomValues(out);
    return out;
  }
  throw new Error("Secure random number generator (crypto.getRandomValues) is unavailable.");
}

export function bytesToBase64(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < arr.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, arr.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

export function base64ToBytes(b64) {
  const binary = atob(String(b64 || "").trim());
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

// ============================================================================
// PURE-JS FIPS 180-4 SHA-256, RFC 2104 HMAC-SHA256 & RFC 2898 PBKDF2-SHA256
// ============================================================================

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const SHA256_IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const _shaW = new Uint32Array(64);

function sha256CompressBlock(state, block, offset) {
  for (let i = 0; i < 16; i++) {
    const j = offset + i * 4;
    _shaW[i] =
      ((block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3]) >>> 0;
  }
  for (let i = 16; i < 64; i++) {
    const w15 = _shaW[i - 15];
    const w2 = _shaW[i - 2];
    const s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
    const s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
    _shaW[i] = (_shaW[i - 16] + s0 + _shaW[i - 7] + s1) >>> 0;
  }

  let a = state[0];
  let b = state[1];
  let c = state[2];
  let d = state[3];
  let e = state[4];
  let f = state[5];
  let g = state[6];
  let h = state[7];

  for (let i = 0; i < 64; i++) {
    const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const ch = (e & f) ^ (~e & g);
    const temp1 = (h + S1 + ch + SHA256_K[i] + _shaW[i]) >>> 0;
    const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const temp2 = (S0 + maj) >>> 0;

    h = g;
    g = f;
    f = e;
    e = (d + temp1) >>> 0;
    d = c;
    c = b;
    b = a;
    a = (temp1 + temp2) >>> 0;
  }

  state[0] = (state[0] + a) >>> 0;
  state[1] = (state[1] + b) >>> 0;
  state[2] = (state[2] + c) >>> 0;
  state[3] = (state[3] + d) >>> 0;
  state[4] = (state[4] + e) >>> 0;
  state[5] = (state[5] + f) >>> 0;
  state[6] = (state[6] + g) >>> 0;
  state[7] = (state[7] + h) >>> 0;
}

function sha256(data) {
  const state = new Uint32Array(SHA256_IV);
  const len = data.length;
  const fullBlocks = Math.floor(len / 64);
  for (let i = 0; i < fullBlocks; i++) {
    sha256CompressBlock(state, data, i * 64);
  }
  const rem = len - fullBlocks * 64;
  const padLen = rem < 56 ? 64 : 128;
  const tail = new Uint8Array(padLen);
  tail.set(data.subarray(fullBlocks * 64));
  tail[rem] = 0x80;
  const bitLenHi = Math.floor(len / 0x20000000);
  const bitLenLo = (len << 3) >>> 0;
  tail[padLen - 8] = (bitLenHi >>> 24) & 0xff;
  tail[padLen - 7] = (bitLenHi >>> 16) & 0xff;
  tail[padLen - 6] = (bitLenHi >>> 8) & 0xff;
  tail[padLen - 5] = bitLenHi & 0xff;
  tail[padLen - 4] = (bitLenLo >>> 24) & 0xff;
  tail[padLen - 3] = (bitLenLo >>> 16) & 0xff;
  tail[padLen - 2] = (bitLenLo >>> 8) & 0xff;
  tail[padLen - 1] = bitLenLo & 0xff;

  sha256CompressBlock(state, tail, 0);
  if (padLen === 128) sha256CompressBlock(state, tail, 64);

  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    out[i * 4] = (state[i] >>> 24) & 0xff;
    out[i * 4 + 1] = (state[i] >>> 16) & 0xff;
    out[i * 4 + 2] = (state[i] >>> 8) & 0xff;
    out[i * 4 + 3] = state[i] & 0xff;
  }
  return out;
}

function makeHmacSha256Context(keyBytes) {
  const keyBlock = new Uint8Array(64);
  if (keyBytes.length > 64) {
    keyBlock.set(sha256(keyBytes));
  } else {
    keyBlock.set(keyBytes);
  }
  const ipad = new Uint8Array(64);
  const opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    ipad[i] = keyBlock[i] ^ 0x36;
    opad[i] = keyBlock[i] ^ 0x5c;
  }
  const innerInit = new Uint32Array(SHA256_IV);
  sha256CompressBlock(innerInit, ipad, 0);
  const outerInit = new Uint32Array(SHA256_IV);
  sha256CompressBlock(outerInit, opad, 0);
  keyBlock.fill(0);
  ipad.fill(0);
  opad.fill(0);
  return { innerInit, outerInit };
}

function hmacSha256Fast(ctx, message) {
  const innerState = new Uint32Array(ctx.innerInit);
  const len = message.length;
  const fullBlocks = Math.floor(len / 64);
  for (let i = 0; i < fullBlocks; i++) {
    sha256CompressBlock(innerState, message, i * 64);
  }
  const rem = len - fullBlocks * 64;
  const padLen = rem < 56 ? 64 : 128;
  const tail = new Uint8Array(padLen);
  tail.set(message.subarray(fullBlocks * 64));
  tail[rem] = 0x80;
  const totalLen = 64 + len;
  const bitLenHi = Math.floor(totalLen / 0x20000000);
  const bitLenLo = (totalLen << 3) >>> 0;
  tail[padLen - 8] = (bitLenHi >>> 24) & 0xff;
  tail[padLen - 7] = (bitLenHi >>> 16) & 0xff;
  tail[padLen - 6] = (bitLenHi >>> 8) & 0xff;
  tail[padLen - 5] = bitLenHi & 0xff;
  tail[padLen - 4] = (bitLenLo >>> 24) & 0xff;
  tail[padLen - 3] = (bitLenLo >>> 16) & 0xff;
  tail[padLen - 2] = (bitLenLo >>> 8) & 0xff;
  tail[padLen - 1] = bitLenLo & 0xff;
  sha256CompressBlock(innerState, tail, 0);
  if (padLen === 128) sha256CompressBlock(innerState, tail, 64);

  // Outer block is always 64 bytes (opad) + 32 bytes (inner digest) = 96 bytes = 768 bits
  const outerBlock = new Uint8Array(64);
  for (let i = 0; i < 8; i++) {
    outerBlock[i * 4] = (innerState[i] >>> 24) & 0xff;
    outerBlock[i * 4 + 1] = (innerState[i] >>> 16) & 0xff;
    outerBlock[i * 4 + 2] = (innerState[i] >>> 8) & 0xff;
    outerBlock[i * 4 + 3] = innerState[i] & 0xff;
  }
  outerBlock[32] = 0x80;
  // 96 * 8 = 768 = 0x0300
  outerBlock[62] = 0x03;
  outerBlock[63] = 0x00;

  const outerState = new Uint32Array(ctx.outerInit);
  sha256CompressBlock(outerState, outerBlock, 0);

  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    out[i * 4] = (outerState[i] >>> 24) & 0xff;
    out[i * 4 + 1] = (outerState[i] >>> 16) & 0xff;
    out[i * 4 + 2] = (outerState[i] >>> 8) & 0xff;
    out[i * 4 + 3] = outerState[i] & 0xff;
  }
  return out;
}

function hmacSha256Block32(ctx, block32, outState, scratch64) {
  // Fast specialized path for PBKDF2 inner loop where input is always exactly 32 bytes
  outState.set(ctx.innerInit);
  scratch64.fill(0);
  scratch64.set(block32, 0);
  scratch64[32] = 0x80;
  // (64 + 32) * 8 = 768 = 0x0300
  scratch64[62] = 0x03;
  scratch64[63] = 0x00;
  sha256CompressBlock(outState, scratch64, 0);

  scratch64.fill(0);
  for (let i = 0; i < 8; i++) {
    scratch64[i * 4] = (outState[i] >>> 24) & 0xff;
    scratch64[i * 4 + 1] = (outState[i] >>> 16) & 0xff;
    scratch64[i * 4 + 2] = (outState[i] >>> 8) & 0xff;
    scratch64[i * 4 + 3] = outState[i] & 0xff;
  }
  scratch64[32] = 0x80;
  scratch64[62] = 0x03;
  scratch64[63] = 0x00;

  outState.set(ctx.outerInit);
  sha256CompressBlock(outState, scratch64, 0);

  for (let i = 0; i < 8; i++) {
    block32[i * 4] = (outState[i] >>> 24) & 0xff;
    block32[i * 4 + 1] = (outState[i] >>> 16) & 0xff;
    block32[i * 4 + 2] = (outState[i] >>> 8) & 0xff;
    block32[i * 4 + 3] = outState[i] & 0xff;
  }
}

function pbkdf2Sha256Pure(passwordBytes, saltBytes, iterations, dkLen) {
  if (!Number.isInteger(iterations) || iterations < 1) {
    throw new Error("PBKDF2 iterations must be a positive integer");
  }
  const ctx = makeHmacSha256Context(passwordBytes);
  const blockCount = Math.ceil(dkLen / 32);
  const out = new Uint8Array(blockCount * 32);
  const saltPlusIndex = new Uint8Array(saltBytes.length + 4);
  saltPlusIndex.set(saltBytes, 0);

  const workState = new Uint32Array(8);
  const scratch64 = new Uint8Array(64);

  try {
    for (let b = 1; b <= blockCount; b++) {
      saltPlusIndex[saltBytes.length] = (b >>> 24) & 0xff;
      saltPlusIndex[saltBytes.length + 1] = (b >>> 16) & 0xff;
      saltPlusIndex[saltBytes.length + 2] = (b >>> 8) & 0xff;
      saltPlusIndex[saltBytes.length + 3] = b & 0xff;

      const u = hmacSha256Fast(ctx, saltPlusIndex);
      const t = new Uint8Array(u);

      for (let iter = 1; iter < iterations; iter++) {
        hmacSha256Block32(ctx, u, workState, scratch64);
        for (let j = 0; j < 32; j++) {
          t[j] ^= u[j];
        }
      }
      out.set(t, (b - 1) * 32);
      u.fill(0);
      t.fill(0);
    }
    return out.subarray(0, dkLen);
  } finally {
    _shaW.fill(0);
    workState.fill(0);
    scratch64.fill(0);
    saltPlusIndex.fill(0);
    ctx.innerInit.fill(0);
    ctx.outerInit.fill(0);
  }
}

function yieldMacrotask() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

async function pbkdf2Sha256PureAsync(passwordBytes, saltBytes, iterations, dkLen) {
  if (!Number.isInteger(iterations) || iterations < 1) {
    throw new Error("PBKDF2 iterations must be a positive integer");
  }
  // Yield once before heavy work so UI busy states ("unlocking...") paint immediately
  await yieldMacrotask();

  const ctx = makeHmacSha256Context(passwordBytes);
  const blockCount = Math.ceil(dkLen / 32);
  const out = new Uint8Array(blockCount * 32);
  const saltPlusIndex = new Uint8Array(saltBytes.length + 4);
  saltPlusIndex.set(saltBytes, 0);

  const workState = new Uint32Array(8);
  const scratch64 = new Uint8Array(64);
  const CHUNK_ITERS = 25000;

  try {
    for (let b = 1; b <= blockCount; b++) {
      saltPlusIndex[saltBytes.length] = (b >>> 24) & 0xff;
      saltPlusIndex[saltBytes.length + 1] = (b >>> 16) & 0xff;
      saltPlusIndex[saltBytes.length + 2] = (b >>> 8) & 0xff;
      saltPlusIndex[saltBytes.length + 3] = b & 0xff;

      const u = hmacSha256Fast(ctx, saltPlusIndex);
      const t = new Uint8Array(u);

      for (let iter = 1; iter < iterations; iter++) {
        hmacSha256Block32(ctx, u, workState, scratch64);
        for (let j = 0; j < 32; j++) {
          t[j] ^= u[j];
        }
        if (iter % CHUNK_ITERS === 0) {
          await yieldMacrotask();
        }
      }
      out.set(t, (b - 1) * 32);
      u.fill(0);
      t.fill(0);
    }
    return out.subarray(0, dkLen);
  } finally {
    _shaW.fill(0);
    workState.fill(0);
    scratch64.fill(0);
    saltPlusIndex.fill(0);
    ctx.innerInit.fill(0);
    ctx.outerInit.fill(0);
  }
}

// ============================================================================
// PURE-JS FIPS 197 AES-256 + NIST SP 800-38D GCM
// ============================================================================

const AES_SBOX = new Uint8Array([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]);

const AES_RCON = new Uint8Array([0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40]);

function xtime(a) {
  return ((a << 1) ^ ((a & 0x80) ? 0x1b : 0x00)) & 0xff;
}

function aes256ExpandKey(key32) {
  if (key32.length !== 32) {
    throw new Error("AES-256 requires a 32-byte key");
  }
  const roundKeys = new Uint8Array(240); // 15 round keys * 16 bytes
  roundKeys.set(key32, 0);
  let bytesGenerated = 32;
  let rconIter = 1;
  const temp = new Uint8Array(4);

  while (bytesGenerated < 240) {
    for (let i = 0; i < 4; i++) {
      temp[i] = roundKeys[bytesGenerated - 4 + i];
    }
    if (bytesGenerated % 32 === 0) {
      const t0 = temp[0];
      temp[0] = AES_SBOX[temp[1]] ^ AES_RCON[rconIter++];
      temp[1] = AES_SBOX[temp[2]];
      temp[2] = AES_SBOX[temp[3]];
      temp[3] = AES_SBOX[t0];
    } else if (bytesGenerated % 32 === 16) {
      temp[0] = AES_SBOX[temp[0]];
      temp[1] = AES_SBOX[temp[1]];
      temp[2] = AES_SBOX[temp[2]];
      temp[3] = AES_SBOX[temp[3]];
    }
    for (let i = 0; i < 4; i++) {
      roundKeys[bytesGenerated] = roundKeys[bytesGenerated - 32] ^ temp[i];
      bytesGenerated++;
    }
  }
  return roundKeys;
}

function aes256EncryptBlock(roundKeys, input16, out16) {
  const s = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    s[i] = input16[i] ^ roundKeys[i];
  }

  for (let round = 1; round <= 14; round++) {
    // SubBytes
    for (let i = 0; i < 16; i++) {
      s[i] = AES_SBOX[s[i]];
    }
    // ShiftRows (column-major layout: col c, row r -> index c*4 + r)
    let t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;

    t = s[2];
    const t2 = s[6];
    s[2] = s[10];
    s[6] = s[14];
    s[10] = t;
    s[14] = t2;

    t = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t;

    // MixColumns (skipped on final round 14)
    if (round < 14) {
      for (let c = 0; c < 4; c++) {
        const idx = c * 4;
        const a0 = s[idx];
        const a1 = s[idx + 1];
        const a2 = s[idx + 2];
        const a3 = s[idx + 3];
        const xorAll = a0 ^ a1 ^ a2 ^ a3;
        s[idx] = a0 ^ xorAll ^ xtime(a0 ^ a1);
        s[idx + 1] = a1 ^ xorAll ^ xtime(a1 ^ a2);
        s[idx + 2] = a2 ^ xorAll ^ xtime(a2 ^ a3);
        s[idx + 3] = a3 ^ xorAll ^ xtime(a3 ^ a0);
      }
    }

    // AddRoundKey
    const rkOffset = round * 16;
    for (let i = 0; i < 16; i++) {
      s[i] ^= roundKeys[rkOffset + i];
    }
  }

  out16.set(s, 0);
}

// GF(2^128) multiplication per NIST SP 800-38D Algorithm 1
function gcmMul(x, y) {
  const z = new Uint8Array(16);
  const v = new Uint8Array(y);
  for (let i = 0; i < 128; i++) {
    const bit = (x[i >>> 3] >>> (7 - (i & 7))) & 1;
    if (bit) {
      for (let j = 0; j < 16; j++) z[j] ^= v[j];
    }
    const lsb = v[15] & 1;
    for (let j = 15; j > 0; j--) {
      v[j] = ((v[j] >>> 1) | ((v[j - 1] & 1) << 7)) & 0xff;
    }
    v[0] = (v[0] >>> 1) & 0xff;
    if (lsb) v[0] ^= 0xe1;
  }
  return z;
}

function ghash(h, aad, ciphertext) {
  let y = new Uint8Array(16);

  const absorb = (data) => {
    const full = Math.floor(data.length / 16);
    for (let i = 0; i < full; i++) {
      for (let j = 0; j < 16; j++) y[j] ^= data[i * 16 + j];
      y = gcmMul(y, h);
    }
    const rem = data.length - full * 16;
    if (rem > 0) {
      for (let j = 0; j < rem; j++) y[j] ^= data[full * 16 + j];
      y = gcmMul(y, h);
    }
  };

  if (aad && aad.length > 0) absorb(aad);
  if (ciphertext && ciphertext.length > 0) absorb(ciphertext);

  const lenBlock = new Uint8Array(16);
  const aadBits = (aad ? aad.length : 0) * 8;
  const ctBits = (ciphertext ? ciphertext.length : 0) * 8;
  const writeUint64BE = (buf, offset, val) => {
    const hi = Math.floor(val / 0x100000000);
    const lo = val >>> 0;
    buf[offset] = (hi >>> 24) & 0xff;
    buf[offset + 1] = (hi >>> 16) & 0xff;
    buf[offset + 2] = (hi >>> 8) & 0xff;
    buf[offset + 3] = hi & 0xff;
    buf[offset + 4] = (lo >>> 24) & 0xff;
    buf[offset + 5] = (lo >>> 16) & 0xff;
    buf[offset + 6] = (lo >>> 8) & 0xff;
    buf[offset + 7] = lo & 0xff;
  };
  writeUint64BE(lenBlock, 0, aadBits);
  writeUint64BE(lenBlock, 8, ctBits);
  for (let j = 0; j < 16; j++) y[j] ^= lenBlock[j];
  return gcmMul(y, h);
}

function gcmInc32(counter) {
  const next = new Uint8Array(counter);
  const c =
    (((next[12] << 24) | (next[13] << 16) | (next[14] << 8) | next[15]) + 1) >>> 0;
  next[12] = (c >>> 24) & 0xff;
  next[13] = (c >>> 16) & 0xff;
  next[14] = (c >>> 8) & 0xff;
  next[15] = c & 0xff;
  return next;
}

function aes256GcmEncryptPure(key32, iv12, plaintext, aad = new Uint8Array(0)) {
  if (iv12.length !== GCM_IV_BYTES) {
    throw new Error("AES-GCM requires a 12-byte IV");
  }
  const roundKeys = aes256ExpandKey(key32);
  const h = new Uint8Array(16);
  aes256EncryptBlock(roundKeys, new Uint8Array(16), h);

  const j0 = new Uint8Array(16);
  j0.set(iv12, 0);
  j0[15] = 1;

  const ct = new Uint8Array(plaintext.length);
  let ctr = gcmInc32(j0);
  const keystream = new Uint8Array(16);
  for (let offset = 0; offset < plaintext.length; offset += 16) {
    aes256EncryptBlock(roundKeys, ctr, keystream);
    const take = Math.min(16, plaintext.length - offset);
    for (let i = 0; i < take; i++) {
      ct[offset + i] = plaintext[offset + i] ^ keystream[i];
    }
    ctr = gcmInc32(ctr);
  }

  const s = ghash(h, aad, ct);
  const ej0 = new Uint8Array(16);
  aes256EncryptBlock(roundKeys, j0, ej0);
  const tag = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    tag[i] = s[i] ^ ej0[i];
  }

  const combined = new Uint8Array(ct.length + GCM_TAG_BYTES);
  combined.set(ct, 0);
  combined.set(tag, ct.length);
  roundKeys.fill(0);
  keystream.fill(0);
  h.fill(0);
  s.fill(0);
  j0.fill(0);
  ej0.fill(0);
  ctr.fill(0);
  return combined;
}

function aes256GcmDecryptPure(key32, iv12, combinedCtTag, aad = new Uint8Array(0)) {
  if (iv12.length !== GCM_IV_BYTES) {
    throw new Error("AES-GCM requires a 12-byte IV");
  }
  if (combinedCtTag.length < GCM_TAG_BYTES) {
    throw new Error("Ciphertext too short");
  }
  const ct = combinedCtTag.subarray(0, combinedCtTag.length - GCM_TAG_BYTES);
  const receivedTag = combinedCtTag.subarray(combinedCtTag.length - GCM_TAG_BYTES);

  const roundKeys = aes256ExpandKey(key32);
  const h = new Uint8Array(16);
  aes256EncryptBlock(roundKeys, new Uint8Array(16), h);

  const j0 = new Uint8Array(16);
  j0.set(iv12, 0);
  j0[15] = 1;

  const s = ghash(h, aad, ct);
  const ej0 = new Uint8Array(16);
  aes256EncryptBlock(roundKeys, j0, ej0);
  const expectedTag = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    expectedTag[i] = s[i] ^ ej0[i];
  }

  if (!constantTimeEqual(receivedTag, expectedTag)) {
    roundKeys.fill(0);
    h.fill(0);
    s.fill(0);
    j0.fill(0);
    ej0.fill(0);
    throw new Error("Authentication tag mismatch — wrong password or corrupted ciphertext");
  }

  const pt = new Uint8Array(ct.length);
  let ctr = gcmInc32(j0);
  const keystream = new Uint8Array(16);
  for (let offset = 0; offset < ct.length; offset += 16) {
    aes256EncryptBlock(roundKeys, ctr, keystream);
    const take = Math.min(16, ct.length - offset);
    for (let i = 0; i < take; i++) {
      pt[offset + i] = ct[offset + i] ^ keystream[i];
    }
    ctr = gcmInc32(ctr);
  }
  roundKeys.fill(0);
  keystream.fill(0);
  h.fill(0);
  s.fill(0);
  j0.fill(0);
  ej0.fill(0);
  ctr.fill(0);
  return pt;
}

// ============================================================================
// UNIFIED HIGH-LEVEL VAULT API (WEB CRYPTO + PURE-JS FALLBACK)
// ============================================================================

async function pbkdf2Derive64(password, saltBytes, iterations) {
  if (!Number.isInteger(iterations) || iterations < 1) {
    throw new Error("PBKDF2 iterations must be a positive integer");
  }
  const pwBytes = textEncoder.encode(password);
  try {
    if (isNativeWebCryptoAvailable()) {
      const baseKey = await globalThis.crypto.subtle.importKey(
        "raw",
        pwBytes,
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
      );
      const bits = await globalThis.crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: saltBytes,
          iterations,
          hash: "SHA-256",
        },
        baseKey,
        512
      );
      return new Uint8Array(bits);
    }
    return await pbkdf2Sha256PureAsync(pwBytes, saltBytes, iterations, 64);
  } finally {
    pwBytes.fill(0);
  }
}

async function aesGcmEncryptRaw(keyBytes, ivBytes, plaintextBytes, aadBytes) {
  if (isNativeWebCryptoAvailable()) {
    const key = await globalThis.crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );
    const params =
      aadBytes && aadBytes.length > 0
        ? { name: "AES-GCM", iv: ivBytes, additionalData: aadBytes, tagLength: 128 }
        : { name: "AES-GCM", iv: ivBytes, tagLength: 128 };
    const encrypted = await globalThis.crypto.subtle.encrypt(params, key, plaintextBytes);
    return new Uint8Array(encrypted);
  }
  return aes256GcmEncryptPure(keyBytes, ivBytes, plaintextBytes, aadBytes || new Uint8Array(0));
}

async function aesGcmDecryptRaw(keyBytes, ivBytes, ciphertextBytes, aadBytes) {
  if (isNativeWebCryptoAvailable()) {
    const key = await globalThis.crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );
    const params =
      aadBytes && aadBytes.length > 0
        ? { name: "AES-GCM", iv: ivBytes, additionalData: aadBytes, tagLength: 128 }
        : { name: "AES-GCM", iv: ivBytes, tagLength: 128 };
    const decrypted = await globalThis.crypto.subtle.decrypt(params, key, ciphertextBytes);
    return new Uint8Array(decrypted);
  }
  return aes256GcmDecryptPure(keyBytes, ivBytes, ciphertextBytes, aadBytes || new Uint8Array(0));
}

/**
 * Derives two cryptographically independent 256-bit keys from password + salt:
 * - authKeyB64: sent to the server for login verification (never decrypts data)
 * - kekBytes: stays strictly in browser memory to wrap/unwrap the random DEK
 */
export async function deriveAuthAndKek(password, kdfSaltB64, iterations = DEFAULT_KDF_ITERATIONS) {
  const saltBytes = base64ToBytes(kdfSaltB64);
  const derived = await pbkdf2Derive64(password, saltBytes, iterations);
  const authKeyBytes = derived.slice(0, 32);
  const kekBytes = derived.slice(32, 64);
  const authKeyB64 = bytesToBase64(authKeyBytes);
  derived.fill(0);
  authKeyBytes.fill(0);
  return {
    authKeyB64,
    kekBytes,
  };
}

export function generateSaltB64() {
  return bytesToBase64(generateRandomBytes(16));
}

export function generateDek() {
  return generateRandomBytes(32);
}

/**
 * Generates a 160-bit random recovery key formatted as 8 groups of 4 unambiguous Base32 characters.
 */
export function generateRecoveryKey() {
  const bytes = generateRandomBytes(20); // 160 bits = 32 * 5 bits
  let chars = "";
  let bitBuf = 0;
  let bitCount = 0;
  for (let i = 0; i < bytes.length; i++) {
    bitBuf = (bitBuf << 8) | bytes[i];
    bitCount += 8;
    while (bitCount >= 5) {
      bitCount -= 5;
      chars += RECOVERY_ALPHABET[(bitBuf >>> bitCount) & 31];
    }
  }
  bytes.fill(0);
  return chars.match(/.{1,4}/g).join("-");
}

export function normalizeRecoveryKey(raw) {
  // Crockford Base32 normalization: strip separators, uppercase, map O->0 and I/L->1
  const cleaned = String(raw || "")
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");
  if (cleaned.length !== 32) return "";
  for (let i = 0; i < cleaned.length; i++) {
    if (RECOVERY_ALPHABET.indexOf(cleaned[i]) === -1) return "";
  }
  return cleaned;
}

export async function wrapDek(dekBytes, kekBytes, aadStr = "heyjournal:dek:v1") {
  const iv = generateRandomBytes(GCM_IV_BYTES);
  const aad = textEncoder.encode(aadStr);
  const ct = await aesGcmEncryptRaw(kekBytes, iv, dekBytes, aad);
  return JSON.stringify({
    v: 1,
    alg: "A256GCM",
    iv: bytesToBase64(iv),
    ct: bytesToBase64(ct),
  });
}

export async function unwrapDek(wrappedDekJson, kekBytes, aadStr = "heyjournal:dek:v1") {
  const parsed = JSON.parse(wrappedDekJson);
  if (
    !parsed ||
    typeof parsed !== "object" ||
    parsed.v !== 1 ||
    parsed.alg !== "A256GCM" ||
    typeof parsed.iv !== "string" ||
    typeof parsed.ct !== "string"
  ) {
    throw new Error("Unsupported vault key envelope");
  }
  const iv = base64ToBytes(parsed.iv);
  const ct = base64ToBytes(parsed.ct);
  if (iv.length !== GCM_IV_BYTES || ct.length < GCM_TAG_BYTES) {
    throw new Error("Invalid vault key envelope length");
  }
  const aad = textEncoder.encode(aadStr);
  const dek = await aesGcmDecryptRaw(kekBytes, iv, ct, aad);
  if (dek.length !== 32) {
    throw new Error("Invalid unwrapped vault key length");
  }
  return dek;
}

export async function encryptJson(obj, dekBytes, aadStr = "") {
  const iv = generateRandomBytes(GCM_IV_BYTES);
  const pt = textEncoder.encode(JSON.stringify(obj));
  const aad = aadStr ? textEncoder.encode(aadStr) : new Uint8Array(0);
  const ct = await aesGcmEncryptRaw(dekBytes, iv, pt, aad);
  return JSON.stringify({
    v: 1,
    alg: "A256GCM",
    iv: bytesToBase64(iv),
    ct: bytesToBase64(ct),
  });
}

export async function decryptJson(blobJson, dekBytes, aadStr = "") {
  const parsed = JSON.parse(blobJson);
  if (
    !parsed ||
    typeof parsed !== "object" ||
    parsed.v !== 1 ||
    parsed.alg !== "A256GCM" ||
    typeof parsed.iv !== "string" ||
    typeof parsed.ct !== "string"
  ) {
    throw new Error("Unsupported encrypted payload envelope");
  }
  const iv = base64ToBytes(parsed.iv);
  const ct = base64ToBytes(parsed.ct);
  if (iv.length !== GCM_IV_BYTES || ct.length < GCM_TAG_BYTES) {
    throw new Error("Invalid encrypted payload envelope length");
  }
  const aad = aadStr ? textEncoder.encode(aadStr) : new Uint8Array(0);
  const pt = await aesGcmDecryptRaw(dekBytes, iv, ct, aad);
  return JSON.parse(textDecoder.decode(pt));
}

// Export pure-JS primitives strictly for automated NIST & cross-engine test verification
export const _pureJs = {
  sha256,
  pbkdf2Sha256Pure,
  pbkdf2Sha256PureAsync,
  aes256GcmEncryptPure,
  aes256GcmDecryptPure,
};
