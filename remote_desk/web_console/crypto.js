/* Asistencia Remota Antonio Ortega — Cifrado E2E (PBKDF2-SHA256 + HMAC + AES-256-GCM)
 * Usa Web Crypto API nativo en HTTPS/localhost y fallback JS puro en HTTP de red local (iOS Safari).
 */
(function (global) {
  "use strict";

  const PBKDF2_ITERATIONS = 100000;
  const AUTH_LABEL = new TextEncoder().encode("winremotedesk-auth-v1");
  const ENC_LABEL = new TextEncoder().encode("winremotedesk-e2e-v1");
  const HAS_SUBTLE = !!(global.crypto && global.crypto.subtle);

  function bytesToBase64(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function base64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToHex(bytes) {
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex;
  }

  function randomBytes(len) {
    const out = new Uint8Array(len);
    if (global.crypto && global.crypto.getRandomValues) {
      global.crypto.getRandomValues(out);
    } else {
      for (let i = 0; i < len; i++) out[i] = (Math.random() * 256) | 0;
    }
    return out;
  }

  // =========================================================================
  // Implementación pura JS (FIPS 180-4 SHA-256 + RFC 2104 HMAC + PBKDF2 + AES-256-GCM)
  // =========================================================================
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

  function sha256Pure(data) {
    const len = data.length;
    const bitLenHi = Math.floor((len * 8) / 0x100000000);
    const bitLenLo = (len * 8) >>> 0;
    const padLen = (((len + 9 + 63) >> 6) << 6);
    const buf = new Uint8Array(padLen);
    buf.set(data);
    buf[len] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(padLen - 8, bitLenHi, false);
    dv.setUint32(padLen - 4, bitLenLo, false);

    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    const w = new Uint32Array(64);

    for (let off = 0; off < padLen; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
      for (let i = 16; i < 64; i++) {
        const s0 = ((w[i - 15] >>> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >>> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >>> 3);
        const s1 = ((w[i - 2] >>> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >>> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (let i = 0; i < 64; i++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }

    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    odv.setUint32(0, h0, false); odv.setUint32(4, h1, false);
    odv.setUint32(8, h2, false); odv.setUint32(12, h3, false);
    odv.setUint32(16, h4, false); odv.setUint32(20, h5, false);
    odv.setUint32(24, h6, false); odv.setUint32(28, h7, false);
    return out;
  }

  function hmacSha256Pure(key, msg) {
    let k = key.length > 64 ? sha256Pure(key) : key;
    const ipad = new Uint8Array(64 + msg.length);
    const opad = new Uint8Array(64 + 32);
    for (let i = 0; i < 64; i++) {
      const kb = i < k.length ? k[i] : 0;
      ipad[i] = kb ^ 0x36;
      opad[i] = kb ^ 0x5c;
    }
    ipad.set(msg, 64);
    opad.set(sha256Pure(ipad), 64);
    return sha256Pure(opad);
  }

  async function pbkdf2Sha256Pure(passwordBytes, salt, iterations) {
    const block = new Uint8Array(salt.length + 4);
    block.set(salt, 0);
    block[salt.length + 3] = 1;
    let u = hmacSha256Pure(passwordBytes, block);
    const out = new Uint8Array(u);
    for (let i = 1; i < iterations; i++) {
      u = hmacSha256Pure(passwordBytes, u);
      for (let j = 0; j < 32; j++) out[j] ^= u[j];
      if ((i & 4095) === 0) await new Promise((r) => setTimeout(r, 0));
    }
    return out;
  }

  // AES-256 (FIPS 197)
  const SBOX = new Uint8Array([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
  ]);
  const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

  function aes256ExpandKey(key) {
    const rk = new Uint8Array(240);
    rk.set(key, 0);
    let rconIdx = 0;
    for (let i = 32; i < 240; i += 4) {
      let t0 = rk[i - 4], t1 = rk[i - 3], t2 = rk[i - 2], t3 = rk[i - 1];
      if ((i & 31) === 0) {
        const tmp = t0;
        t0 = SBOX[t1] ^ RCON[rconIdx++];
        t1 = SBOX[t2];
        t2 = SBOX[t3];
        t3 = SBOX[tmp];
      } else if ((i & 31) === 16) {
        t0 = SBOX[t0]; t1 = SBOX[t1]; t2 = SBOX[t2]; t3 = SBOX[t3];
      }
      rk[i] = rk[i - 32] ^ t0;
      rk[i + 1] = rk[i - 31] ^ t1;
      rk[i + 2] = rk[i - 30] ^ t2;
      rk[i + 3] = rk[i - 29] ^ t3;
    }
    return rk;
  }

  function xtime(a) {
    return ((a << 1) ^ ((a & 0x80) ? 0x1b : 0)) & 0xff;
  }

  function aes256EncryptBlock(rk, block) {
    const s = new Uint8Array(16);
    for (let i = 0; i < 16; i++) s[i] = block[i] ^ rk[i];
    for (let round = 1; round <= 14; round++) {
      // SubBytes + ShiftRows
      const t0 = SBOX[s[0]], t1 = SBOX[s[5]], t2 = SBOX[s[10]], t3 = SBOX[s[15]];
      const t4 = SBOX[s[4]], t5 = SBOX[s[9]], t6 = SBOX[s[14]], t7 = SBOX[s[3]];
      const t8 = SBOX[s[8]], t9 = SBOX[s[13]], t10 = SBOX[s[2]], t11 = SBOX[s[7]];
      const t12 = SBOX[s[12]], t13 = SBOX[s[1]], t14 = SBOX[s[6]], t15 = SBOX[s[11]];
      const ro = round * 16;
      if (round < 14) {
        const cols = [
          [t0, t1, t2, t3],
          [t4, t5, t6, t7],
          [t8, t9, t10, t11],
          [t12, t13, t14, t15],
        ];
        for (let c = 0; c < 4; c++) {
          const a0 = cols[c][0], a1 = cols[c][1], a2 = cols[c][2], a3 = cols[c][3];
          const xr = a0 ^ a1 ^ a2 ^ a3;
          s[c * 4 + 0] = a0 ^ xr ^ xtime(a0 ^ a1) ^ rk[ro + c * 4 + 0];
          s[c * 4 + 1] = a1 ^ xr ^ xtime(a1 ^ a2) ^ rk[ro + c * 4 + 1];
          s[c * 4 + 2] = a2 ^ xr ^ xtime(a2 ^ a3) ^ rk[ro + c * 4 + 2];
          s[c * 4 + 3] = a3 ^ xr ^ xtime(a3 ^ a0) ^ rk[ro + c * 4 + 3];
        }
      } else {
        s[0] = t0 ^ rk[ro + 0]; s[1] = t1 ^ rk[ro + 1]; s[2] = t2 ^ rk[ro + 2]; s[3] = t3 ^ rk[ro + 3];
        s[4] = t4 ^ rk[ro + 4]; s[5] = t5 ^ rk[ro + 5]; s[6] = t6 ^ rk[ro + 6]; s[7] = t7 ^ rk[ro + 7];
        s[8] = t8 ^ rk[ro + 8]; s[9] = t9 ^ rk[ro + 9]; s[10] = t10 ^ rk[ro + 10]; s[11] = t11 ^ rk[ro + 11];
        s[12] = t12 ^ rk[ro + 12]; s[13] = t13 ^ rk[ro + 13]; s[14] = t14 ^ rk[ro + 14]; s[15] = t15 ^ rk[ro + 15];
      }
    }
    return s;
  }

  function gfMul(x, y) {
    const z = new Uint8Array(16);
    const v = new Uint8Array(y);
    for (let i = 0; i < 16; i++) {
      let xi = x[i];
      for (let bit = 7; bit >= 0; bit--) {
        if ((xi >>> bit) & 1) {
          for (let j = 0; j < 16; j++) z[j] ^= v[j];
        }
        const lsb = v[15] & 1;
        for (let j = 15; j > 0; j--) v[j] = (v[j] >>> 1) | ((v[j - 1] & 1) << 7);
        v[0] = (v[0] >>> 1) ^ (lsb ? 0xe1 : 0);
      }
    }
    return z;
  }

  function ghash(H, aad, ct) {
    let y = new Uint8Array(16);
    function updateBlocks(data) {
      for (let off = 0; off < data.length; off += 16) {
        for (let i = 0; i < 16 && off + i < data.length; i++) y[i] ^= data[off + i];
        y = gfMul(y, H);
      }
    }
    updateBlocks(aad);
    updateBlocks(ct);
    const lenBlock = new Uint8Array(16);
    const dv = new DataView(lenBlock.buffer);
    dv.setUint32(0, Math.floor((aad.length * 8) / 0x100000000), false);
    dv.setUint32(4, (aad.length * 8) >>> 0, false);
    dv.setUint32(8, Math.floor((ct.length * 8) / 0x100000000), false);
    dv.setUint32(12, (ct.length * 8) >>> 0, false);
    for (let i = 0; i < 16; i++) y[i] ^= lenBlock[i];
    return gfMul(y, H);
  }

  function gctr(rk, icb, input) {
    const out = new Uint8Array(input.length);
    const cb = new Uint8Array(icb);
    const dv = new DataView(cb.buffer);
    for (let off = 0; off < input.length; off += 16) {
      const ks = aes256EncryptBlock(rk, cb);
      const n = Math.min(16, input.length - off);
      for (let i = 0; i < n; i++) out[off + i] = input[off + i] ^ ks[i];
      dv.setUint32(12, (dv.getUint32(12, false) + 1) >>> 0, false);
    }
    return out;
  }

  function aesGcmEncryptPure(rk, H, nonce, plaintext, aad) {
    const j0 = new Uint8Array(16);
    j0.set(nonce, 0);
    j0[15] = 1;
    const icb = new Uint8Array(j0);
    icb[15] = 2;
    const ct = gctr(rk, icb, plaintext);
    const s = ghash(H, aad, ct);
    const t0 = aes256EncryptBlock(rk, j0);
    const out = new Uint8Array(ct.length + 16);
    out.set(ct, 0);
    for (let i = 0; i < 16; i++) out[ct.length + i] = s[i] ^ t0[i];
    return out;
  }

  function aesGcmDecryptPure(rk, H, nonce, ctWithTag, aad) {
    if (ctWithTag.length < 16) throw new Error("Etiqueta GCM incompleta.");
    const ct = ctWithTag.subarray(0, ctWithTag.length - 16);
    const tag = ctWithTag.subarray(ctWithTag.length - 16);
    const j0 = new Uint8Array(16);
    j0.set(nonce, 0);
    j0[15] = 1;
    const s = ghash(H, aad, ct);
    const t0 = aes256EncryptBlock(rk, j0);
    let diff = 0;
    for (let i = 0; i < 16; i++) diff |= (s[i] ^ t0[i]) ^ tag[i];
    if (diff !== 0) throw new Error("Autenticación AES-GCM inválida.");
    const icb = new Uint8Array(j0);
    icb[15] = 2;
    return gctr(rk, icb, ct);
  }

  // =========================================================================
  // API Pública Unificada (WebCrypto si hay HTTPS/localhost, si no Pure JS)
  // =========================================================================
  async function sha256Hex(data) {
    if (HAS_SUBTLE) {
      const digest = await global.crypto.subtle.digest("SHA-256", data);
      return bytesToHex(new Uint8Array(digest));
    }
    return bytesToHex(sha256Pure(data));
  }

  async function hmacSha256(keyBytes, dataBytes) {
    if (HAS_SUBTLE) {
      const k = await global.crypto.subtle.importKey(
        "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
      );
      const sig = await global.crypto.subtle.sign("HMAC", k, dataBytes);
      return new Uint8Array(sig);
    }
    return hmacSha256Pure(keyBytes, dataBytes);
  }

  async function deriveSessionKeys(pin, saltBytes) {
    const pinBytes = new TextEncoder().encode(pin);
    let masterKey;
    if (HAS_SUBTLE) {
      const baseKey = await global.crypto.subtle.importKey(
        "raw", pinBytes, { name: "PBKDF2" }, false, ["deriveBits"]
      );
      const bits = await global.crypto.subtle.deriveBits(
        { name: "PBKDF2", salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
        baseKey,
        256
      );
      masterKey = new Uint8Array(bits);
    } else {
      masterKey = await pbkdf2Sha256Pure(pinBytes, saltBytes, PBKDF2_ITERATIONS);
    }
    const authKey = await hmacSha256(masterKey, AUTH_LABEL);
    const encKey = await hmacSha256(masterKey, ENC_LABEL);
    return { salt: saltBytes, authKey, encKey };
  }

  async function computeAuthProof(authKey, nonceBytes) {
    const sig = await hmacSha256(authKey, nonceBytes);
    return bytesToBase64(sig);
  }

  class E2ECipher {
    constructor(encKeyBytes) {
      this._encKeyBytes = encKeyBytes;
      this._subtleKeyPromise = HAS_SUBTLE
        ? global.crypto.subtle.importKey("raw", encKeyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"])
        : null;
      this._rk = HAS_SUBTLE ? null : aes256ExpandKey(encKeyBytes);
      this._H = HAS_SUBTLE ? null : aes256EncryptBlock(this._rk, new Uint8Array(16));
      this._sendSeq = 0;
      this._recvSeq = -1;
    }

    async encrypt(plaintext) {
      const seq = this._sendSeq++;
      const aad = new Uint8Array(8);
      const dv = new DataView(aad.buffer);
      dv.setUint32(0, Math.floor(seq / 0x100000000), false);
      dv.setUint32(4, seq >>> 0, false);
      const nonce = randomBytes(12);

      let ct;
      if (this._subtleKeyPromise) {
        const key = await this._subtleKeyPromise;
        const buf = await global.crypto.subtle.encrypt(
          { name: "AES-GCM", iv: nonce, additionalData: aad },
          key,
          plaintext
        );
        ct = new Uint8Array(buf);
      } else {
        ct = aesGcmEncryptPure(this._rk, this._H, nonce, plaintext, aad);
      }

      const packet = new Uint8Array(20 + ct.length);
      packet.set(aad, 0);
      packet.set(nonce, 8);
      packet.set(ct, 20);
      return packet;
    }

    async decrypt(packet) {
      if (packet.length <= 36) throw new Error("Paquete cifrado incompleto.");
      const aad = packet.subarray(0, 8);
      const dv = new DataView(packet.buffer, packet.byteOffset, 8);
      const seq = dv.getUint32(0, false) * 0x100000000 + dv.getUint32(4, false);
      if (seq <= this._recvSeq) throw new Error("Secuencia repetida o fuera de orden.");
      const nonce = packet.subarray(8, 20);
      const ct = packet.subarray(20);

      let plain;
      if (this._subtleKeyPromise) {
        const key = await this._subtleKeyPromise;
        const buf = await global.crypto.subtle.decrypt(
          { name: "AES-GCM", iv: nonce, additionalData: aad },
          key,
          ct
        );
        plain = new Uint8Array(buf);
      } else {
        plain = aesGcmDecryptPure(this._rk, this._H, nonce, ct, aad);
      }
      this._recvSeq = seq;
      return plain;
    }
  }

  global.AOCrypto = {
    HAS_SUBTLE,
    bytesToBase64,
    base64ToBytes,
    bytesToHex,
    sha256Hex,
    deriveSessionKeys,
    computeAuthProof,
    E2ECipher,
  };
})(typeof window !== "undefined" ? window : globalThis);
