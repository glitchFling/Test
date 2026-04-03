// AccessGateWASM.js
//
// Loader for Emscripten-built index.wasm.
// Expects exports:
//   _malloc, _free
//   _ag_generate_2auth
//   _ag_deterministic_id
//   _ag_is_valid_id

const HEX = Array.from({ length: 256 }, (_, i) =>
  i.toString(16).padStart(2, "0")
);

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => HEX[b]).join("");
}

function bytesToBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;

  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }

  return btoa(binary);
}

function rotr64(hi, lo, bits) {
  bits &= 63;
  if (bits === 0) return [hi >>> 0, lo >>> 0];
  if (bits < 32) {
    return [
      ((hi >>> bits) | (lo << (32 - bits))) >>> 0,
      ((lo >>> bits) | (hi << (32 - bits))) >>> 0
    ];
  }
  if (bits === 32) return [lo >>> 0, hi >>> 0];

  const shift = bits - 32;
  return [
    ((lo >>> shift) | (hi << (32 - shift))) >>> 0,
    ((hi >>> shift) | (lo << (32 - shift))) >>> 0
  ];
}

function shr64(hi, lo, bits) {
  if (bits === 0) return [hi >>> 0, lo >>> 0];
  if (bits < 32) {
    return [
      hi >>> bits,
      ((lo >>> bits) | (hi << (32 - bits))) >>> 0
    ];
  }
  if (bits === 32) return [0, hi >>> 0];
  if (bits < 64) return [0, hi >>> (bits - 32)];
  return [0, 0];
}

function xor64(aHi, aLo, bHi, bLo) {
  return [(aHi ^ bHi) >>> 0, (aLo ^ bLo) >>> 0];
}

function add64(...parts) {
  let lo = 0;
  let hi = 0;

  for (const [partHi, partLo] of parts) {
    const nextLo = (lo + partLo) >>> 0;
    hi = (hi + partHi + (nextLo < lo ? 1 : 0)) >>> 0;
    lo = nextLo;
  }

  return [hi, lo];
}

function sha256(bytes) {
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  const H = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ]);

  const paddedLength = (((bytes.length + 9 + 63) >> 6) << 6);
  const data = new Uint8Array(paddedLength);
  data.set(bytes);
  data[bytes.length] = 0x80;

  const bitLength = bytes.length * 8;
  data[data.length - 4] = (bitLength >>> 24) & 0xff;
  data[data.length - 3] = (bitLength >>> 16) & 0xff;
  data[data.length - 2] = (bitLength >>> 8) & 0xff;
  data[data.length - 1] = bitLength & 0xff;

  const w = new Uint32Array(64);

  for (let offset = 0; offset < data.length; offset += 64) {
    for (let i = 0; i < 16; i += 1) {
      const j = offset + i * 4;
      w[i] = (
        (data[j] << 24) |
        (data[j + 1] << 16) |
        (data[j + 2] << 8) |
        data[j + 3]
      ) >>> 0;
    }

    for (let i = 16; i < 64; i += 1) {
      const s0 = (
        ((w[i - 15] >>> 7) | (w[i - 15] << 25)) ^
        ((w[i - 15] >>> 18) | (w[i - 15] << 14)) ^
        (w[i - 15] >>> 3)
      ) >>> 0;
      const s1 = (
        ((w[i - 2] >>> 17) | (w[i - 2] << 15)) ^
        ((w[i - 2] >>> 19) | (w[i - 2] << 13)) ^
        (w[i - 2] >>> 10)
      ) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = H[0];
    let b = H[1];
    let c = H[2];
    let d = H[3];
    let e = H[4];
    let f = H[5];
    let g = H[6];
    let h = H[7];

    for (let i = 0; i < 64; i += 1) {
      const S1 = (
        ((e >>> 6) | (e << 26)) ^
        ((e >>> 11) | (e << 21)) ^
        ((e >>> 25) | (e << 7))
      ) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const temp1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = (
        ((a >>> 2) | (a << 30)) ^
        ((a >>> 13) | (a << 19)) ^
        ((a >>> 22) | (a << 10))
      ) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
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

    H[0] = (H[0] + a) >>> 0;
    H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0;
    H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0;
    H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0;
    H[7] = (H[7] + h) >>> 0;
  }

  const out = new Uint8Array(32);
  for (let i = 0; i < H.length; i += 1) {
    const word = H[i];
    out[i * 4] = (word >>> 24) & 0xff;
    out[i * 4 + 1] = (word >>> 16) & 0xff;
    out[i * 4 + 2] = (word >>> 8) & 0xff;
    out[i * 4 + 3] = word & 0xff;
  }
  return out;
}

function sha512(bytes) {
  const K = [
    [0x428a2f98, 0xd728ae22], [0x71374491, 0x23ef65cd],
    [0xb5c0fbcf, 0xec4d3b2f], [0xe9b5dba5, 0x8189dbbc],
    [0x3956c25b, 0xf348b538], [0x59f111f1, 0xb605d019],
    [0x923f82a4, 0xaf194f9b], [0xab1c5ed5, 0xda6d8118],
    [0xd807aa98, 0xa3030242], [0x12835b01, 0x45706fbe],
    [0x243185be, 0x4ee4b28c], [0x550c7dc3, 0xd5ffb4e2],
    [0x72be5d74, 0xf27b896f], [0x80deb1fe, 0x3b1696b1],
    [0x9bdc06a7, 0x25c71235], [0xc19bf174, 0xcf692694],
    [0xe49b69c1, 0x9ef14ad2], [0xefbe4786, 0x384f25e3],
    [0x0fc19dc6, 0x8b8cd5b5], [0x240ca1cc, 0x77ac9c65],
    [0x2de92c6f, 0x592b0275], [0x4a7484aa, 0x6ea6e483],
    [0x5cb0a9dc, 0xbd41fbd4], [0x76f988da, 0x831153b5],
    [0x983e5152, 0xee66dfab], [0xa831c66d, 0x2db43210],
    [0xb00327c8, 0x98fb213f], [0xbf597fc7, 0xbeef0ee4],
    [0xc6e00bf3, 0x3da88fc2], [0xd5a79147, 0x930aa725],
    [0x06ca6351, 0xe003826f], [0x14292967, 0x0a0e6e70],
    [0x27b70a85, 0x46d22ffc], [0x2e1b2138, 0x5c26c926],
    [0x4d2c6dfc, 0x5ac42aed], [0x53380d13, 0x9d95b3df],
    [0x650a7354, 0x8baf63de], [0x766a0abb, 0x3c77b2a8],
    [0x81c2c92e, 0x47edaee6], [0x92722c85, 0x1482353b],
    [0xa2bfe8a1, 0x4cf10364], [0xa81a664b, 0xbc423001],
    [0xc24b8b70, 0xd0f89791], [0xc76c51a3, 0x0654be30],
    [0xd192e819, 0xd6ef5218], [0xd6990624, 0x5565a910],
    [0xf40e3585, 0x5771202a], [0x106aa070, 0x32bbd1b8],
    [0x19a4c116, 0xb8d2d0c8], [0x1e376c08, 0x5141ab53],
    [0x2748774c, 0xdf8eeb99], [0x34b0bcb5, 0xe19b48a8],
    [0x391c0cb3, 0xc5c95a63], [0x4ed8aa4a, 0xe3418acb],
    [0x5b9cca4f, 0x7763e373], [0x682e6ff3, 0xd6b2b8a3],
    [0x748f82ee, 0x5defb2fc], [0x78a5636f, 0x43172f60],
    [0x84c87814, 0xa1f0ab72], [0x8cc70208, 0x1a6439ec],
    [0x90befffa, 0x23631e28], [0xa4506ceb, 0xde82bde9],
    [0xbef9a3f7, 0xb2c67915], [0xc67178f2, 0xe372532b],
    [0xca273ece, 0xea26619c], [0xd186b8c7, 0x21c0c207],
    [0xeada7dd6, 0xcde0eb1e], [0xf57d4f7f, 0xee6ed178],
    [0x06f067aa, 0x72176fba], [0x0a637dc5, 0xa2c898a6],
    [0x113f9804, 0xbef90dae], [0x1b710b35, 0x131c471b],
    [0x28db77f5, 0x23047d84], [0x32caab7b, 0x40c72493],
    [0x3c9ebe0a, 0x15c9bebc], [0x431d67c4, 0x9c100d4c],
    [0x4cc5d4be, 0xcb3e42b6], [0x597f299c, 0xfc657e2a],
    [0x5fcb6fab, 0x3ad6faec], [0x6c44198c, 0x4a475817]
  ];

  const H = [
    [0x6a09e667, 0xf3bcc908], [0xbb67ae85, 0x84caa73b],
    [0x3c6ef372, 0xfe94f82b], [0xa54ff53a, 0x5f1d36f1],
    [0x510e527f, 0xade682d1], [0x9b05688c, 0x2b3e6c1f],
    [0x1f83d9ab, 0xfb41bd6b], [0x5be0cd19, 0x137e2179]
  ];

  const paddedLength = (((bytes.length + 17 + 127) >> 7) << 7);
  const data = new Uint8Array(paddedLength);
  data.set(bytes);
  data[bytes.length] = 0x80;

  const bitLengthLo = (bytes.length * 8) >>> 0;
  const bitLengthHi = Math.floor(bytes.length / 0x20000000) >>> 0;
  data[data.length - 8] = (bitLengthHi >>> 24) & 0xff;
  data[data.length - 7] = (bitLengthHi >>> 16) & 0xff;
  data[data.length - 6] = (bitLengthHi >>> 8) & 0xff;
  data[data.length - 5] = bitLengthHi & 0xff;
  data[data.length - 4] = (bitLengthLo >>> 24) & 0xff;
  data[data.length - 3] = (bitLengthLo >>> 16) & 0xff;
  data[data.length - 2] = (bitLengthLo >>> 8) & 0xff;
  data[data.length - 1] = bitLengthLo & 0xff;

  const w = Array.from({ length: 80 }, () => [0, 0]);

  for (let offset = 0; offset < data.length; offset += 128) {
    for (let i = 0; i < 16; i += 1) {
      const j = offset + i * 8;
      w[i][0] = (
        (data[j] << 24) |
        (data[j + 1] << 16) |
        (data[j + 2] << 8) |
        data[j + 3]
      ) >>> 0;
      w[i][1] = (
        (data[j + 4] << 24) |
        (data[j + 5] << 16) |
        (data[j + 6] << 8) |
        data[j + 7]
      ) >>> 0;
    }

    for (let i = 16; i < 80; i += 1) {
      const [r1Hi, r1Lo] = rotr64(w[i - 15][0], w[i - 15][1], 1);
      const [r8Hi, r8Lo] = rotr64(w[i - 15][0], w[i - 15][1], 8);
      const [s7Hi, s7Lo] = shr64(w[i - 15][0], w[i - 15][1], 7);
      const [sigma0Hi, sigma0Lo] = xor64(r1Hi, r1Lo, r8Hi, r8Lo);
      const [sigma0bHi, sigma0bLo] = xor64(sigma0Hi, sigma0Lo, s7Hi, s7Lo);

      const [r19Hi, r19Lo] = rotr64(w[i - 2][0], w[i - 2][1], 19);
      const [r61Hi, r61Lo] = rotr64(w[i - 2][0], w[i - 2][1], 61);
      const [s6Hi, s6Lo] = shr64(w[i - 2][0], w[i - 2][1], 6);
      const [sigma1Hi, sigma1Lo] = xor64(r19Hi, r19Lo, r61Hi, r61Lo);
      const [sigma1bHi, sigma1bLo] = xor64(sigma1Hi, sigma1Lo, s6Hi, s6Lo);

      w[i] = add64(w[i - 16], [sigma0bHi, sigma0bLo], w[i - 7], [sigma1bHi, sigma1bLo]);
    }

    let [aHi, aLo] = H[0];
    let [bHi, bLo] = H[1];
    let [cHi, cLo] = H[2];
    let [dHi, dLo] = H[3];
    let [eHi, eLo] = H[4];
    let [fHi, fLo] = H[5];
    let [gHi, gLo] = H[6];
    let [hHi, hLo] = H[7];

    for (let i = 0; i < 80; i += 1) {
      const [e14Hi, e14Lo] = rotr64(eHi, eLo, 14);
      const [e18Hi, e18Lo] = rotr64(eHi, eLo, 18);
      const [e41Hi, e41Lo] = rotr64(eHi, eLo, 41);
      const [sum1Hi, sum1Lo] = xor64(e14Hi, e14Lo, e18Hi, e18Lo);
      const [bigSigma1Hi, bigSigma1Lo] = xor64(sum1Hi, sum1Lo, e41Hi, e41Lo);

      const chHi = ((eHi & fHi) ^ (~eHi & gHi)) >>> 0;
      const chLo = ((eLo & fLo) ^ (~eLo & gLo)) >>> 0;

      const temp1 = add64(
        [hHi, hLo],
        [bigSigma1Hi, bigSigma1Lo],
        [chHi, chLo],
        K[i],
        w[i]
      );

      const [a28Hi, a28Lo] = rotr64(aHi, aLo, 28);
      const [a34Hi, a34Lo] = rotr64(aHi, aLo, 34);
      const [a39Hi, a39Lo] = rotr64(aHi, aLo, 39);
      const [sum0Hi, sum0Lo] = xor64(a28Hi, a28Lo, a34Hi, a34Lo);
      const [bigSigma0Hi, bigSigma0Lo] = xor64(sum0Hi, sum0Lo, a39Hi, a39Lo);

      const majHi = ((aHi & bHi) ^ (aHi & cHi) ^ (bHi & cHi)) >>> 0;
      const majLo = ((aLo & bLo) ^ (aLo & cLo) ^ (bLo & cLo)) >>> 0;
      const temp2 = add64([bigSigma0Hi, bigSigma0Lo], [majHi, majLo]);

      [hHi, hLo] = [gHi, gLo];
      [gHi, gLo] = [fHi, fLo];
      [fHi, fLo] = [eHi, eLo];
      [eHi, eLo] = add64([dHi, dLo], temp1);
      [dHi, dLo] = [cHi, cLo];
      [cHi, cLo] = [bHi, bLo];
      [bHi, bLo] = [aHi, aLo];
      [aHi, aLo] = add64(temp1, temp2);
    }

    H[0] = add64(H[0], [aHi, aLo]);
    H[1] = add64(H[1], [bHi, bLo]);
    H[2] = add64(H[2], [cHi, cLo]);
    H[3] = add64(H[3], [dHi, dLo]);
    H[4] = add64(H[4], [eHi, eLo]);
    H[5] = add64(H[5], [fHi, fLo]);
    H[6] = add64(H[6], [gHi, gLo]);
    H[7] = add64(H[7], [hHi, hLo]);
  }

  const out = new Uint8Array(64);
  for (let i = 0; i < H.length; i += 1) {
    const [hi, lo] = H[i];
    out[i * 8] = (hi >>> 24) & 0xff;
    out[i * 8 + 1] = (hi >>> 16) & 0xff;
    out[i * 8 + 2] = (hi >>> 8) & 0xff;
    out[i * 8 + 3] = hi & 0xff;
    out[i * 8 + 4] = (lo >>> 24) & 0xff;
    out[i * 8 + 5] = (lo >>> 16) & 0xff;
    out[i * 8 + 6] = (lo >>> 8) & 0xff;
    out[i * 8 + 7] = lo & 0xff;
  }
  return out;
}

class AccessGateWASM {
  constructor(instance) {
    this.instance = instance;
    this.exports = instance.exports;
    this.memory = this.exports.memory;
    this.mem8 = new Uint8Array(this.memory.buffer);

    this.malloc = this.resolveExport("malloc", "_malloc");
    this.free = this.resolveExport("free", "_free");

    this.generate2auth = this.resolveExport("ag_generate_2auth", "_ag_generate_2auth");
    this.deterministicId = this.resolveExport("ag_deterministic_id", "_ag_deterministic_id");
    this.isValidId = this.resolveExport("ag_is_valid_id", "_ag_is_valid_id");
  }

  resolveExport(...names) {
    for (const name of names) {
      if (typeof this.exports[name] === "function") {
        return this.exports[name];
      }
    }

    throw new Error(`Missing WASM export. Tried: ${names.join(", ")}`);
  }

  static async init() {
    let wasmInstance;

    const importObject = {
      env: {
        sha256(ptr, len, outPtr) {
          const mem = new Uint8Array(wasmInstance.exports.memory.buffer, ptr, len);
          const digest = sha256(mem);
          new Uint8Array(wasmInstance.exports.memory.buffer, outPtr, 32).set(digest);
        },
        sha512(ptr, len, outPtr) {
          const mem = new Uint8Array(wasmInstance.exports.memory.buffer, ptr, len);
          const digest = sha512(mem);
          new Uint8Array(wasmInstance.exports.memory.buffer, outPtr, 64).set(digest);
        }
      }
    };

    let instance;
    try {
      ({ instance } = await WebAssembly.instantiateStreaming(
        fetch("index.wasm"),
        importObject
      ));
    } catch (_err) {
      const response = await fetch("index.wasm");
      const bytes = await response.arrayBuffer();
      ({ instance } = await WebAssembly.instantiate(bytes, importObject));
    }

    wasmInstance = instance;
    return new AccessGateWASM(instance);
  }

  refreshMemoryView() {
    if (this.mem8.buffer !== this.memory.buffer) {
      this.mem8 = new Uint8Array(this.memory.buffer);
    }
  }

  alloc(size) {
    if (size === 0) return 0;

    const ptr = this.malloc(size);
    if (!ptr) throw new Error("malloc failed");
    return ptr;
  }

  freePtr(ptr) {
    if (ptr) this.free(ptr);
  }

  write(ptr, bytes) {
    if (!bytes.length) return;
    this.refreshMemoryView();
    this.mem8.set(bytes, ptr);
  }

  read(ptr, len) {
    this.refreshMemoryView();
    return this.mem8.slice(ptr, ptr + len);
  }

  encodeString(value) {
    return new TextEncoder().encode(value);
  }

  allocString(bytes) {
    if (bytes.length === 0) {
      // The C ABI checks pointers before lengths, so empty optional strings
      // still need a valid non-null pointer.
      return { ptr: this.alloc(1), len: 0 };
    }

    const ptr = this.alloc(bytes.length);
    this.write(ptr, bytes);
    return { ptr, len: bytes.length };
  }

  generate2authFromId(idStr, length) {
    const idBytes = this.encodeString(idStr);
    const { ptr: idPtr, len: idLen } = this.allocString(idBytes);
    const outBufLen = length > 0 ? length : 2048;
    const outPtr = this.alloc(outBufLen);

    try {
      const written = this.generate2auth(idPtr, idLen, length, outPtr, outBufLen);
      if (written <= 0) {
        throw new Error("ag_generate_2auth failed");
      }
      return this.read(outPtr, written);
    } finally {
      this.freePtr(idPtr);
      this.freePtr(outPtr);
    }
  }

  deterministicIdFromBrowser(salt, ua, lang, platform, hw, touch, tz) {
    const saltArg = this.allocString(this.encodeString(salt));
    const uaArg = this.allocString(this.encodeString(ua));
    const langArg = this.allocString(this.encodeString(lang));
    const platformArg = this.allocString(this.encodeString(platform));
    const hwArg = this.allocString(this.encodeString(hw));
    const touchArg = this.allocString(this.encodeString(touch));
    const tzArg = this.allocString(this.encodeString(tz));
    const outBufLen = 128;
    const outPtr = this.alloc(outBufLen);

    try {
      const written = this.deterministicId(
        saltArg.ptr, saltArg.len,
        uaArg.ptr, uaArg.len,
        langArg.ptr, langArg.len,
        platformArg.ptr, platformArg.len,
        hwArg.ptr, hwArg.len,
        touchArg.ptr, touchArg.len,
        tzArg.ptr, tzArg.len,
        outPtr, outBufLen
      );

      if (written <= 0) {
        throw new Error("ag_deterministic_id failed");
      }

      return new TextDecoder().decode(this.read(outPtr, written));
    } finally {
      this.freePtr(saltArg.ptr);
      this.freePtr(uaArg.ptr);
      this.freePtr(langArg.ptr);
      this.freePtr(platformArg.ptr);
      this.freePtr(hwArg.ptr);
      this.freePtr(touchArg.ptr);
      this.freePtr(tzArg.ptr);
      this.freePtr(outPtr);
    }
  }
}

function getBrowserSignals() {
  return {
    ua: navigator.userAgent || "",
    lang: navigator.language || "",
    platform: navigator.platform || "",
    hw: String(navigator.hardwareConcurrency ?? ""),
    touch: String(navigator.maxTouchPoints ?? ""),
    tz: String(new Date().getTimezoneOffset())
  };
}

(async () => {
  const wasm = await AccessGateWASM.init();

  const inputEl = document.getElementById("input");
  const saltEl = document.getElementById("salt");
  const outLenEl = document.getElementById("outLen");
  const deriveBtn = document.getElementById("deriveBtn");
  const fallbackBtn = document.getElementById("fallbackBtn");
  const outputEl = document.getElementById("output");

  deriveBtn.addEventListener("click", () => {
    const id = inputEl.value;
    const length = parseInt(outLenEl.value, 10) || 32;
    const derived = wasm.generate2authFromId(id, length);

    outputEl.textContent =
      "2auth bytes (hex):\n" +
      bytesToHex(derived) +
      "\n\n2auth bytes (base64):\n" +
      bytesToBase64(derived);
  });

  fallbackBtn.addEventListener("click", () => {
    const salt = saltEl.value;
    const { ua, lang, platform, hw, touch, tz } = getBrowserSignals();
    const fallbackId = wasm.deterministicIdFromBrowser(
      salt,
      ua,
      lang,
      platform,
      hw,
      touch,
      tz
    );

    outputEl.textContent =
      "Deterministic fallback ID:\n" +
      fallbackId +
      "\n\nSource signals:\n" +
      JSON.stringify({ ua, lang, platform, hw, touch, tz }, null, 2);
  });
})();
