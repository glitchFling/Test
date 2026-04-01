// AccessGateWASM.js
//
// Loader for Emscripten-built index.wasm (PATH A).
// Expects exports:
//   _malloc, _free
//   _ag_generate_2auth
//   _ag_deterministic_id
//   _ag_is_valid_id

class AccessGateWASM {
  constructor(instance) {
    this.instance = instance;
    this.exports = instance.exports;
    this.memory = this.exports.memory;
    this.mem8 = new Uint8Array(this.memory.buffer);

    this.malloc = this.exports._malloc;
    this.free = this.exports._free;

    this.generate2auth = this.exports._ag_generate_2auth;
    this.deterministicId = this.exports._ag_deterministic_id;
    this.isValidId = this.exports._ag_is_valid_id;
  }

  static async init() {
    let wasmInstance;

    const importObject = {
      env: {
        sha256(ptr, len, outPtr) {
          const mem = new Uint8Array(
            wasmInstance.exports.memory.buffer,
            ptr,
            len
          );
          const digest = sha256(mem); // must return Uint8Array(32)
          new Uint8Array(
            wasmInstance.exports.memory.buffer,
            outPtr,
            32
          ).set(digest);
        },
        sha512(ptr, len, outPtr) {
          const mem = new Uint8Array(
            wasmInstance.exports.memory.buffer,
            ptr,
            len
          );
          const digest = sha512(mem); // must return Uint8Array(64)
          new Uint8Array(
            wasmInstance.exports.memory.buffer,
            outPtr,
            64
          ).set(digest);
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
    const ptr = this.malloc(size);
    if (!ptr) throw new Error("malloc failed");
    return ptr;
  }

  freePtr(ptr) {
    this.free(ptr);
  }

  write(ptr, bytes) {
    this.refreshMemoryView();
    this.mem8.set(bytes, ptr);
  }

  read(ptr, len) {
    this.refreshMemoryView();
    return this.mem8.slice(ptr, ptr + len);
  }

  // Wrapper: generate 2auth from an ID string
  generate2authFromId(idStr, length) {
    const enc = new TextEncoder();
    const idBytes = enc.encode(idStr);

    const idPtr = this.alloc(idBytes.length);
    this.write(idPtr, idBytes);

    const outBufLen = length > 0 ? length : 2048;
    const outPtr = this.alloc(outBufLen);

    const written = this.generate2auth(
      idPtr,
      idBytes.length,
      length,
      outPtr,
      outBufLen
    );

    if (written <= 0) {
      this.freePtr(idPtr);
      this.freePtr(outPtr);
      throw new Error("ag_generate_2auth failed");
    }

    const out = this.read(outPtr, written);

    this.freePtr(idPtr);
    this.freePtr(outPtr);

    return out;
  }

  // Wrapper: deterministic fallback ID
  deterministicIdFromBrowser(
    salt,
    ua,
    lang,
    platform,
    hw,
    touch,
    tz
  ) {
    const enc = new TextEncoder();

    const saltBytes = enc.encode(salt);
    const uaBytes = enc.encode(ua);
    const langBytes = enc.encode(lang);
    const platBytes = enc.encode(platform);
    const hwBytes = enc.encode(hw);
    const touchBytes = enc.encode(touch);
    const tzBytes = enc.encode(tz);

    const saltPtr = this.alloc(saltBytes.length);
    const uaPtr = this.alloc(uaBytes.length);
    const langPtr = this.alloc(langBytes.length);
    const platPtr = this.alloc(platBytes.length);
    const hwPtr = this.alloc(hwBytes.length);
    const touchPtr = this.alloc(touchBytes.length);
    const tzPtr = this.alloc(tzBytes.length);

    this.write(saltPtr, saltBytes);
    this.write(uaPtr, uaBytes);
    this.write(langPtr, langBytes);
    this.write(platPtr, platBytes);
    this.write(hwPtr, hwBytes);
    this.write(touchPtr, touchBytes);
    this.write(tzPtr, tzBytes);

    const outBufLen = 128;
    const outPtr = this.alloc(outBufLen);

    const written = this.deterministicId(
      saltPtr,
      saltBytes.length,
      uaPtr,
      uaBytes.length,
      langPtr,
      langBytes.length,
      platPtr,
      platBytes.length,
      hwPtr,
      hwBytes.length,
      touchPtr,
      touchBytes.length,
      tzPtr,
      tzBytes.length,
      outPtr,
      outBufLen
    );

    if (written <= 0) {
      this.freePtr(saltPtr);
      this.freePtr(uaPtr);
      this.freePtr(langPtr);
      this.freePtr(platPtr);
      this.freePtr(hwPtr);
      this.freePtr(touchPtr);
      this.freePtr(tzPtr);
      this.freePtr(outPtr);
      throw new Error("ag_deterministic_id failed");
    }

    const outBytes = this.read(outPtr, written);

    this.freePtr(saltPtr);
    this.freePtr(uaPtr);
    this.freePtr(langPtr);
    this.freePtr(platPtr);
    this.freePtr(hwPtr);
    this.freePtr(touchPtr);
    this.freePtr(tzPtr);
    this.freePtr(outPtr);

    const dec = new TextDecoder();
    return dec.decode(outBytes);
  }
}

// Example UI wiring (adapt as needed)
(async () => {
  const wasm = await AccessGateWASM.init();

  const inputEl = document.getElementById("input");
  const outLenEl = document.getElementById("outLen");
  const btn = document.getElementById("deriveBtn");
  const out = document.getElementById("output");

  btn.addEventListener("click", () => {
    const id = inputEl.value;
    const length = parseInt(outLenEl.value, 10) || 32;

    const derived = wasm.generate2authFromId(id, length);

    out.textContent =
      "Hex:\n" +
      Array.from(derived)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("") +
      "\n\nBase64:\n" +
      btoa(String.fromCharCode(...derived));
  });
})();
