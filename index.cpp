// AccessGate.cpp
//
// Core deterministic logic extracted from AccessGate.js,
// written as a pure C++/WASM module with no direct browser dependencies.
//
// JS is responsible for:
//   - localStorage
//   - fetch / network
//   - navigator.*
//   - redirects
//   - wiring AuthWasm / OTPWasm
//
// This module provides:
//   - ID validation
//   - deterministic fallback ID
//   - 2auth key generation
//   - base64url encoding
//
// Compile with Emscripten and import sha256/sha512 from JS.

#include <string>
#include <vector>
#include <stdint.h>

// ---------- WASM crypto imports (provided by JS) ----------
extern "C" {
    // SHA-256: writes 32 bytes into out32
    __attribute__((import_module("env"), import_name("sha256")))
    void ag_sha256(const uint8_t* data, uint32_t len, uint8_t* out32);

    // SHA-512: writes 64 bytes into out64
    __attribute__((import_module("env"), import_name("sha512")))
    void ag_sha512(const uint8_t* data, uint32_t len, uint8_t* out64);
}

// ---------- Internal helpers ----------

static inline bool isValidId(const std::string& s) {
    const size_t n = s.size();
    return n >= 8 && n <= 128;
}

static inline std::string base64Url(const uint8_t* data, size_t len) {
    static const char* tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    size_t i = 0;
    while (i < len) {
        uint32_t a = i < len ? data[i++] : 0;
        uint32_t b = i < len ? data[i++] : 0;
        uint32_t c = i < len ? data[i++] : 0;

        uint32_t triple = (a << 16) | (b << 8) | c;

        out.push_back(tbl[(triple >> 18) & 63]);
        out.push_back(tbl[(triple >> 12) & 63]);
        out.push_back(i - 1 < len ? tbl[(triple >> 6) & 63] : '=');
        out.push_back(i < len ? tbl[triple & 63] : '=');
    }

    // strip '=' padding
    while (!out.empty() && out.back() == '=') out.pop_back();
    return out;
}

static inline std::string sha256Hex(const std::string& text) {
    uint8_t out[32];
    ag_sha256(reinterpret_cast<const uint8_t*>(text.data()),
              static_cast<uint32_t>(text.size()),
              out);

    static const char* hex = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (int i = 0; i < 32; i++) {
        s.push_back(hex[out[i] >> 4]);
        s.push_back(hex[out[i] & 0xF]);
    }
    return s;
}

// ---------- Deterministic fallback ID ----------
//
// Mirrors JS seed:
//   salt | userAgent | language | platform | hwConcurrency | maxTouchPoints | timezoneOffset
//
// JS must pass those strings in.

static inline std::string deterministicFallbackIdInternal(
    const std::string& salt,
    const std::string& userAgent,
    const std::string& language,
    const std::string& platform,
    const std::string& hwConcurrency,
    const std::string& maxTouchPoints,
    const std::string& timezoneOffset
) {
    std::string seed =
        salt + "|" +
        userAgent + "|" +
        language + "|" +
        platform + "|" +
        hwConcurrency + "|" +
        maxTouchPoints + "|" +
        timezoneOffset;

    std::string digest = sha256Hex(seed);
    // JS: "det_" + digest.slice(0, 48)
    return std::string("det_") + digest.substr(0, 48);
}

// ---------- 2auth generator ----------
//
// JS logic:
//   while (parts.join("").length < target) {
//     material = `${id}|${counter}`;
//     hash = SHA-512(material);
//     parts.push(base64Url(hash));
//   }
//   return joined.slice(0, target);

static inline std::string generate2authInternal(const std::string& id, int length) {
    if (!isValidId(id)) {
        // JS throws; here we return empty and let JS decide what to do.
        return std::string();
    }

    const int target = (length > 0 ? length : 2048);

    std::string out;
    out.reserve(target);

    int counter = 0;
    uint8_t buf[64];

    while (static_cast<int>(out.size()) < target) {
        std::string material = id + "|" + std::to_string(counter);

        ag_sha512(reinterpret_cast<const uint8_t*>(material.data()),
                  static_cast<uint32_t>(material.size()),
                  buf);

        out += base64Url(buf, 64);
        counter++;
    }

    out.resize(target);
    return out;
}

// ---------- C ABI exports for JS glue ----------
//
// These are simple, stable exports you can bind to from JS.
// All strings are passed as (ptr, len) and returned via a
// linear-memory buffer pattern (caller owns memory).

extern "C" {

// Simple validity check: returns 1 if valid, 0 otherwise.
int ag_is_valid_id(const char* ptr, int len) {
    if (!ptr || len <= 0) return 0;
    std::string s(ptr, ptr + len);
    return isValidId(s) ? 1 : 0;
}

// Generate 2auth key. Returns length of written bytes into outBuf.
// If id invalid or error, returns 0.
int ag_generate_2auth(const char* idPtr, int idLen, int length,
                      char* outBuf, int outBufLen) {
    if (!idPtr || idLen <= 0 || !outBuf || outBufLen <= 0) return 0;

    std::string id(idPtr, idPtr + idLen);
    std::string key = generate2authInternal(id, length);

    if (key.empty()) return 0;
    if (static_cast<int>(key.size()) > outBufLen) return 0;

    for (size_t i = 0; i < key.size(); ++i) {
        outBuf[i] = key[i];
    }
    return static_cast<int>(key.size());
}

// Deterministic fallback ID. Returns length of written bytes into outBuf.
// JS passes browser-derived strings.
int ag_deterministic_id(
    const char* saltPtr, int saltLen,
    const char* uaPtr, int uaLen,
    const char* langPtr, int langLen,
    const char* platformPtr, int platformLen,
    const char* hwPtr, int hwLen,
    const char* touchPtr, int touchLen,
    const char* tzPtr, int tzLen,
    char* outBuf, int outBufLen
) {
    if (!saltPtr || saltLen < 0 ||
        !uaPtr || uaLen < 0 ||
        !langPtr || langLen < 0 ||
        !platformPtr || platformLen < 0 ||
        !hwPtr || hwLen < 0 ||
        !touchPtr || touchLen < 0 ||
        !tzPtr || tzLen < 0 ||
        !outBuf || outBufLen <= 0) {
        return 0;
    }

    std::string salt(saltPtr, saltPtr + saltLen);
    std::string ua(uaPtr, uaPtr + uaLen);
    std::string lang(langPtr, langPtr + langLen);
    std::string platform(platformPtr, platformPtr + platformLen);
    std::string hw(hwPtr, hwPtr + hwLen);
    std::string touch(touchPtr, touchPtr + touchLen);
    std::string tz(tzPtr, tzPtr + tzLen);

    if (salt.empty()) {
        salt = "my-radio-io.v1";
    }

    std::string id = deterministicFallbackIdInternal(
        salt, ua, lang, platform, hw, touch, tz
    );

    if (static_cast<int>(id.size()) > outBufLen) return 0;

    for (size_t i = 0; i < id.size(); ++i) {
        outBuf[i] = id[i];
    }
    return static_cast<int>(id.size());
}

} // extern "C"
