// AccessGate.cpp — v4 (password-KDF aware, stronger memory-hard core, same C ABI)
//
// Hardened C++/WASM core for AccessGate in Emscripten mode.
// Exports (C ABI):
//   int ag_is_valid_id(const char* ptr, int len);
//   int ag_generate_2auth(const char* idPtr, int idLen, int length,
//                         char* outBuf, int outBufLen);
//   int ag_deterministic_id(..., char* outBuf, int outBufLen);
//
// Emscripten will export them as:
//   _ag_is_valid_id
//   _ag_generate_2auth
//   _ag_deterministic_id
//
// v4 assumptions:
// - Weak passwords (if any) are already passed through a memory-hard KDF
//   (e.g., Argon2id) OUTSIDE this module.
// - This core treats its inputs as high-entropy secrets and adds its own
//   stronger memory-hard mixing + domain separation.
// - C ABI is unchanged from v1/v2/v3.

#include <string>
#include <stdint.h>
#include <limits>
#include <vector>
#include <string.h>

// ---------- WASM crypto imports (provided by JS) ----------
extern "C" {
    __attribute__((import_module("env"), import_name("sha256")))
    void ag_sha256(const uint8_t* data, uint32_t len, uint8_t* out32);

    __attribute__((import_module("env"), import_name("sha512")))
    void ag_sha512(const uint8_t* data, uint32_t len, uint8_t* out64);
}

// ---------- Limits & constants ----------

static constexpr int MIN_ID_LEN        = 8;
static constexpr int MAX_ID_LEN        = 128;

static constexpr int MAX_INPUT_LEN     = 4096;   // per string input from JS
static constexpr int MAX_2AUTH_LEN     = 4096;   // hard cap for 2auth output
static constexpr int DEFAULT_2AUTH_LEN = 2048;

// v4 tags (v1/v2/v3 kept only for reference)
// static constexpr const char* TAG_2AUTH_V1    = "AccessGate-2auth-v1";
// static constexpr const char* TAG_FALLBACK_V1 = "AccessGate-fallback-id-v1";
// static constexpr const char* TAG_2AUTH_V2    = "AccessGate-2auth-v2";
// static constexpr const char* TAG_FALLBACK_V2 = "AccessGate-fallback-id-v2";
// static constexpr const char* TAG_2AUTH_V3    = "AccessGate-2auth-v3";
// static constexpr const char* TAG_FALLBACK_V3 = "AccessGate-fallback-id-v3";

static constexpr const char* TAG_2AUTH_V4    = "AccessGate-2auth-v4";
static constexpr const char* TAG_FALLBACK_V4 = "AccessGate-fallback-id-v4";

// v4: encode that upstream password KDF is in play (informational, domain sep)
static constexpr const char* PLAN_PWD_KDF    = "AG-PWD-v1:mem64m-time2-par1";

// Stronger memory-hard parameters (still WASM-friendly)
static constexpr size_t MH_2AUTH_BLOCKS   = 8192; // 8192 * 64 = 512 KiB
static constexpr size_t MH_2AUTH_BLKSIZE  = 64;

static constexpr size_t MH_ID_BLOCKS      = 4096; // 4096 * 32 = 128 KiB
static constexpr size_t MH_ID_BLKSIZE     = 32;

// ---------- Internal helpers ----------

static inline bool isValidId(const std::string& s) {
    const size_t n = s.size();
    return n >= MIN_ID_LEN && n <= MAX_ID_LEN;
}

static inline std::string base64Url(const uint8_t* data, size_t len) {
    static const char* tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    size_t i = 0;
    while (i < len) {
        const size_t rem = len - i;
        uint32_t a = data[i++];
        uint32_t b = rem > 1 ? data[i++] : 0;
        uint32_t c = rem > 2 ? data[i++] : 0;

        uint32_t triple = (a << 16) | (b << 8) | c;

        out.push_back(tbl[(triple >> 18) & 63]);
        out.push_back(tbl[(triple >> 12) & 63]);
        out.push_back(rem > 1 ? tbl[(triple >> 6) & 63] : '=');
        out.push_back(rem > 2 ? tbl[triple & 63] : '=');
    }

    while (!out.empty() && out.back() == '=') out.pop_back();
    return out;
}

static inline std::string sha256Hex(const uint8_t* data, uint32_t len) {
    uint8_t out[32];
    ag_sha256(data, len, out);

    static const char* hex = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (int i = 0; i < 32; i++) {
        s.push_back(hex[out[i] >> 4]);
        s.push_back(hex[out[i] & 0xF]);
    }
    return s;
}

static inline std::string sha256Hex(const std::string& text) {
    return sha256Hex(reinterpret_cast<const uint8_t*>(text.data()),
                     static_cast<uint32_t>(text.size()));
}

static inline void appendLenPrefixed(std::string& dst,
                                     const char* tag,
                                     const std::string& s) {
    dst.append(tag);
    dst.push_back(':');
    dst.append(std::to_string(s.size()));
    dst.push_back(':');
    dst.append(s);
}

// ---------- Small mixing helpers ----------

static inline uint32_t rotl32(uint32_t x, int r) {
    return (x << r) | (x >> (32 - r));
}

static inline uint8_t rotl8(uint8_t x, int r) {
    return static_cast<uint8_t>((x << r) | (x >> (8 - r)));
}

// Derive a data-dependent reference index from a block
static inline size_t derive_index(const uint8_t* block, size_t i, size_t max) {
    // Use first 16 bytes to build a 32-bit state
    uint32_t s = 0x9E3779B9u ^ static_cast<uint32_t>(i);
    for (int k = 0; k < 16; ++k) {
        s ^= static_cast<uint32_t>(block[k]) << ((k & 3) * 8);
        s = rotl32(s, 7) * 0x85EBCA6Bu;
    }
    return static_cast<size_t>(s % max);
}

// ---------- Memory-hard cores (v4, stronger) ----------

// 64-byte memory-hard expansion (for 2auth blocks)
static inline void mh_expand_64(const uint8_t* seed64, uint8_t* out64) {
    // Buffer: MH_2AUTH_BLOCKS * 64 bytes
    std::vector<uint8_t> buf(MH_2AUTH_BLOCKS * MH_2AUTH_BLKSIZE);

    // Block 0 = seed
    memcpy(&buf[0], seed64, MH_2AUTH_BLKSIZE);

    for (size_t i = 1; i < MH_2AUTH_BLOCKS; ++i) {
        uint8_t* prev = &buf[(i - 1) * MH_2AUTH_BLKSIZE];

        // Stronger data-dependent index
        size_t refIndex = derive_index(prev, i, i);
        uint8_t* ref = &buf[refIndex * MH_2AUTH_BLKSIZE];

        uint8_t tmp[MH_2AUTH_BLKSIZE];
        for (size_t j = 0; j < MH_2AUTH_BLKSIZE; ++j) {
            // Cross-mix prev, ref, and position
            uint8_t x = static_cast<uint8_t>(prev[j] ^ ref[j]);
            x = static_cast<uint8_t>(x + static_cast<uint8_t>(j * 131));
            tmp[j] = rotl8(x, 3);
        }

        ag_sha512(tmp, MH_2AUTH_BLKSIZE, &buf[i * MH_2AUTH_BLKSIZE]);
    }

    // Final: hash the entire buffer, not just last block
    ag_sha512(buf.data(),
              static_cast<uint32_t>(buf.size()),
              out64);
}

// 32-byte memory-hard expansion (for deterministic ID)
static inline void mh_expand_32(const uint8_t* seed32, uint8_t* out32) {
    std::vector<uint8_t> buf(MH_ID_BLOCKS * MH_ID_BLKSIZE);

    memcpy(&buf[0], seed32, MH_ID_BLKSIZE);

    for (size_t i = 1; i < MH_ID_BLOCKS; ++i) {
        uint8_t* prev = &buf[(i - 1) * MH_ID_BLKSIZE];

        size_t refIndex = derive_index(prev, i, i);
        uint8_t* ref = &buf[refIndex * MH_ID_BLKSIZE];

        uint8_t tmp[MH_ID_BLKSIZE];
        for (size_t j = 0; j < MH_ID_BLKSIZE; ++j) {
            uint8_t x = static_cast<uint8_t>(prev[j] ^ ref[j]);
            x = static_cast<uint8_t>(x + static_cast<uint8_t>(j * 197));
            tmp[j] = rotl8(x, 5);
        }

        ag_sha256(tmp, MH_ID_BLKSIZE, &buf[i * MH_ID_BLKSIZE]);
    }

    ag_sha256(buf.data(),
              static_cast<uint32_t>(buf.size()),
              out32);
}

// ---------- Deterministic fallback ID (v4, memory-hard, KDF-aware) ----------

static inline std::string deterministicFallbackIdInternal(
    const std::string& salt,
    const std::string& userAgent,
    const std::string& language,
    const std::string& platform,
    const std::string& hwConcurrency,
    const std::string& maxTouchPoints,
    const std::string& timezoneOffset
) {
    std::string seed;
    seed.reserve(256);

    // v4 tag + plan marker (binds this to the password-KDF-aware profile)
    seed.append(TAG_FALLBACK_V4);
    seed.push_back('|');
    seed.append("plan:");
    seed.append(PLAN_PWD_KDF);
    seed.push_back('|');

    appendLenPrefixed(seed, "salt",   salt);
    appendLenPrefixed(seed, "ua",     userAgent);
    appendLenPrefixed(seed, "lang",   language);
    appendLenPrefixed(seed, "plat",   platform);
    appendLenPrefixed(seed, "hw",     hwConcurrency);
    appendLenPrefixed(seed, "touch",  maxTouchPoints);
    appendLenPrefixed(seed, "tz",     timezoneOffset);

    // Initial 32-byte seed
    uint8_t seed32[32];
    ag_sha256(reinterpret_cast<const uint8_t*>(seed.data()),
              static_cast<uint32_t>(seed.size()),
              seed32);

    // Memory-hard expansion
    uint8_t final32[32];
    mh_expand_32(seed32, final32);

    // Hex-encode and prefix
    static const char* hex = "0123456789abcdef";
    std::string digest;
    digest.reserve(64);
    for (int i = 0; i < 32; ++i) {
        digest.push_back(hex[final32[i] >> 4]);
        digest.push_back(hex[final32[i] & 0xF]);
    }

    // Keep same external shape: "det_" + 48 hex chars
    return std::string("det_") + digest.substr(0, 48);
}

// ---------- 2auth generator (v4, memory-hard, KDF-aware) ----------

static inline std::string generate2authInternal(const std::string& id,
                                                int requestedLength) {
    if (!isValidId(id)) {
        return std::string();
    }

    int targetInt = (requestedLength > 0 ? requestedLength : DEFAULT_2AUTH_LEN);
    if (targetInt > MAX_2AUTH_LEN) {
        targetInt = MAX_2AUTH_LEN;
    }
    if (targetInt <= 0) {
        return std::string();
    }

    const size_t target = static_cast<size_t>(targetInt);

    std::string out;
    out.reserve(target);

    uint8_t buf[64];
    uint64_t counter = 0;

    while (out.size() < target) {
        std::string material;
        material.reserve(id.size() + 96);
        material.append(TAG_2AUTH_V4);
        material.push_back('|');
        material.append("plan:");
        material.append(PLAN_PWD_KDF);
        material.push_back('|');
        material.append(std::to_string(id.size()));
        material.push_back(':');
        material.append(id);
        material.push_back('|');
        material.append(std::to_string(counter));

        // Initial SHA-512 of material
        uint8_t seed64[64];
        ag_sha512(reinterpret_cast<const uint8_t*>(material.data()),
                  static_cast<uint32_t>(material.size()),
                  seed64);

        // Memory-hard expansion
        mh_expand_64(seed64, buf);

        // Base64URL encode final block
        std::string chunk = base64Url(buf, sizeof(buf));
        if (chunk.empty()) {
            return std::string();
        }

        const size_t remaining = target - out.size();
        if (chunk.size() <= remaining) {
            out += chunk;
        } else {
            out.append(chunk.data(), remaining);
        }

        if (counter == std::numeric_limits<uint64_t>::max()) {
            break;
        }
        ++counter;
    }

    if (out.size() > target) {
        out.resize(target);
    }
    return out;
}

// ---------- C ABI exports ----------

extern "C" {

// 1 if valid, 0 otherwise
int ag_is_valid_id(const char* ptr, int len) {
    if (!ptr || len <= 0 || len > MAX_INPUT_LEN) return 0;
    std::string s(ptr, ptr + len);
    return isValidId(s) ? 1 : 0;
}

// Generate 2auth key. Returns length written, or 0 on error.
int ag_generate_2auth(const char* idPtr, int idLen, int length,
                      char* outBuf, int outBufLen) {
    if (!idPtr || !outBuf) return 0;
    if (idLen <= 0 || idLen > MAX_INPUT_LEN) return 0;
    if (outBufLen <= 0) return 0;

    std::string id(idPtr, idPtr + idLen);
    std::string key = generate2authInternal(id, length);

    if (key.empty()) return 0;
    if (key.size() > static_cast<size_t>(outBufLen)) return 0;

    for (size_t i = 0; i < key.size(); ++i) {
        outBuf[i] = key[i];
    }
    return static_cast<int>(key.size());
}

// Deterministic fallback ID. Returns length written, or 0 on error.
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
    if (!saltPtr || !uaPtr || !langPtr || !platformPtr ||
        !hwPtr || !touchPtr || !tzPtr || !outBuf) {
        return 0;
    }

    auto validLen = [](int len) {
        return len >= 0 && len <= MAX_INPUT_LEN;
    };

    if (!validLen(saltLen)     ||
        !validLen(uaLen)       ||
        !validLen(langLen)     ||
        !validLen(platformLen) ||
        !validLen(hwLen)       ||
        !validLen(touchLen)    ||
        !validLen(tzLen)) {
        return 0;
    }

    if (outBufLen <= 0) return 0;

    std::string salt(saltPtr, saltPtr + saltLen);
    std::string ua(uaPtr, uaPtr + uaLen);
    std::string lang(langPtr, langPtr + langLen);
    std::string platform(platformPtr, platformPtr + platformLen);
    std::string hw(hwPtr, hwPtr + hwLen);
    std::string touch(touchPtr, touchPtr + touchLen);
    std::string tz(tzPtr, tzPtr + tzLen);

    if (salt.empty()) {
        return 0;
    }

    std::string id = deterministicFallbackIdInternal(
        salt, ua, lang, platform, hw, touch, tz
    );

    if (id.empty()) return 0;
    if (id.size() > static_cast<size_t>(outBufLen)) return 0;

    for (size_t i = 0; i < id.size(); ++i) {
        outBuf[i] = id[i];
    }
    return static_cast<int>(id.size());
}

} // extern "C"
