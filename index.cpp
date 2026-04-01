// AccessGate.cpp
//
// Hardened C++/WASM core for AccessGate in Emscripten mode (PATH A).
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

#include <string>
#include <stdint.h>
#include <limits>

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

static constexpr const char* TAG_2AUTH    = "AccessGate-2auth-v1";
static constexpr const char* TAG_FALLBACK = "AccessGate-fallback-id-v1";

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
        uint32_t a = i < len ? data[i++] : 0;
        uint32_t b = i < len ? data[i++] : 0;
        uint32_t c = i < len ? data[i++] : 0;

        uint32_t triple = (a << 16) | (b << 8) | c;

        out.push_back(tbl[(triple >> 18) & 63]);
        out.push_back(tbl[(triple >> 12) & 63]);
        out.push_back(i - 1 < len ? tbl[(triple >> 6) & 63] : '=');
        out.push_back(i < len ? tbl[triple & 63] : '=');
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

// ---------- Deterministic fallback ID ----------

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

    seed.append(TAG_FALLBACK);
    seed.push_back('|');

    appendLenPrefixed(seed, "salt",   salt);
    appendLenPrefixed(seed, "ua",     userAgent);
    appendLenPrefixed(seed, "lang",   language);
    appendLenPrefixed(seed, "plat",   platform);
    appendLenPrefixed(seed, "hw",     hwConcurrency);
    appendLenPrefixed(seed, "touch",  maxTouchPoints);
    appendLenPrefixed(seed, "tz",     timezoneOffset);

    std::string digest = sha256Hex(seed);
    return std::string("det_") + digest.substr(0, 48);
}

// ---------- 2auth generator ----------

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
        material.reserve(id.size() + 64);
        material.append(TAG_2AUTH);
        material.push_back('|');
        material.append(std::to_string(id.size()));
        material.push_back(':');
        material.append(id);
        material.push_back('|');
        material.append(std::to_string(counter));

        ag_sha512(reinterpret_cast<const uint8_t*>(material.data()),
                  static_cast<uint32_t>(material.size()),
                  buf);

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
