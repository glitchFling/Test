#include <cstdint>
#include <cstring>
#include <vector>
#include <emscripten.h>

extern "C" {

// imported JS hash function (32‑byte output)
extern void hash32(uint8_t* in, uint32_t in_len,
                   uint8_t* salt, uint32_t salt_len,
                   uint8_t* out);

EMSCRIPTEN_KEEPALIVE
void derive_key(uint8_t* pwd, uint32_t pwd_len,
                uint8_t* salt, uint32_t salt_len,
                uint8_t* out,
                uint32_t blocks,
                uint32_t passes)
{
    const uint32_t BS = 32;
    if (blocks < 2) blocks = 2;

    std::vector<uint8_t> mem(blocks * BS);
    std::vector<uint8_t> tmp(BS + salt_len);

    // B[0] = H(pwd || salt)
    memcpy(tmp.data(), pwd, pwd_len);
    memcpy(tmp.data() + pwd_len, salt, salt_len);
    hash32(tmp.data(), pwd_len + salt_len, salt, salt_len, mem.data());

    // fill
    for (uint32_t i = 1; i < blocks; i++) {
        uint32_t idx = *(uint32_t*)&mem[(i - 1) * BS] % i;

        for (uint32_t b = 0; b < BS; b++)
            tmp[b] = mem[(i - 1) * BS + b] ^ mem[idx * BS + b];

        memcpy(tmp.data() + BS, salt, salt_len);
        hash32(tmp.data(), BS + salt_len, salt, salt_len, &mem[i * BS]);
    }

    // passes
    for (uint32_t p = 1; p < passes; p++) {
        for (uint32_t i = 0; i < blocks; i++) {
            uint32_t idx = *(uint32_t*)&mem[i * BS + 4] % blocks;

            for (uint32_t b = 0; b < BS; b++)
                tmp[b] = mem[i * BS + b] ^ mem[idx * BS + b];

            memcpy(tmp.data() + BS, salt, salt_len);
            hash32(tmp.data(), BS + salt_len, salt, salt_len, &mem[i * BS]);
        }
    }

    // final digest
    memcpy(tmp.data(), &mem[(blocks - 1) * BS], BS);
    memcpy(tmp.data() + BS, salt, salt_len);
    hash32(tmp.data(), BS + salt_len, salt, salt_len, out);
}

EMSCRIPTEN_KEEPALIVE
int ct_eq(uint8_t* a, uint8_t* b, uint32_t len)
{
    uint32_t acc = 0;
    for (uint32_t i = 0; i < len; i++)
        acc |= (a[i] ^ b[i]);
    return acc == 0;
}

}
