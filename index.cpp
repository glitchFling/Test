#include <cstdint>
#include <cstring>
#include <vector>
#include <emscripten.h>

extern "C" {

// -----------------------------------------------------------------------------
// IMPORT: hash32
// This function must be provided by JS at runtime.
// It writes a 32‑byte digest to `out`.
// -----------------------------------------------------------------------------
extern void hash32(uint8_t* in, uint32_t in_len,
                   uint8_t* salt, uint32_t salt_len,
                   uint8_t* out)
    __attribute__((import_module("env"), import_name("hash32")));


// -----------------------------------------------------------------------------
// Constant‑time equality check
// -----------------------------------------------------------------------------
EMSCRIPTEN_KEEPALIVE
int ct_eq(uint8_t* a, uint8_t* b, uint32_t len)
{
    uint32_t acc = 0;
    for (uint32_t i = 0; i < len; i++)
        acc |= (a[i] ^ b[i]);
    return acc == 0;
}


// -----------------------------------------------------------------------------
// Memory‑hard KDF
//
// derive_key(pwd, pwd_len, salt, salt_len, out, blocks, passes)
//
// - blocks: number of 32‑byte blocks (minimum 2)
// - passes: number of full sweeps over memory
//
// Layout:
//   mem[i] = 32‑byte block
//
// B[0] = H(pwd || salt)
// B[i] = H( (B[i‑1] XOR B[idx]) || salt )
// idx = first 4 bytes of previous block mod i
//
// Additional passes:
//   same logic but idx = bytes[4..7] mod blocks
//
// Final output:
//   out = H(B[last] || salt)
// -----------------------------------------------------------------------------
EMSCRIPTEN_KEEPALIVE
void derive_key(uint8_t* pwd, uint32_t pwd_len,
                uint8_t* salt, uint32_t salt_len,
                uint8_t* out,
                uint32_t blocks,
                uint32_t passes)
{
    const uint32_t BS = 32;
    if (blocks < 2) blocks = 2;

    // Allocate memory-hard region
    std::vector<uint8_t> mem(blocks * BS);
    std::vector<uint8_t> tmp(BS + salt_len);

    // -------------------------------------------------------------------------
    // B[0] = H(pwd || salt)
    // -------------------------------------------------------------------------
    memcpy(tmp.data(), pwd, pwd_len);
    memcpy(tmp.data() + pwd_len, salt, salt_len);
    hash32(tmp.data(), pwd_len + salt_len, salt, salt_len, mem.data());

    // -------------------------------------------------------------------------
    // First fill pass
    // -------------------------------------------------------------------------
    for (uint32_t i = 1; i < blocks; i++) {
        uint32_t idx = *(uint32_t*)&mem[(i - 1) * BS] % i;

        for (uint32_t b = 0; b < BS; b++)
            tmp[b] = mem[(i - 1) * BS + b] ^ mem[idx * BS + b];

        memcpy(tmp.data() + BS, salt, salt_len);
        hash32(tmp.data(), BS + salt_len, salt, salt_len, &mem[i * BS]);
    }

    // -------------------------------------------------------------------------
    // Additional passes
    // -------------------------------------------------------------------------
    for (uint32_t p = 1; p < passes; p++) {
        for (uint32_t i = 0; i < blocks; i++) {
            uint32_t idx = *(uint32_t*)&mem[i * BS + 4] % blocks;

            for (uint32_t b = 0; b < BS; b++)
                tmp[b] = mem[i * BS + b] ^ mem[idx * BS + b];

            memcpy(tmp.data() + BS, salt, salt_len);
            hash32(tmp.data(), BS + salt_len, salt, salt_len, &mem[i * BS]);
        }
    }

    // -------------------------------------------------------------------------
    // Final digest: H(B[last] || salt)
    // -------------------------------------------------------------------------
    memcpy(tmp.data(), &mem[(blocks - 1) * BS], BS);
    memcpy(tmp.data() + BS, salt, salt_len);
    hash32(tmp.data(), BS + salt_len, salt, salt_len, out);
}

} // extern "C"
