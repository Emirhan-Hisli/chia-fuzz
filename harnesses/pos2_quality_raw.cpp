// libFuzzer harness for the pos2 C API entry `proof_to_quality_string`.
//
// This is the C entry underneath chia_rs's ProofOfSpace::quality_string(),
// which the FULL NODE and WALLET call when hashing any block that carries a
// v2 proof-of-space (the same path behind the PanicException finding in
// report #4205646 follow-up). Raw k/strength are passed through unchanged.
//
// Input layout:
//   [0]        k         u8 (raw)
//   [1]        strength  u8 (raw)
//   [2..33]    plot_id   32 bytes
//   [34..]     x-values (up to 512 bytes used, zero-padded, 128 x u32)
//
// Build (from pos2-chip repo root, fse patched once):
//   clang++ -std=c++20 -O1 -g -fsanitize=fuzzer,address,undefined \
//       -fno-omit-frame-pointer -I src -I lib/fse/fse \
//       pos2_quality_raw.cpp src/api.cpp src/pos/sha/sha256.c \
//       lib/fse/fse/*.c -pthread -o pos2_quality_raw

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "pos/ProofCore.hpp"  // QualityChain

extern "C" {
bool proof_to_quality_string(
    uint8_t const* plot_id,
    uint8_t const k,
    uint8_t const strength,
    uint32_t const* proof,
    QualityChain* quality);
}

namespace {
constexpr std::size_t kPrefix = 1 + 1 + 32;                       // 34
constexpr std::size_t kProofBytes = 128 * sizeof(uint32_t);        // 512
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
    if (size < kPrefix) {
        return 0;
    }

    const uint8_t k = data[0];
    const uint8_t strength = data[1];
    const uint8_t* plot_id = data + 2;

    std::array<uint8_t, kProofBytes> proof_buf{};
    const std::size_t available = size - kPrefix;
    const std::size_t to_copy = available < kProofBytes ? available : kProofBytes;
    std::memcpy(proof_buf.data(), data + kPrefix, to_copy);

    QualityChain quality{};
    (void)proof_to_quality_string(
        plot_id,
        k,
        strength,
        reinterpret_cast<uint32_t const*>(proof_buf.data()),
        &quality);
    return 0;
}
