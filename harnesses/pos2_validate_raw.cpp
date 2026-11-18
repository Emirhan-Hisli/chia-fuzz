// libFuzzer harness for the pos2 C API entry `validate_proof`.
//
// This is the EXACT entry the full node's consensus path calls on
// network-supplied v2 proof-of-space data (chia_rs -> chia-pos2 ->
// validate_proof). Unlike the upstream Rust fuzz target (which clamps
// k to 12..=28 and strength to 2..=64), this harness passes RAW u8 values
// (0..=255) for k and strength, plus arbitrary meta_group/plot_index, because
// that is what the network parser delivers.
//
// Input layout (all little-endian, safe-clamped reads):
//   [0]        k          u8   (raw, 0..=255)
//   [1]        strength   u8   (raw, 0..=255)
//   [2]        meta_group u8   (raw)
//   [3..4]     plot_index u16 LE
//   [5..36]    plot_group_id  32 bytes
//   [37..68]   challenge      32 bytes
//   [69..]     proof bytes (up to 512 used, zero-padded)
//
// Total fixed prefix: 69 bytes.
//
// Build (from pos2-chip repo root, fse patched once via `python3 patch_fse.py`):
//   clang++ -std=c++20 -O1 -g -fsanitize=fuzzer,address,undefined \
//       -fno-omit-frame-pointer -I src -I lib/fse/fse \
//       pos2_validate_raw.cpp src/api.cpp src/pos/sha/sha256.c \
//       lib/fse/fse/*.c -pthread -o pos2_validate_raw

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "pos/ProofCore.hpp"  // QualityChain

extern "C" {
bool validate_proof(
    uint8_t const* plot_group_id,
    uint16_t const plot_index,
    uint8_t const k_size,
    uint8_t const strength,
    uint8_t const meta_group,
    uint8_t const* challenge,
    uint32_t const* proof,
    QualityChain* quality);
}

namespace {
constexpr std::size_t kPrefix = 1 + 1 + 1 + 2 + 32 + 32;          // 69
constexpr std::size_t kProofBytes = 128 * sizeof(uint32_t);        // 512
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
    if (size < kPrefix) {
        return 0;
    }

    const uint8_t k = data[0];
    const uint8_t strength = data[1];
    const uint8_t meta_group = data[2];
    const uint16_t plot_index = static_cast<uint16_t>(
        static_cast<uint16_t>(data[3]) | (static_cast<uint16_t>(data[4]) << 8));

    const uint8_t* plot_group_id = data + 5;
    const uint8_t* challenge = data + 5 + 32;

    std::array<uint8_t, kProofBytes> proof_buf{};
    const std::size_t available = size - kPrefix;
    const std::size_t to_copy = available < kProofBytes ? available : kProofBytes;
    std::memcpy(proof_buf.data(), data + kPrefix, to_copy);

    QualityChain quality{};
    (void)validate_proof(
        plot_group_id,
        plot_index,
        k,
        strength,
        meta_group,
        challenge,
        reinterpret_cast<uint32_t const*>(proof_buf.data()),
        &quality);
    return 0;
}
