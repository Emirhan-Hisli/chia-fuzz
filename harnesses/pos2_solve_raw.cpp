// libFuzzer harness for the pos2 C API entry `solve_partial_proof`.
//
// This is the exact entry the solver service calls on attacker-supplied
// SolverInfo (PartialProof fragments + plot_id + k + strength) when the
// solver is reachable over the network (solver service,
// trusted_peers_only=false). Raw u8 k/strength values are passed through
// unchanged, covering the range the upstream Rust fuzz target excludes.
//
// Input layout:
//   [0]        k          u8 (raw)
//   [1]        strength   u8 (raw)
//   [2..33]    plot_id    32 bytes
//   [34..161]  chain_links 16 x u64 LE (128 bytes; short input zero-pads)
//
// Build (from pos2-chip repo root, fse patched once):
//   clang++ -std=c++20 -O1 -g -fsanitize=fuzzer,address,undefined \
//       -fno-omit-frame-pointer -I src -I lib/fse/fse \
//       pos2_solve_raw.cpp src/api.cpp src/pos/sha/sha256.c \
//       lib/fse/fse/*.c -pthread -o pos2_solve_raw

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "pos/ProofCore.hpp"  // QualityChain

extern "C" {
bool solve_partial_proof(
    QualityChain const* quality,
    uint8_t const* plot_id,
    uint8_t const k,
    uint8_t const strength,
    uint32_t* output);
}

namespace {
constexpr std::size_t kPrefix = 1 + 1 + 32;                       // 34
constexpr std::size_t kChainBytes = 16 * sizeof(uint64_t);        // 128
constexpr std::size_t kOutput = 128 * sizeof(uint32_t);           // 512
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
    if (size < kPrefix) {
        return 0;
    }

    const uint8_t k = data[0];
    const uint8_t strength = data[1];
    const uint8_t* plot_id = data + 2;

    QualityChain quality{};
    {
        const std::size_t available = size - kPrefix;
        const std::size_t to_copy = available < kChainBytes ? available : kChainBytes;
        std::memcpy(&quality.chain_links, data + kPrefix, to_copy);
    }

    std::array<uint32_t, 128> output{};
    (void)solve_partial_proof(&quality, plot_id, k, strength, output.data());
    return 0;
}
