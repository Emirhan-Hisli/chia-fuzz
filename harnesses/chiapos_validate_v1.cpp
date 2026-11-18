// libFuzzer harness for the chiapos (v1 plots) Verifier::ValidateProof.
//
// Every full node calls this exact C++ path (via the `chiapos` Python wheel)
// when validating a v1 proof-of-space taken from a network block or unfinished
// block. k, proof_size and proof bytes are attacker-controlled (u8/u16/bytes
// from the wire). The harness clamps reads safely so any crash/OOM the fuzzer
// finds belongs to chiapos, not to the harness.
//
// Input layout:
//   [0]        k           u8   (raw; Verifier rejects out-of-range)
//   [1..32]    id          32 bytes
//   [33..64]   challenge   32 bytes
//   [65..66]   proof_size  u16 LE (clamped to <= 4096 and to remaining bytes)
//   [67..]     proof bytes
//
// Build (from chiapos repo root):
//   clang++ -std=c++17 -O1 -g -fsanitize=fuzzer,address,undefined \
//       -fno-omit-frame-pointer -I src -I lib/include \
//       chiapos_validate_v1.cpp lib/FiniteStateEntropy/*.c \
//       -o chiapos_validate_v1

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "verifier.hpp"

namespace {
constexpr std::size_t kPrefix = 1 + 32 + 32 + 2;                  // 67
constexpr std::size_t kMaxProof = 4096;
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
    if (size < kPrefix) {
        return 0;
    }

    const uint8_t k = data[0];
    const uint8_t* id = data + 1;
    const uint8_t* challenge = data + 1 + 32;

    uint16_t claimed = static_cast<uint16_t>(
        static_cast<uint16_t>(data[65]) | (static_cast<uint16_t>(data[66]) << 8));
    std::size_t available = size - kPrefix;
    std::size_t proof_size = claimed < available ? claimed : available;
    if (proof_size > kMaxProof) {
        proof_size = kMaxProof;
    }

    std::vector<uint8_t> proof(proof_size);
    std::memcpy(proof.data(), data + kPrefix, proof_size);

    Verifier verifier;
    LargeBits quality = verifier.ValidateProof(
        id, k, challenge, proof.data(), static_cast<uint16_t>(proof_size));
    (void)quality;
    return 0;
}
