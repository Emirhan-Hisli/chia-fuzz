#!/usr/bin/env bash
# Builds every fuzz target. Runs in Docker OR directly on Linux (bare metal,
# WSL2, or GitHub Actions). All locations are env-configurable:
#
#   FUZZ_DIR   fuzz package dir (harnesses/, seeds/)   [default /fuzz]
#   SRC_DIR    dir containing pos2/, chiapos/, clvm_rs/ checkouts [default /src]
#   OUT_DIR    output dir (bin/, artifacts/)            [default /out]
#
# Tolerant: a single failing target is reported and skipped, not fatal.
set -uo pipefail

FUZZ_DIR=${FUZZ_DIR:-/fuzz}
SRC_DIR=${SRC_DIR:-/src}
OUT_DIR=${OUT_DIR:-/out}

SAN_CXX="-O1 -g -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer"
SAN_C="-O1 -g -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer"
FUZZ_LD="-fsanitize=fuzzer,address,undefined"

mkdir -p "$OUT_DIR/bin"

echo "=== [1/4] pos2-chip: C++ libFuzzer harnesses (raw k/strength, network-exact entries) ==="
cd "$SRC_DIR/pos2"
python3 patch_fse.py || echo "WARN: patch_fse.py failed (continuing)"

# Compile the C parts once (patched FSE + sha256).
mkdir -p /tmp/pos2-c && cd /tmp/pos2-c
clang $SAN_C -I "$SRC_DIR/pos2/lib/fse/fse" -c "$SRC_DIR"/pos2/lib/fse/fse/*.c "$SRC_DIR/pos2/src/pos/sha/sha256.c"

build_pos2_harness() {
  local src_file="$1"; local out_name="$2"
  clang++ -std=c++20 $SAN_CXX -I "$SRC_DIR/pos2/src" -I "$SRC_DIR/pos2/src/pos" \
      -I "$SRC_DIR/pos2/lib/fse/fse" \
      "$FUZZ_DIR/harnesses/$src_file" "$SRC_DIR/pos2/src/api.cpp" /tmp/pos2-c/*.o \
      $FUZZ_LD -pthread -o "$OUT_DIR/bin/$out_name" \
    && echo "OK  $out_name" \
    || echo "FAIL $out_name (check logs)"
}

build_pos2_harness pos2_validate_raw.cpp pos2_validate_raw
build_pos2_harness pos2_solve_raw.cpp pos2_solve_raw
build_pos2_harness pos2_quality_raw.cpp pos2_quality_raw

echo "=== [2/4] chiapos v1: Verifier::ValidateProof harness ==="
cd "$SRC_DIR/chiapos"
mkdir -p /tmp/chiapos-c && cd /tmp/chiapos-c
clang $SAN_C -I "$SRC_DIR/chiapos/lib/FiniteStateEntropy" -c "$SRC_DIR"/chiapos/lib/FiniteStateEntropy/*.c 2>/dev/null || echo "WARN: FSE C compile failed"
clang++ -std=c++17 $SAN_CXX -I "$SRC_DIR/chiapos/src" -I "$SRC_DIR/chiapos/lib/include" \
    -I "$SRC_DIR/chiapos/lib/FiniteStateEntropy" \
    "$FUZZ_DIR/harnesses/chiapos_validate_v1.cpp" /tmp/chiapos-c/*.o \
    $FUZZ_LD -pthread -o "$OUT_DIR/bin/chiapos_validate_v1" \
  && echo "OK  chiapos_validate_v1" \
  || echo "FAIL chiapos_validate_v1 (check logs; try adding missing sources)"

if [ "${QUICK:-0}" != "1" ]; then
echo "=== [3/4] pos2-chip: Rust cargo-fuzz targets (validate / solver / prover) ==="
cd "$SRC_DIR/pos2/crates/chia-pos2/fuzz"
for t in validate solver prover; do
  cargo +nightly fuzz build "$t" && echo "OK  pos2/$t" || echo "FAIL pos2/$t"
done

echo "=== [4/4] clvm_rs: cargo-fuzz targets (curated subset) ==="
cd "$SRC_DIR/clvm_rs/fuzz"
for t in serde_2026_panic operators run_program divmod deserialize deserialize_br \
         canonical_serialization canonical_serialization_br allocator arithmetic \
         keccak modpow tree_hash serializer serialized_length; do
  cargo +nightly fuzz build "$t" && echo "OK  clvm_rs/$t" || echo "FAIL clvm_rs/$t (target may not exist in Cargo.toml)"
done
else
echo "QUICK=1: Rust hedef derlemeleri atlandi (yalnizca C++ harness'lar)"
fi

echo "=== build finished; binaries in $OUT_DIR/bin ==="
ls -la "$OUT_DIR/bin" || true
