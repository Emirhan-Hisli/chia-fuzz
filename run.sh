#!/usr/bin/env bash
# Runs every built fuzz target for FUZZ_SECONDS each and collects artifacts.
# Works in Docker, on bare Linux, and in GitHub Actions.
set -uo pipefail

FUZZ_SECONDS=${FUZZ_SECONDS:-300}
CORES=${CORES:-$(nproc)}
OUT_DIR=${OUT_DIR:-/out}
FUZZ_DIR=${FUZZ_DIR:-/fuzz}
SRC_DIR=${SRC_DIR:-/src}
ARTIFACTS=${ARTIFACTS:-$OUT_DIR/artifacts}
SEEDS=$FUZZ_DIR/seeds
mkdir -p "$ARTIFACTS"

echo "fuzzing with: FUZZ_SECONDS=$FUZZ_SECONDS CORES=$CORES"

run_binary() {
  local bin="$1"; local seed_dir="$2"
  local name; name=$(basename "$bin")
  echo ""
  echo "=== $name (${FUZZ_SECONDS}s, ${CORES} workers) ==="
  mkdir -p "$ARTIFACTS/$name"
  [ -d "$seed_dir" ] || seed_dir=/dev/null
  timeout $((FUZZ_SECONDS + 120))s "$bin" "$seed_dir" \
      -max_total_time="$FUZZ_SECONDS" \
      -timeout=10 \
      -rss_limit_mb=4096 \
      -fork="$CORES" \
      -print_final_stats=1 \
      -artifact_prefix="$ARTIFACTS/$name/" || true
}

run_cargo() {
  local dir="$1"; local target="$2"; local seed_dir="$3"
  local name="$dir-$target"
  echo ""
  echo "=== $name (${FUZZ_SECONDS}s) ==="
  mkdir -p "$ARTIFACTS/$name"
  cd "$dir"
  [ -d "$seed_dir" ] || seed_dir=/dev/null
  timeout $((FUZZ_SECONDS + 120))s cargo +nightly fuzz run "$target" -- \
      "$seed_dir" \
      -max_total_time="$FUZZ_SECONDS" \
      -timeout=10 \
      -rss_limit_mb=4096 \
      -fork="$CORES" \
      -print_final_stats=1 \
      -artifact_prefix="$ARTIFACTS/$name/" || true
}

# --- C++ libFuzzer harnesses (network-exact, raw k/strength) ---
run_binary "$OUT_DIR/bin/pos2_validate_raw" "$SEEDS/pos2-raw"
run_binary "$OUT_DIR/bin/pos2_solve_raw"    "$SEEDS/pos2-raw"
run_binary "$OUT_DIR/bin/pos2_quality_raw"  "$SEEDS/pos2-raw"
run_binary "$OUT_DIR/bin/chiapos_validate_v1" "$SEEDS/chiapos-v1"

# --- pos2-chip Rust targets ---
if [ "${QUICK:-0}" != "1" ]; then
P2=$SRC_DIR/pos2/crates/chia-pos2/fuzz
run_cargo "$P2" validate "$SEEDS/pos2-validate"
run_cargo "$P2" solver   "$SEEDS/pos2-solver"
run_cargo "$P2" prover   "$SEEDS/pos2-prover"

# --- clvm_rs Rust targets ---
CL=$SRC_DIR/clvm_rs/fuzz
run_cargo "$CL" serde_2026_panic        "$SEEDS/clvm"
run_cargo "$CL" operators               "$SEEDS/clvm"
run_cargo "$CL" run_program             "$SEEDS/clvm"
run_cargo "$CL" divmod                  "$SEEDS/clvm"
run_cargo "$CL" deserialize             "$SEEDS/clvm"
run_cargo "$CL" deserialize_br          "$SEEDS/clvm"
run_cargo "$CL" canonical_serialization "$SEEDS/clvm"
else
echo "QUICK=1: Rust hedefleri atlandi (yalnizca C++ harness'lar)"
fi

echo ""
echo "=== summary ==="
find "$ARTIFACTS" -type f ! -name 'fuzz-*.log' | sort
CRASHES=$(find "$ARTIFACTS" -type f -name 'crash-*' | wc -l)
TIMEOUTS=$(find "$ARTIFACTS" -type f -name 'timeout-*' | wc -l)
OOMS=$(find "$ARTIFACTS" -type f -name 'oom-*' | wc -l)
echo "crashes=$CRASHES timeouts=$TIMEOUTS ooms=$OOMS"
echo "reproduce a crash with:  <target-binary> <artifact-file>"
