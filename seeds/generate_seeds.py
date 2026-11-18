#!/usr/bin/env python3
"""Chia fuzz seed corpus generator.

Generates seed inputs for:
  * pos2-chip Rust fuzz targets (cargo-fuzz, `arbitrary` crate input format):
      - chia-pos2/fuzz/fuzz_targets/validate.rs
      - chia-pos2/fuzz/fuzz_targets/solver.rs
      - chia-pos2/fuzz/fuzz_targets/prover.rs
  * our raw C++ libFuzzer harnesses (network-exact entries, unclamped k/strength):
      - pos2_validate_raw  (C API `validate_proof`)
      - pos2_solve_raw     (C API `solve_partial_proof`)
      - pos2_quality_raw   (C API `proof_to_quality_string`)
  * chiapos v1 harness (Verifier::ValidateProof).

Key insight encoded here: the upstream Rust fuzz targets clamp k to 12..=28 and
strength to 2..=64, but the network gives RAW u8 values (0..=255) and the C ABI
only rejects odd/out-of-range k. The malformed extremes (k=29..255, strength=255,
k=0, odd k, wrong proof lengths) are never produced by the upstream targets.
Our raw harnesses + seeds cover exactly that gap.

`arbitrary` crate encoding notes (version used by the repos):
  * int_in_range for a u8 range of size n uses ONE byte b; accepted when
    b < n * floor(256/n); the value is start + (b % n). All bytes we emit for
    in-range fields are b = value - start, which is always accepted.
  * u16 range 0..=65535 consumes 2 bytes little-endian (power of two: always accepted).
  * [u8; 32] / Bytes32 consumes exactly 32 bytes.
  * Vec<u8> consumes 8 bytes little-endian length, then length bytes
    (lengths we use are <= 1024, the default size_hint cap).
"""

import os

HERE = os.path.dirname(os.path.abspath(__file__))


def u8(v: int) -> bytes:
    return bytes([v & 0xFF])


def u16le(v: int) -> bytes:
    return (v & 0xFFFF).to_bytes(2, "little")


def u64le(v: int) -> bytes:
    return (v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def w(name: str, data: bytes) -> None:
    path = os.path.join(HERE, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def seed_rust_validate(k: int, strength: int, plot_index: int, meta_group: int, proof: bytes) -> bytes:
    # plot_group_id(32) k(1) challenge(32) strength(1) plot_index(2LE) meta_group(1) vec_len(8LE) proof
    return (
        bytes(32)
        + u8(k - 12)          # k in 12..=28  -> b = k-12 (accepted, b < 255)
        + bytes(32)
        + u8(strength - 2)    # strength in 2..=64 -> b = s-2 (accepted, b < 252)
        + u16le(plot_index)
        + u8(meta_group)
        + u64le(len(proof))
        + proof
    )


def seed_rust_solver(k: int, strength: int, chain_links: list[int]) -> bytes:
    # k(1) strength(1) plot_id(32) chain_links(16 x u64 LE)
    return (
        u8(k - 12)            # k in 12..=32
        + u8(strength - 2)    # strength in 2..=10
        + bytes(32)
        + b"".join(u64le(x) for x in chain_links)
    )


def seed_raw_validate(k: int, strength: int, meta_group: int, plot_index: int, proof: bytes) -> bytes:
    # [k][strength][meta_group][plot_index u16le][plot_group_id 32][challenge 32][proof...]
    return (
        u8(k) + u8(strength) + u8(meta_group) + u16le(plot_index)
        + bytes(32) + bytes(32) + proof
    )


def seed_raw_solve(k: int, strength: int, chain_links: list[int]) -> bytes:
    # [k][strength][plot_id 32][16 x u64 LE]
    return u8(k) + u8(strength) + bytes(32) + b"".join(u64le(x) for x in chain_links)


def seed_raw_quality(k: int, strength: int, xvalues: bytes) -> bytes:
    # [k][strength][plot_id 32][x-values ...]
    return u8(k) + u8(strength) + bytes(32) + xvalues


def seed_chiapos_v1(k: int, proof_size: int, proof: bytes) -> bytes:
    # [k][id 32][challenge 32][proof_size u16le][proof...]
    return u8(k) + bytes(32) + bytes(32) + u16le(proof_size) + proof


def main() -> None:
    n = 0

    # ---------------------------------------------------------------- pos2 Rust: validate
    proofs = {
        "empty": b"",
        "len1": b"\x00",
        "len100": b"\x00" * 100,
        "len447": b"\x00" * 447,
        "len448_zeros": b"\x00" * 448,       # valid k=28 length
        "len448_ff": b"\xff" * 448,
        "len449": b"\x00" * 449,
        "len463": b"\x00" * 463,
        "len464": b"\x00" * 464,             # k_size = 29 -> quality_string() None -> chia_rs panic class
        "len480": b"\x00" * 480,
        "len512": b"\x00" * 512,
        "len1024": b"\x00" * 1024,
    }
    for pname, proof in proofs.items():
        w(f"pos2-validate/seed-{pname}", seed_rust_validate(28, 2, 0, 0, proof))
        n += 1
    for s, m, pi in ((64, 255, 65535), (2, 0, 1), (17, 128, 32768)):
        w(f"pos2-validate/seed-s{s}-m{m}-pi{pi}",
          seed_rust_validate(28, s, pi, m, b"\x00" * 448))
        n += 1
    for k in (12, 13, 27, 28):
        w(f"pos2-validate/seed-k{k}", seed_rust_validate(k, 2, 0, 0, b"\x00" * (k * 16)))
        n += 1

    # ---------------------------------------------------------------- pos2 Rust: solver
    chain_variants = {
        "zeros": [0] * 16,
        "ones": [1] * 16,
        "max": [0xFFFFFFFFFFFFFFFF] * 16,
        "mix": [0, 1, 2, 0xFFFFFFFF, 0x100000000, 0x8000000000000000,
                0x7FFFFFFFFFFFFFFF, 0xDEADBEEF, 1 << 20, 1 << 40, 1 << 63,
                255, 256, 4095, 4096, 0xFFFFFFFFFFFFFFFE],
    }
    for cname, chain in chain_variants.items():
        w(f"pos2-solver/seed-{cname}", seed_rust_solver(28, 2, chain))
        n += 1
    w("pos2-solver/seed-k12-s10", seed_rust_solver(12, 10, [0xFFFF] * 16))
    w("pos2-solver/seed-k32-s2", seed_rust_solver(32, 2, [0] * 16))
    n += 2

    # ---------------------------------------------------------------- pos2 Rust: prover (32-byte challenge)
    for cname, ch in (("zeros", bytes(32)), ("ff", b"\xff" * 32), ("half", b"\xaa" * 32)):
        w(f"pos2-prover/seed-{cname}", ch)
        n += 1

    # ---------------------------------------------------------------- pos2 C++ RAW harnesses (unclamped!)
    raw_proofs = {
        "empty": b"",
        "len1": b"\x00",
        "len447": b"\x00" * 447,
        "len448_zeros": b"\x00" * 448,
        "len448_ff": b"\xff" * 448,
        "len464": b"\x00" * 464,
        "len512": b"\x00" * 512,
        "len1024": b"\x00" * 1024,
        "len4096": b"\x00" * 4096,
    }
    for pname, proof in raw_proofs.items():
        w(f"pos2-raw/validate-seed-{pname}",
          seed_raw_validate(28, 2, 0, 0, proof))
        n += 1
    # unclamped k / strength / meta_group / plot_index extremes (the upstream gap)
    for k in (0, 1, 11, 12, 13, 27, 28, 29, 30, 32, 33, 255):
        w(f"pos2-raw/validate-seed-k{k}",
          seed_raw_validate(k, 2, 0, 0, b"\x00" * 448))
        n += 1
    for s in (0, 1, 2, 3, 17, 63, 64, 65, 255):
        w(f"pos2-raw/validate-seed-s{s}",
          seed_raw_validate(28, s, 0, 0, b"\x00" * 448))
        n += 1
    for m in (0, 1, 255):
        w(f"pos2-raw/validate-seed-m{m}",
          seed_raw_validate(28, 2, m, 0, b"\x00" * 448))
        n += 1
    for pi in (0, 1, 255, 256, 65535):
        w(f"pos2-raw/validate-seed-pi{pi}",
          seed_raw_validate(28, 2, 0, pi, b"\x00" * 448))
        n += 1
    w("pos2-raw/validate-seed-k255-s255-m255-pi65535",
      seed_raw_validate(255, 255, 255, 65535, b"\x00" * 1024))
    n += 1

    for cname, chain in chain_variants.items():
        w(f"pos2-raw/solve-seed-{cname}", seed_raw_solve(28, 2, chain))
        n += 1
    for k in (0, 1, 11, 13, 29, 33, 255):
        w(f"pos2-raw/solve-seed-k{k}", seed_raw_solve(k, 2, [0] * 16))
        n += 1
    for s in (0, 1, 2, 255):
        w(f"pos2-raw/solve-seed-s{s}", seed_raw_solve(28, s, [0xFFFFFFFFFFFFFFFF] * 16))
        n += 1

    for pname, proof in raw_proofs.items():
        w(f"pos2-raw/quality-seed-{pname}", seed_raw_quality(28, 2, proof))
        n += 1
    for k in (0, 1, 7, 8, 9, 11, 13, 29, 33, 255):
        w(f"pos2-raw/quality-seed-k{k}", seed_raw_quality(k, 2, b"\x00" * 512))
        n += 1
    for s in (0, 1, 2, 255):
        w(f"pos2-raw/quality-seed-s{s}", seed_raw_quality(28, s, b"\x00" * 512))
        n += 1

    # ---------------------------------------------------------------- chiapos v1
    for k in (1, 31, 32, 33, 50, 51, 255):
        w(f"chiapos-v1/seed-k{k}-exact", seed_chiapos_v1(k, k * 8, b"\x00" * (k * 8)))
        w(f"chiapos-v1/seed-k{k}-short", seed_chiapos_v1(k, k * 8 - 1, b"\x00" * (k * 8 - 1)))
        n += 2
    for ps in (0, 1, 2, 399, 400, 401, 4095, 4096, 65535):
        w(f"chiapos-v1/seed-k32-ps{ps}", seed_chiapos_v1(32, ps, b"\x00" * min(ps, 4096)))
        n += 1
    w("chiapos-v1/seed-ff", seed_chiapos_v1(32, 256, b"\xff" * 256))
    n += 1

    # ---------------------------------------------------------------- clvm_rs (generic atoms/programs)
    for cname, data in (
        ("empty", b""),
        ("one", b"\x01"),
        ("nil-80", b"\x80"),
        ("neg1", b"\xff"),
        ("pair-ff80", b"\xff\xff\x80"),
        ("quote", b"\x01\x01"),
        ("lsh-huge", b"\x0b\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"),
        ("div-by-zero", b"\x13\x01\x80"),
    ):
        w(f"clvm/generic-{cname}", data)
        n += 1

    print(f"generated {n} seed files under {HERE}")


if __name__ == "__main__":
    main()
