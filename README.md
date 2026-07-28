# pq-sigs / pq-kems Benchmarks

Rust benchmarking suite for measuring the raw performance of post-quantum
signature schemes and key encapsulation mechanisms (KEMs), compared against
their classical counterparts. Timings are taken directly from the CPU cycle
counter (`RDTSC`), fenced with `LFENCE`, to get low-noise, per-operation
measurements without relying on wall-clock timers.

## What is measured

For each algorithm, three operations are benchmarked independently:

- **Key generation** (`kgen`)
- **Sign / Encapsulate**
- **Verify / Decapsulate**

Each run executes a configurable number of iterations and prints one
comma-separated line per iteration in the form:

```
kgen_cycles,sign_or_encap_cycles,verify_or_decap_cycles
```

This raw, unaggregated output is intended to be piped into a separate
analysis step (e.g. a Python/Pandas notebook) for computing medians,
percentiles, and plots, rather than being aggregated in Rust itself.

## Included algorithms

### Signatures (`sig_bench`)

| Algorithm | Family | Notes |
|---|---|---|
| ML-DSA-44 / 65 / 87 | Lattice-based | NIST-standardized (FIPS 204) |
| Falcon-512 / Falcon-1024 | Lattice-based (NTRU) | FN-DSA candidate |
| SLH-DSA (SPHINCS+), SHAKE-128/192/256, f/s variants | Hash-based | FIPS 205, currently disabled by default |
| SQIsign (level 1) | Isogeny-based | Experimental, not yet standardized |
| RSA-2048 (PKCS#1 v1.5, SHA-256) | Classical | Baseline for comparison |
| Ed25519 | Classical (elliptic curve) | Baseline for comparison |

### KEMs (`kem_bench`)

| Algorithm | Family | Notes |
|---|---|---|
| ML-KEM-512 / 768 / 1024 | Lattice-based | NIST-standardized (FIPS 203) |
| HQC-128 / 192 / 256 | Code-based | Currently disabled by default |
| X25519 | Classical (elliptic curve Diffie-Hellman) | Baseline for comparison |

Algorithms commented out in `main()` are implemented but disabled by default,
typically because they are slow, still unstable in their crate, or not the
current focus of measurement. Uncomment the relevant `println!`/`run(...)`
pair to include them in a run.

## Requirements

- Rust (nightly or stable with `x86_64` target; the code uses
  `core::arch::x86_64::_rdtsc` and `_mm_lfence`, so it currently **only runs
  on x86-64 CPUs** that support the `RDTSC` and `SSE2` instructions)

## Usage

Build and run the signature benchmarks:

```bash
cargo run --release --bin sig_bench > sig_results.csv
```

Build and run the KEM benchmarks:

```bash
cargo run --release --bin kem_bench > kem_results.csv
```

Adjust the algorithm selection and iteration count (`ITER`) directly in
`main()` / at the top of each file before building.

> **Note:** Always run with `--release`. Debug builds include bounds checks
> and lack inlining/optimizations that would otherwise dominate the cycle
> counts and make cross-algorithm comparisons meaningless.

## Reproducible measurements

Cycle counts from `RDTSC` are sensitive to system noise. For more reliable
comparisons:

- Pin the benchmark process to a single CPU core (e.g. `taskset -c 0`)
- Disable CPU frequency scaling / turbo boost during measurement
- Disable hyperthreading on the pinned core if possible
- Run on an otherwise idle machine
- Use enough iterations (`ITER`) to allow discarding warm-up outliers during
  post-processing


## Project structure

```
.
├── src/
│   ├── kem_bench.rs     # KEM benchmarks (ML-KEM, HQC, X25519)
│   └── sig_bench.rs     # Signature benchmarks (ML-DSA, Falcon, SLH-DSA, SQIsign, RSA, Ed25519)
├── Cargo.toml
└── README.md
```

## Caveats

- Results reflect **software implementations** available in the respective
  Rust crates at the time of measurement, not necessarily the fastest
  possible (e.g. hardware-accelerated or hand-optimized assembly)
  implementation of each algorithm.
- SQIsign and HQC crates are less mature than the NIST-standardized
  algorithms; expect higher variance and possible instability across crate
  versions.
