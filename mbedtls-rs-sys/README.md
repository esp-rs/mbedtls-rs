# mbedtls-rs-sys

"No-thrills" raw Rust bindings to the 3.X branch of the MbedTLS library.
`no_std` compatible and thus suitable for use on baremetal MCUs.

## Goals

- Power `mbedtls-rs` - a **type-safe**, async and blocking API specifically and only for TLS IO (the original purpose of MbedTLS);
- Use the generated `.a` libs with other C libraries depending on `MbedTLS` crypto algorithms (e.g. OpenThread) thus taking advantage of the hardware-acceleration capabilities this crate exposes (See "Hooking" below);
- Use - from Rust - as a generic library for crypto algorithms (e.g. digests, AES, RSA etc.). Alternative to `RustCrypto`.

## Non-goals

- Provide type-safe bindings for the crypto algorithms in MbedTLS
  - The above use cases are too few and a bit corner-case to justify the effort

## Precompilation

For user-convenience, the MbedTLS C library also comes pre-built for the following Rust targets:
- `rsicv32imc-unknown-none-elf`
- `rsicv32imac-unknown-none-elf`
- `xtensa-esp32-none-elf`
- `xtensa-esp32s2-none-elf`
- `xtensa-esp32s3-none-elf`
- (PRs for other Rust baremetal targets appreciated!)

The prebuilt libraries are built with the default `tls` profile and with all the algorithm hooks (see "Hooking" below). They are used when the selected algorithms are exactly those of `tls`, whichever of the algorithm hooks are enabled. Any other selection of algorithms, or the timer and wall-clock hooks, means that the MbedTLS C library is compiled on the fly.

For other MCU baremetal targets as well as for STD platforms, the MbedTLS C library will be compiled on the fly with `clang` (by default), or with GCC (if the `use-gcc` feature is enabled). 

Note that for the latter, you DO need to have the GCC cross-compiler flavor for your MCU pre-installed and on your $PATH, while with `clang` _ANY_ `clang` instance would do, as `clang` is natively a cross-compiler. `clang` is anyway always necessary during on-the-fly compilation for the Rust bindings' generation, so that's why it is used by default for compiling the MbedTLS C library as well.

The on-the-fly compilation process also needs `cmake` (3.19 or newer) and `ninja` pre-installed (for now).

On macOS, the `clang` build also needs the `llvm-tools` rustup component (`rustup component add llvm-tools`), or a non-Apple `clang` such as Homebrew's LLVM first on `$PATH`: Apple's `ar` silently drops the ELF objects of the C library.

ESP-IDF is also supported and in that case `mbedtls-rs-sys` becomes just an alias for `esp-idf-sys` and uses the MbedTLS library which is built-in inside ESP-IDF.

**NOTE:**: on-the-fly compilation can be forced by using the `force-generate-bindings` feature.

## Tuning TLS record buffer sizes (RAM)

By default MbedTLS allocates two ~16 KiB record-plaintext buffers **per TLS connection** (`MBEDTLS_SSL_IN_CONTENT_LEN` / `MBEDTLS_SSL_OUT_CONTENT_LEN` default to `16384`), i.e. ~32 KiB of heap per connection. On RAM-constrained MCUs you can shrink these with the `ssl-in-content-len-<N>` / `ssl-out-content-len-<N>` features (`N` one of `256, 512, 1024, 2048, 4096, 8192, 16384`):

```toml
mbedtls-rs-sys = { version = "...", features = ["ssl-in-content-len-4096", "ssl-out-content-len-2048"] }
```

(The `mbedtls-rs` crate re-exposes the same features.)

- **Additive:** Cargo features unify across the dependency graph, so if several `ssl-in-content-len-*` (or `-out-`) are enabled the **largest wins** — a bigger buffer is always safe for the consumer that asked for a smaller one.
- **Default-preserving:** selecting none (or `-16384`) keeps MbedTLS's default and reuses the committed prebuilt `.a` libraries. A smaller size is `#define`d into the MbedTLS config, which **forces an on-the-fly MbedTLS rebuild** (so `clang`/`cmake`/`ninja` must be installed — see above). A Max-Fragment-Length (MFL) negotiation alone does *not* shrink these buffers; only `*_CONTENT_LEN` does.
- **`IN` is the risky one:** if the incoming buffer is smaller than a record the peer sends, the handshake/read fails. A **client** lowering `IN` should request MFL ≤ `IN`; a **server** cannot force arbitrary clients to send smaller records, so keep its `IN` conservative. `OUT` is usually less constrained, but an `OUT` smaller than an outgoing handshake message (e.g. a large client certificate chain in mTLS) will also fail the handshake.

## Hooking (for HW accel)

Putting aside the new PSA Crypto driver layer, MbedTLS 3.X has a relatively simplistic approach ("_ALT" macros) towards hardware acceleration.
Say, you want the SHA-1 algorithm beging accelerated. You then need to:
- Instruct MbedTLS - **at C compile-time** to **compile-out** its built-in SHA-1 implementation by defining the `MBEDTLS_SHA1_ALT` macro;
- Provide your own mbedtls_sha1_* functions at link time which need to match the signatures of the MbedTLS SHA-1 implementation;
- Provide your own `mbedtls_sha1_context` structure to MbedTLS - **at C compile-time** - in a custom C header file (the structure is treated as opaque by MbedTLS).

Needless to say, this is a lot of lift-and-shift for Rust developers, especially if they plan to plug-in **Rust-based** hardware accelerated routines.
For that reason, `mbedtls-rs-sys` provides the so called Hooking mechanism, currently for:
- The SHA-1, SHA-224/256 and SHA-384/512 digests (`hook_sha1`, `hook_sha224`, `hook_sha256`, `hook_sha384`, `hook_sha512`; features `hook-sha1`, `hook-sha256` and `hook-sha512`)
- The AES block cipher, including all its cipher modes and everything MbedTLS builds on top of it - CCM, GCM, CMAC and CTR-DRBG (`hook_aes`; feature `hook-aes`)
- The ECP scalar multiplication (`R = m * P`) and public-key (point-on-curve) check, through which all ECDH / ECDSA / ECJPAKE (and generic SPAKE2+-style protocol) math funnels (`hook_ecp_mul`, `hook_ecp_verify`; features `hook-ecp-mul` and `hook-ecp-verify`)
- The MPI (bignum) modular exponentiation used by RSA and DHM (`hook_exp_mod`; feature `hook-exp-mod`)

Each hook is behind its own `hook-*` feature, and none is enabled by default. Without the feature, MbedTLS is compiled with its own implementation only and the `hook_*` function does not exist. A hook also needs its algorithm to be compiled in (e.g. `hook-aes` does nothing without `alg-aes`).

The exception are the prebuilt libraries. They are built with all the algorithm hooks, so a build that uses them has all of these hooks installed and all the `hook_*` functions available, whether or not the `hook-*` features are enabled. A hook that is not registered falls back to the software implementation.

The features are meant to be enabled by the crates that implement the hooks, rather than by the user. For example, [`mbedtls-rs-sys-esp`](../mbedtls-rs-sys-esp) implements them with the hardware accelerators of the ESP32 chips and enables the hooks of the accelerators the selected chip has. Such crates learn which hooks are installed from the `hooks` metadata key of this crate (`DEP_MBEDTLS_HOOKS` in their build script): a comma-separated list such as `sha1,sha256,aes`. This crate gates its own hook code on the same list, as `mbedtls_hook = "<name>"` cfgs.

Besides the hardware-acceleration hooks above, two further hooks supply platform facilities that MbedTLS cannot obtain by itself on a baremetal target:
- A monotonic timer, for DTLS retransmission timeouts (`hook_timer`, behind the `hook-timer` feature)
- A wall clock, for X.509 certificate time validation (`hook_wall_clock`, behind the `hook-wall-clock` feature, which enables `hook-timer` too)

**The wall clock hook has a security consequence and is off by default.** Without the `hook-wall-clock` feature, `MBEDTLS_HAVE_TIME_DATE` is undefined, so the `notBefore` / `notAfter` window of a certificate is not checked at all: an expired or not-yet-valid peer certificate is accepted even when verification is otherwise required. Chain, signature and hostname verification are unaffected. Enable `hook-wall-clock` and install an `MbedtlsWallClock` (plus an `MbedtlsTimer`) before any X.509 use to get the date checks; with the feature enabled and no clock installed, validation fails closed.

In essence Hooking relies on the "_ALT" functionality in MbedTLS and specifically does the following:
- It replaces e.g. the `mbedtls_sha1_context` of MbedTLS with a custom one which is just a sequence of bytes (called a "work area" throughout `mbedtls-rs-sys`)
  - The exact number of bytes of the work area depends on the concrete algorithm being hooked, but the size **IS** hard-coded yet chosen large enough to be "good enough" for any Rust based HW-accel implementation
  - In case the unthinkable happens and the size is not large enough, it must be extended with a PR, or the Rust accel needs to manage its own storage and use the sequence of bytes in `mbedtls_sha1_context` as a pointer of sorts
  - How the Rust HW accel implementation uses the sequence of bytes is up to the implementation, but the expectation is that it would emplace its own Rust type(s) in there, following the rules of Rust for proper memory allgnment; the `WorkArea` type provided by `mbedtls-rs-sys` provides helpers for that
- There is a dyn-compatible trait for each hook (algorithm to be HW accelerated) provided by `mbedtls-rs-sys` that the Rust developer needs to implement. For e.g. SHA-1, the trait is called `MbedtlsSha1`. User is expected to call e.g. `hook_sha1(&'static dyn MbedtlsSha1)` with their own implementation early in their program initialization code
  - If `hook_XXX` is not called for a particular hook algorithm, MbedTLS would function just fine and would fallback to its own software implementation of the algorithm
    - For hooks that replace a whole module (`MBEDTLS_SHA1_ALT`, `MBEDTLS_SHA256_ALT`, `MBEDTLS_SHA512_ALT`, `MBEDTLS_AES_ALT`) the "_ALT" macro functionality normally **completely erases** the original C software impl from the build. `mbedtls-rs-sys` keeps it by compiling those modules' source files with the "_ALT" switch off and every public symbol (context types included) renamed via `-D` macros to `mbedtls_*_soft_*`
    - Hardware implementations can reuse the software fallback as an escape hatch (e.g. `SoftAesState`, used by `mbedtls-rs-sys-esp` for key sizes the AES peripheral does not support)

Finally, when hooking stateless algorithms that do their job with a single function call (like `mbedtls_mpi_mod_exp`), there is no notion of a "work area" as the crypto algorithm does not really have an externally-observable state, in that it finishes all its operation in one go.

## Error Handling

Laboriously checking the integer result when calling each `mbedtls_*` function is deemed unergonomic enough so that `mbedtls-rs-sys` provides:
- A Rust `core::error::Error` wrapper over the integer codes of MbedTLS: `MbedtlsError`
- A small macro - `merr!` that turns MbedTLS error codes into a `Result<i32, MbedtlsError>` where `Ok(i32)` is returned for non-negative error codes, and `Err(MbedtlsError)` is returned for negative error codes

## Future

The [backwards-incompatible MbedTLS 4.0 released in Oct 2025](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-4.0.0) finally splits the "I'm a generic library for crypto algorithms" use case from the "I'm a library for doing TLS IO" use case into two separate libraries:
- [TF-PSA-Crypto](https://github.com/Mbed-TLS/TF-PSA-Crypto) - for "I'm a generic library for crypto algorithms" - implementing the PSA API and having a special new driver layer for HW accel
- [MBedTLS](https://github.com/Mbed-TLS/mbedtls) - for "I'm a library for doing TLS IO" - and for now - relying **specifically** on the TF-PSA-Crypto for doing that rather than capable of using any library implementing the PSA API

Whether, and how exactly a migration to MbedTLS 4.0 would happen is still unclear but that's on the table once it starts to see wider use overall.

One way would be to have a new crate - `tf-psa-crypto-sys` which provides raw bindings to `TF-PSA-Crypto` (and somehow still does hooking). `mbedtls-rs-sys` would then only provide bindings for the "I'm a library for doing TLS IO" which is what MBedTLS 4.0 is.
