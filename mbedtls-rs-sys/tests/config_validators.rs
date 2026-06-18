//! Integration test entry point for the codegen input validators in
//! `mbedtls-rs-sys/gen/config.rs`.
//!
//! `gen/config.rs` is only reachable in production via the `#[path]` import
//! from `mbedtls-rs-sys/build.rs`, so it has no public surface. To exercise
//! its `pub(crate)` validators under `cargo test`, this integration test
//! `#[path]`-loads the same module file as a test-crate-local `mod config`.
//! Inside that module a `#[cfg(test)] mod tests` block holds every assertion
//! against `validate_macro_ident`, `validate_macro_literal`, and
//! `validate_header_path` (including their `#[should_panic]` cases). Cargo
//! discovers those tests through normal `#[test]` walking.
//!
//! Adding tests: edit `mbedtls-rs-sys/gen/config.rs::tests`, not this file.

#![allow(
    dead_code,
    reason = "Production callers of MbedtlsUserConfig live in gen/builder.rs and gen/features.rs, neither of which is reachable from the test binary; only the validators are exercised here."
)]

#[path = "../gen/config.rs"]
mod config;
