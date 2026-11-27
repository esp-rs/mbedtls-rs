//! Turns the hooks `mbedtls-rs-sys` installs into `mbedtls_hook = "<name>"` cfgs.
//!
//! A hook is installed only if its `hook-*` feature AND its algorithm are
//! enabled on `mbedtls-rs-sys`, or if the prebuilt libraries are used (they
//! have all the algorithm hooks). `mbedtls-rs-sys` publishes the resulting set
//! as its `hooks` metadata key.

use std::env;

/// The hooks this crate implements
const HOOKS: &[&str] = &[
    "sha1", "sha256", "sha512", "aes", "ecp_mul", "ecdsa", "ecdh", "timer",
];

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=DEP_MBEDTLS_HOOKS");

    let values = HOOKS
        .iter()
        .map(|hook| format!("\"{hook}\""))
        .collect::<Vec<_>>()
        .join(", ");
    println!("cargo::rustc-check-cfg=cfg(mbedtls_hook, values({values}))");

    let hooks = env::var("DEP_MBEDTLS_HOOKS").unwrap_or_default();

    // The other hooks (and hooks added by a newer `mbedtls-rs-sys`) are skipped
    for hook in hooks.split(',').filter(|hook| HOOKS.contains(hook)) {
        println!("cargo::rustc-cfg=mbedtls_hook=\"{hook}\"");
    }
}
