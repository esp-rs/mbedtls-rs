//! Turns the hooks `mbedtls-rs-sys` installs into `mbedtls_hook = "<name>"` cfgs.
//!
//! A hook is installed only if its `hook-*` feature AND its algorithm are
//! enabled on `mbedtls-rs-sys`. This crate enables the `hook-*` features, but
//! it cannot see which algorithms the user selected, so `mbedtls-rs-sys`
//! publishes the resulting set as its `hooks` metadata key.

use std::env;

const HOOKS: &[&str] = &[
    "sha1",
    "sha256",
    "sha512",
    "exp_mod",
    "aes",
    "ecp_mul",
    "ecp_verify",
    "timer",
    "wall_clock",
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

    // Hooks this crate does not know (added by a newer `mbedtls-rs-sys`) are
    // skipped
    for hook in hooks.split(',').filter(|hook| HOOKS.contains(hook)) {
        println!("cargo::rustc-cfg=mbedtls_hook=\"{hook}\"");
    }
}
