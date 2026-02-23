use anyhow::Result;
use std::option::Option::Some;
use std::{env, path::PathBuf};

use crate::builder::{Hook, HooksMetadata, MbedtlsBuilder};

#[path = "gen/builder.rs"]
mod builder;

fn read_hooks_metadata(
    target: &str,
    crate_root: &std::path::Path,
) -> Option<enumset::EnumSet<Hook>> {
    let metadata_path = crate_root
        .join("src")
        .join("include")
        .join(format!("{target}.toml"));

    if !metadata_path.exists() {
        return None;
    }

    let content = std::fs::read_to_string(&metadata_path).ok()?;
    let metadata: HooksMetadata = toml::from_str(&content).ok()?;

    Some(metadata.hooks)
}

fn main() -> Result<()> {
    let crate_root_path = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());

    MbedtlsBuilder::track(&crate_root_path.join("gen"));
    MbedtlsBuilder::track(&crate_root_path.join("mbedtls"));

    let host = env::var("HOST").unwrap();
    let target = env::var("TARGET").unwrap();

    let use_gcc = env::var("CARGO_FEATURE_USE_GCC").is_ok();
    let force_esp_riscv_gcc = env::var("CARGO_FEATURE_FORCE_ESP_RISCV_GCC").is_ok();

    let pregen_bindings = env::var("CARGO_FEATURE_FORCE_GENERATE_BINDINGS").is_err();
    let pregen_bindings_rs_file = crate_root_path
        .join("src")
        .join("include")
        .join(format!("{target}.rs"));
    let pregen_libs_dir = crate_root_path.join("libs").join(&target);

    // Figure out what MbedTLS hook options to enable
    let mut hooks = builder::DEFAULT_HOOKS;
    for (feature, hook) in [
        ("CARGO_FEATURE_NOHOOK_SHA1", Hook::Sha1),
        ("CARGO_FEATURE_NOHOOK_SHA256", Hook::Sha256),
        ("CARGO_FEATURE_NOHOOK_SHA512", Hook::Sha512),
        ("CARGO_FEATURE_NOHOOK_EXP_MOD", Hook::ExpMod),
    ] {
        if env::var(feature).is_ok() {
            hooks.remove(hook);
        }
    }

    for (feature, hook) in [
        ("CARGO_FEATURE_HOOK_TIMER", Hook::Timer),
        ("CARGO_FEATURE_HOOK_WALL_CLOCK", Hook::WallClock),
    ] {
        if env::var(feature).is_ok() {
            hooks.insert(hook);
        }
    }

    let hooks_changed = if let Some(pregen_hooks) = read_hooks_metadata(&target, &crate_root_path) {
        // Compare against actual hooks used for pre-generation
        if hooks != pregen_hooks {
            println!(
                "cargo::warning=Hooks changed for {target}. Current: {hooks:?}, Pre-generated: {pregen_hooks:?}"
            );
            true
        } else {
            false
        }
    } else {
        // No metadata found - assume DEFAULT_HOOKS for backward compatibility
        if pregen_bindings_rs_file.exists() {
            println!(
                "cargo::warning=No hooks metadata found for {target}, comparing against DEFAULT_HOOKS"
            );
        }
        hooks != builder::DEFAULT_HOOKS
    };

    let dirs = if pregen_bindings && pregen_bindings_rs_file.exists() && !hooks_changed {
        // Use the pre-generated bindings
        Some((pregen_bindings_rs_file, pregen_libs_dir))
    } else if target.ends_with("-espidf") {
        // Nothing to do for ESP-IDF, `esp-idf-sys` will do everything for us
        None
    } else {
        if pregen_bindings_rs_file.exists() {
            if !pregen_bindings {
                println!("cargo::warning=Forcing on-the-fly build for target {target} as bindings are not available.");
            } else {
                println!("cargo::warning=Forcing on-the-fly build for {target} because hooks don't match default. Enabled hooks: {hooks:?}.");
            }
        }

        // For clang, use our own cross-platform sysroot
        let sysroot = (!use_gcc).then(|| crate_root_path.join("gen").join("sysroot"));

        // Need to do on-the-fly build and bindings' generation
        let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());

        let builder = MbedtlsBuilder::new(
            hooks,
            !use_gcc,
            crate_root_path.clone(),
            Some(target),
            Some(host),
            None,
            sysroot,
            None,
            force_esp_riscv_gcc,
        );

        let libs_dir = builder.compile(&out, None)?;
        let bindings = builder.generate_bindings(&out, None)?;

        Some((bindings, libs_dir))
    };

    if let Some((bindings, libs_dir)) = dirs {
        println!(
            "cargo::rustc-env=MBEDTLS_RS_SYS_BINDINGS_FILE={}",
            bindings.display()
        );

        println!("cargo::rustc-link-search={}", libs_dir.display());

        for entry in std::fs::read_dir(libs_dir)? {
            let entry = entry?;

            let file_name = entry.file_name();
            let file_name = file_name.to_str().unwrap();
            if file_name.ends_with(".a") || file_name.to_ascii_lowercase().ends_with(".lib") {
                let lib_name = if file_name.ends_with(".a") {
                    file_name.trim_start_matches("lib").trim_end_matches(".a")
                } else {
                    file_name.trim_end_matches(".lib")
                };

                println!("cargo::rustc-link-lib=static={lib_name}");
            }
        }
    }

    Ok(())
}
