use std::{env, path::PathBuf};

use anyhow::Result;
use enumset::EnumSet;

use crate::builder::Hook;

#[path = "gen/builder.rs"]
mod builder;

fn main() -> Result<()> {
    let crate_root_path = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());

    builder::MbedtlsBuilder::track(&crate_root_path.join("gen"));
    builder::MbedtlsBuilder::track(&crate_root_path.join("mbedtls"));

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

    // Figure out what MbedTLS hook options (ALT modules) to enable
    let mut removed_hooks = EnumSet::empty();

    for (feature, hook) in [
        ("CARGO_FEATURE_NOHOOK_SHA1", Hook::Sha1),
        ("CARGO_FEATURE_NOHOOK_SHA256", Hook::Sha256),
        ("CARGO_FEATURE_NOHOOK_SHA512", Hook::Sha512),
        ("CARGO_FEATURE_NOHOOK_EXP_MOD", Hook::ExpMod),
    ] {
        if env::var(feature).is_ok() {
            removed_hooks.insert(hook);
        }
    }

    let dirs = if pregen_bindings && pregen_bindings_rs_file.exists() && removed_hooks.is_empty() {
        // Use the pre-generated bindings
        Some((pregen_bindings_rs_file, pregen_libs_dir))
    } else if target.ends_with("-espidf") {
        // Nothing to do for ESP-IDF, `esp-idf-sys` will do everything for us
        None
    } else {
        if pregen_bindings_rs_file.exists() {
            if !pregen_bindings {
                println!("cargo::warning=Forcing on-the-fly build for target {target}");
            } else {
                println!("cargo::warning=Forcing on-the-fly build for {target} because some or all hooks are disabled: {removed_hooks:?}");
            }
        }

        // For clang, use our own cross-platform sysroot
        let sysroot = (!use_gcc).then(|| crate_root_path.join("gen").join("sysroot"));

        // Need to do on-the-fly build and bindings' generation
        let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());

        let builder = builder::MbedtlsBuilder::new(
            removed_hooks.complement(),
            !use_gcc,
            crate_root_path.clone(),
            Some(target),
            Some(host),
            None,
            sysroot,
            None,
            force_esp_riscv_gcc,
        );

        let artifacts = builder.compile(&out, None)?;
        let bindings = builder.generate_bindings(&out, &artifacts.include_dirs, None)?;

        // TODO: Right now we only set this metadata for on-the-fly builds.
        //       We also need to set it when using pre-generated
        //       bindings, but that requires some refactoring.

        println!(
            "cargo::metadata=include={}",
            env::join_paths(artifacts.include_dirs.iter())
                .expect("paths should be valid")
                .to_string_lossy() // Switch to .display() when MSRV is above 1.87.0.
        );

        Some((bindings, artifacts.libraries))
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
