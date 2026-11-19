use std::{env, path::PathBuf};

use anyhow::Result;
use enumset::EnumSet;

use crate::builder::{Hook, MbedtlsBuilder};

#[path = "gen/builder.rs"]
mod builder;

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
    let hooks = Hook::active();

    // The hook modules of this crate are gated on `mbedtls_hook = "<name>"`
    // cfgs, set below for the hooks that end up installed
    let hook_names = EnumSet::<Hook>::all()
        .iter()
        .map(|hook| format!("\"{}\"", hook.name()))
        .collect::<Vec<_>>()
        .join(", ");
    println!("cargo::rustc-check-cfg=cfg(mbedtls_hook, values({hook_names}))");

    // Desync guard: when the `prebuilt` profile itself is active (i.e. `xtask`
    // generating the committed artifacts, with the prebuilt hooks), the active
    // config MUST equal the prebuilt reference. If it doesn't, the leaf list in
    // `Cargo.toml`'s `tls`/`prebuilt` bundle and `features::PREBUILT_FEATURES`
    // have drifted apart — fail loudly rather than silently shipping a `.a`
    // whose fingerprint no longer matches its own validity check.
    if env::var_os("CARGO_FEATURE_PREBUILT").is_some() {
        assert!(
            builder::PREBUILT_HOOKS.is_subset(hooks),
            "BUG: the `prebuilt` feature in Cargo.toml must enable the hooks of `PREBUILT_HOOKS`"
        );

        if hooks == builder::PREBUILT_HOOKS {
            if let Err(delta) = builder::MbedtlsBuilder::prebuilt_validity(hooks) {
                panic!(
                    "BUG: `prebuilt` profile active but the generated config does not match \
                     `features::PREBUILT_FEATURES`. The `tls`/`prebuilt` bundle in Cargo.toml \
                     and PREBUILT_FEATURES have drifted. Delta: {delta}"
                );
            }
        }
    }

    // The committed prebuilt libraries and bindings are produced with the
    // `prebuilt` profile (= `tls`) and `PREBUILT_HOOKS`. They are valid for this
    // build only if the *active* features + hooks generate a byte-for-byte
    // equivalent MbedTLS config. Any deviation — a narrower/wider algorithm
    // profile, an extra feature (e.g. `kex-ecjpake` on top of `tls`), or a hook
    // change — rejects them and forces an on-the-fly rebuild.
    let prebuilt_validity = builder::MbedtlsBuilder::prebuilt_validity(hooks);

    let use_prebuilt =
        pregen_bindings && pregen_bindings_rs_file.exists() && prebuilt_validity.is_ok();

    // The hooks installed in MbedTLS. The prebuilt artifacts have all of
    // `PREBUILT_HOOKS`, of which the requested `hooks` are then a subset.
    let installed_hooks = if use_prebuilt {
        hooks | builder::PREBUILT_HOOKS
    } else {
        hooks
    };

    let dirs = if use_prebuilt {
        // Use the pre-generated bindings.
        //
        // Order matters here and is deliberate. Both `<pregen_libs_dir>/include`
        // and `mbedtls/include` ship a `mbedtls/mbedtls_config.h`:
        //   - The first one is the pre-generated, post-hook merged config
        //     produced by `compile()`'s `copy_path` arm — this is what
        //     downstream consumers must see.
        //   - The second is the upstream mbedtls submodule's default config.
        // Putting `<pregen_libs_dir>/include` first ensures the merged config
        // shadows the upstream one on the C include path. `mbedtls/include` is
        // kept last so the rest of the upstream headers (everything except the
        // duplicated `mbedtls_config.h`) remain available to consumers.
        let include_dirs = vec![
            pregen_libs_dir.join("include"),
            crate_root_path.join("gen").join("hook"),
            crate_root_path.join("mbedtls").join("include"),
        ];

        Some((pregen_bindings_rs_file, pregen_libs_dir, include_dirs))
    } else if target.ends_with("-espidf") {
        // Nothing to do for ESP-IDF, `esp-idf-sys` will do everything for us.
        // Our dependents get ESP-IDF's configuration, which has MbedTLS's
        // options, as `DEP_MBEDTLS_EMBUILD_CFG_ARGS`.
        if let Ok(cfg_args) = embuild::build::CfgArgs::try_from_env("ESP_IDF") {
            cfg_args.propagate();
        }

        None
    } else {
        if pregen_bindings_rs_file.exists() {
            if !pregen_bindings {
                println!("cargo::warning=Forcing on-the-fly build for target {target} as bindings are not available.");
            } else if let Err(delta) = &prebuilt_validity {
                println!("cargo::warning=Forcing on-the-fly build for {target}: the selected features/hooks differ from the prebuilt config by: {delta}.");
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
            Some(target.clone()),
            Some(host),
            None,
            sysroot,
            None,
            force_esp_riscv_gcc,
        );

        let artifacts = builder.compile(&out, None)?;
        let bindings = builder.generate_bindings(&out, &artifacts.include_dirs, None)?;

        Some((bindings, artifacts.libraries, artifacts.include_dirs))
    };

    if let Some((bindings, libs_dir, include_dirs)) = dirs {
        for hook in installed_hooks {
            println!("cargo::rustc-cfg=mbedtls_hook=\"{}\"", hook.name());
        }

        // The installed hooks, for crates that implement them (e.g. hardware
        // acceleration crates), as `DEP_MBEDTLS_HOOKS`
        println!(
            "cargo::metadata=hooks={}",
            installed_hooks
                .iter()
                .map(Hook::name)
                .collect::<Vec<_>>()
                .join(",")
        );

        println!(
            "cargo::metadata=include={}",
            env::join_paths(include_dirs.iter())
                .expect("paths should be valid")
                .to_string_lossy() // Switch to .display() when MSRV is above 1.87.0.
        );

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

        // MbedTLS calls `printf` (self tests), `snprintf` and `vsnprintf`. The
        // UCRT has these only inline, in its headers; MSVC's
        // `legacy_stdio_definitions` has them as symbols. The MSVC linkers need
        // them even when only unused code calls them.
        if target.ends_with("-windows-msvc") {
            println!("cargo::rustc-link-lib=legacy_stdio_definitions");
        }
    }

    Ok(())
}
