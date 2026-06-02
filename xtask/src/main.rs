use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};

use clap::{Parser, Subcommand};

use log::{info, LevelFilter};

use tempfile::TempDir;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Compile and generate bindings for MbedTLS to be used in Rust.",
    long_about = None,
    subcommand_required = true,
)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate Rust bindings and the matching `.a` static libraries for a
    /// given target.
    ///
    /// Delegates the actual build to `cargo build -p mbedtls-rs-sys --target
    /// <target> --features force-generate-bindings[,...]`, so the MbedTLS C
    /// build runs through the regular Cargo dep graph. The resulting `.a`
    /// libraries and `bindings.rs` are then copied from the `mbedtls-rs-sys`
    /// build script's `OUT_DIR` to the canonical
    /// `mbedtls-rs-sys/libs/<target>/` and
    /// `mbedtls-rs-sys/src/include/<target>.rs` paths.
    Gen {
        /// Use GCC instead of clang to build the C MbedTLS code.
        ///
        /// Note that - for non-host targets - the user is expected to have the
        /// corresponding GCC cross-toolchain installed.
        #[arg(short = 'g', long = "gcc")]
        use_gcc: bool,

        /// If the target is a riscv32 target, force the use of the Espressif RISCV GCC toolchain
        /// (`riscv32-esp-elf-gcc`) rather than the derived `riscv32-unknown-elf-gcc` toolchain which is the "official" RISC-V one
        /// (https://github.com/riscv-collab/riscv-gnu-toolchain).
        ///
        /// Implies `--gcc`.
        #[arg(short = 'e', long = "force-esp-riscv-gcc")]
        force_esp_riscv_gcc: bool,

        /// Enable timer hook support.
        #[arg(long = "timer")]
        timer: bool,

        /// Enable wall-clock hook support.
        ///
        /// Implies `--timer`.
        #[arg(long = "wall-clock")]
        wall_clock: bool,

        /// Target triple for which to generate bindings and `.a` libraries.
        target: String,

        /// Extra arguments to forward verbatim to the underlying
        /// `cargo build` invocation. Specify after a `--` separator.
        ///
        /// Notably useful for `-Zbuild-std=core,alloc,panic_abort` when
        /// building for Tier-3 targets like Xtensa, where rustup doesn't
        /// ship a pre-compiled `core`. Such a build also requires the
        /// matching toolchain to be active (e.g. `cargo +esp xtask gen
        /// xtensa-esp32-none-elf -- -Zbuild-std=core,alloc,panic_abort`);
        /// the xtask itself stays toolchain-agnostic.
        #[arg(last = true, allow_hyphen_values = true)]
        cargo_args: Vec<String>,
    },
}

fn main() -> Result<()> {
    env_logger::Builder::new()
        .filter_module("xtask", LevelFilter::Info)
        .init();

    // The directory containing the cargo manifest for the 'xtask' package is a
    // subdirectory of the workspace root.
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = workspace.parent().unwrap().canonicalize()?;

    let sys_crate_root_path = workspace.join("mbedtls-rs-sys");

    let args = Args::parse();

    if let Some(Commands::Gen {
        target,
        use_gcc,
        force_esp_riscv_gcc,
        timer,
        wall_clock,
        cargo_args,
    }) = args.command
    {
        let libs_dst = sys_crate_root_path.join("libs").join(&target);
        let bindings_dst = sys_crate_root_path
            .join("src")
            .join("include")
            .join(format!("{target}.rs"));

        // `_target_dir` is kept in scope for the duration of `harvest` so the
        // scratch CARGO_TARGET_DIR (and therefore `out_dir`, which lives inside
        // it) is not yet cleaned up. It's dropped at the end of this scope.
        let (_target_dir, out_dir) = run_cargo(
            &workspace,
            &target,
            use_gcc,
            force_esp_riscv_gcc,
            timer,
            wall_clock,
            &cargo_args,
        )?;

        harvest(&out_dir, &libs_dst, &bindings_dst)?;
    }

    Ok(())
}

/// Spawn `cargo build` on `mbedtls-rs-sys` for `target`, parse the
/// `--message-format=json-render-diagnostics` event stream and return the
/// `OUT_DIR` reported by `mbedtls-rs-sys`' build script.
fn run_cargo(
    workspace: &Path,
    target: &str,
    use_gcc: bool,
    force_esp_riscv_gcc: bool,
    timer: bool,
    wall_clock: bool,
    cargo_args: &[String],
) -> Result<(TempDir, PathBuf)> {
    let mut features: Vec<&str> = vec!["force-generate-bindings"];

    if use_gcc {
        features.push("use-gcc");
    }

    if force_esp_riscv_gcc {
        // `force-esp-riscv-gcc` already implies `use-gcc` via Cargo's feature
        // dependency, but adding both is harmless and self-documenting.
        features.push("force-esp-riscv-gcc");
    }

    if timer {
        features.push("hook-timer");
    }

    if wall_clock {
        // `hook-wall-clock` already implies `hook-timer` via Cargo's feature
        // dependency, but adding both is harmless and self-documenting.
        features.push("hook-wall-clock");
    }

    let features_arg = features.join(",");

    // Use a scratch CARGO_TARGET_DIR so every `xtask gen` invocation is a
    // guaranteed-clean build. The MbedTLS C compile is the expensive part
    // anyway; pretending to cache it across invocations would risk shipping
    // pre-generated artifacts that aren't actually consistent with the current
    // source.
    let target_dir = TempDir::with_prefix("mbedtls-rs-sys-xtask-")
        .context("creating scratch CARGO_TARGET_DIR")?;

    info!(
        "Building mbedtls-rs-sys for {target} (features: {features_arg}, \
         scratch dir: {})",
        target_dir.path().display(),
    );

    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut child = Command::new(&cargo)
        .arg("build")
        .arg("--release")
        .arg("-p")
        .arg("mbedtls-rs-sys")
        .arg("--target")
        .arg(target)
        .arg("--features")
        .arg(&features_arg)
        // JSON on stdout for programmatic consumption; human-readable
        // diagnostics still rendered on stderr.
        .arg("--message-format=json-render-diagnostics")
        // Forward any user-supplied extra args (e.g.
        // `-Zbuild-std=core,alloc,panic_abort` for Xtensa) verbatim.
        .args(cargo_args)
        .current_dir(workspace)
        .env("CARGO_TARGET_DIR", target_dir.path())
        .stdout(Stdio::piped())
        .spawn()
        .context("spawning `cargo build`")?;

    let stdout = child.stdout.take().expect("stdout is piped");

    let mut out_dir: Option<PathBuf> = None;

    for line in BufReader::new(stdout).lines() {
        let line = line.context("reading cargo stdout")?;
        let msg: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            // Non-JSON output gets ignored; cargo only emits JSON in this mode,
            // but be defensive.
            Err(_) => continue,
        };
        if msg.get("reason").and_then(|v| v.as_str()) != Some("build-script-executed") {
            continue;
        }
        let pkg = msg
            .get("package_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        // `mbedtls-rs-sys` is the only `*-sys` crate in our own dep graph here,
        // but matching on the substring keeps things future-proof.
        if !pkg.contains("mbedtls-rs-sys") {
            continue;
        }
        if let Some(od) = msg.get("out_dir").and_then(|v| v.as_str()) {
            out_dir = Some(PathBuf::from(od));
        }
    }

    let status = child.wait().context("waiting for cargo")?;
    if !status.success() {
        bail!("`cargo build` failed");
    }

    let out_dir = out_dir.ok_or_else(|| {
        anyhow!(
            "no `build-script-executed` event for mbedtls-rs-sys in cargo output \
             - cannot locate OUT_DIR"
        )
    })?;

    Ok((target_dir, out_dir))
}

/// Copy the build script's outputs to the canonical pre-generated paths.
fn harvest(out_dir: &Path, libs_dst: &Path, bindings_dst: &Path) -> Result<()> {
    // `mbedtls-rs-sys/gen/builder.rs::compile` lands the `.a` files under
    // `<OUT_DIR>/mbedtls/lib/`.
    let src_libs = out_dir.join("mbedtls").join("lib");
    if !src_libs.is_dir() {
        bail!("expected `{}` to exist after the build", src_libs.display());
    }

    // Clear any prior contents so libraries removed or renamed in the current
    // mbedtls-rs-sys configuration don't linger as orphans.
    if libs_dst.exists() {
        fs::remove_dir_all(libs_dst).with_context(|| format!("clearing {}", libs_dst.display()))?;
    }

    fs::create_dir_all(libs_dst).with_context(|| format!("creating {}", libs_dst.display()))?;

    let mut count = 0usize;
    for entry in
        fs::read_dir(&src_libs).with_context(|| format!("reading {}", src_libs.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let lower = name_str.to_ascii_lowercase();
        if lower.ends_with(".a") || lower.ends_with(".lib") {
            let dst = libs_dst.join(&*name_str);
            fs::copy(entry.path(), &dst).with_context(|| {
                format!("copying {} -> {}", entry.path().display(), dst.display())
            })?;
            count += 1;
        }
    }

    info!("Copied {count} static libraries to {}", libs_dst.display());

    // The post-hook merged `mbedtls_config.h` produced by
    // `MbedtlsBuilder::compile` lives at
    // `<OUT_DIR>/mbedtls/build/include/mbedtls/mbedtls_config.h`. Pre-generated
    // consumers (the `pregen_bindings` branch of `mbedtls-rs-sys/build.rs`)
    // expect to find it at `<libs_dst>/include/mbedtls/mbedtls_config.h`,
    // which is what the old xtask's `compile(out, Some(libs_dst))` call would
    // have produced via its `copy_path` arm. Mirror that here.
    let config_src = out_dir
        .join("mbedtls")
        .join("build")
        .join("include")
        .join("mbedtls")
        .join("mbedtls_config.h");
    if !config_src.is_file() {
        bail!(
            "expected `{}` to exist after the build",
            config_src.display(),
        );
    }
    let config_dst = libs_dst
        .join("include")
        .join("mbedtls")
        .join("mbedtls_config.h");
    fs::create_dir_all(config_dst.parent().unwrap())
        .with_context(|| format!("creating {}", config_dst.parent().unwrap().display()))?;
    fs::copy(&config_src, &config_dst).with_context(|| {
        format!(
            "copying {} -> {}",
            config_src.display(),
            config_dst.display(),
        )
    })?;
    info!("Copied merged mbedtls_config.h to {}", config_dst.display());

    // `mbedtls-rs-sys/gen/builder.rs::generate_bindings` writes the bindings
    // to `<OUT_DIR>/bindings.rs`.
    let bindings_src = out_dir.join("bindings.rs");
    if !bindings_src.is_file() {
        bail!(
            "expected `{}` to exist after the build",
            bindings_src.display(),
        );
    }

    if let Some(parent) = bindings_dst.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }

    fs::copy(&bindings_src, bindings_dst).with_context(|| {
        format!(
            "copying {} -> {}",
            bindings_src.display(),
            bindings_dst.display(),
        )
    })?;

    info!("Copied bindings to {}", bindings_dst.display());

    Ok(())
}
