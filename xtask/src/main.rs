use std::env;
use std::path::PathBuf;

use anyhow::Result;

use clap::{Parser, Subcommand};

use log::LevelFilter;

use tempdir::TempDir;

#[path = "../../mbedtls-rs-sys/gen/builder.rs"]
mod builder;

// Arguments
#[derive(Parser, Debug)]
#[command(author, version, about = "Compile and generate bindings for MbedTLS to be used in Rust.", long_about = None, subcommand_required = true)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate Rust bindings for MbedTLS and generate .a libraries
    Gen {
        /// Use GCC instead of clang to build the C MbedTLS code
        ///
        /// Note that - for non-host builds - this means that the user should pre-install
        /// the GCC cross-toolchain for the target.
        #[arg(short = 'g', long = "gcc")]
        use_gcc: bool,

        /// If the target is a riscv32 target, force the use of the Espressif RISCV GCC toolchain
        /// (`riscv32-esp-elf-gcc`) rather than the derived `riscv32-unknown-elf-gcc` toolchain which is the "official" RISC-V one
        /// (https://github.com/riscv-collab/riscv-gnu-toolchain)
        #[arg(short = 'e', long = "force-esp-riscv-gcc")]
        force_esp_riscv_gcc: bool,

        /// Target triple for which to generate bindings and `.a` libraries
        target: String,
    },
}

fn main() -> Result<()> {
    env_logger::Builder::new()
        .filter_module("xtask", LevelFilter::Info)
        .init();

    // The directory containing the cargo manifest for the 'xtask' package is a
    // subdirectory
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = workspace.parent().unwrap().canonicalize()?;

    let sys_crate_root_path = workspace.join("mbedtls-rs-sys");

    let args = Args::parse();

    if let Some(Commands::Gen {
        target,
        use_gcc,
        force_esp_riscv_gcc,
    }) = args.command
    {
        let use_gcc = use_gcc || force_esp_riscv_gcc;

        // For clang, use our own cross-platform sysroot
        let sysroot = (!use_gcc).then(|| sys_crate_root_path.join("gen").join("sysroot"));

        let builder = builder::MbedtlsBuilder::new(
            None,
            !use_gcc,
            sys_crate_root_path.clone(),
            Some(target.clone()),
            // Fake host, but we do need to pass something to CMake
            Some("x86_64-unknown-linux-gnu".into()),
            None,
            sysroot,
            None,
            force_esp_riscv_gcc,
        );

        let out = TempDir::new("mbedtls-sys-libs")?;

        builder.compile(
            out.path(),
            Some(&sys_crate_root_path.join("libs").join(&target)),
        )?;

        let out = TempDir::new("mbedtls-sys-bindings")?;

        builder.generate_bindings(
            out.path(),
            Some(
                &sys_crate_root_path
                    .join("src")
                    .join("include")
                    .join(format!("{target}.rs")),
            ),
        )?;
    }

    Ok(())
}
