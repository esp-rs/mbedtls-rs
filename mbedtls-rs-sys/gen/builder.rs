use std::path::{Path, PathBuf};
use std::process::Command;

use self::config::MbedtlsUserConfig;
use anyhow::{anyhow, Result};
use bindgen::Builder;
use cmake::Config;
use enumset::{EnumSet, EnumSetType};

mod config;

/// What hooks to install in MbedTLS
#[derive(EnumSetType, Debug)]
pub enum Hook {
    /// SHA-1
    Sha1,
    /// SHA-224 and SHA-256
    Sha256,
    /// SHA-384 and SHA-512
    Sha512,
    /// MPI modular exponentiation
    ExpMod,
}

impl Hook {
    const fn work_area_size(self) -> Option<usize> {
        match self {
            Self::Sha1 => Some(208),
            Self::Sha256 => Some(208),
            Self::Sha512 => Some(304),
            Self::ExpMod => None,
        }
    }

    /// Returns the config identifier corresponding to this hook.
    const fn config_ident(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1_ALT",
            Self::Sha256 => "SHA256_ALT",
            Self::Sha512 => "SHA512_ALT",
            Self::ExpMod => "MPI_EXP_MOD_ALT_FALLBACK",
        }
    }

    fn apply_to_config(self, config: &mut MbedtlsUserConfig) {
        config.set(self.config_ident(), true);
        if let Some(work_area_size) = self.work_area_size() {
            // This is not relevant for MbedTLS itself, but our
            // implementation needs to know the work area size.
            let size_ident = format!("{}_WORK_AREA_SIZE", self.config_ident());
            config.set(&size_ident, work_area_size.to_string());
        }
    }
}

/// Compilation artifacts.
///
/// Returned by [`MbedtlsBuilder::compile`].
pub struct MbedtlsArtifacts {
    /// Include directories containing relevant MbedTLS headers.
    pub include_dirs: Vec<PathBuf>,
    /// Directory containing the compiled MbedTLS libraries to link against.
    #[allow(unused, reason = "xtask doesn't use this")]
    pub libraries: PathBuf,
}

/// The MbedTLS builder
pub struct MbedtlsBuilder {
    hooks: EnumSet<Hook>,
    crate_root_path: PathBuf,
    cmake_configurer: CMakeConfigurer,
    clang_path: Option<PathBuf>,
    clang_sysroot_path: Option<PathBuf>,
    clang_target: Option<String>,
}

impl MbedtlsBuilder {
    /// Create a new MbedtlsBuilder
    ///
    /// Arguments:
    /// - `hooks` - Set of algorithm hooks to enable
    /// - `force_clang`: If true, force the use of Clang as the C/C++ compiler
    /// - `crate_root_path`: Path to the root of the crate
    /// - `cmake_rust_target`: Optional target for CMake when building MbedTLS, with Rust target-triple syntax. If not specified, the "TARGET" env variable will be used
    /// - `cmake_host_rust_target`: Optional host target for the build
    /// - `clang_path`: Optional path to the Clang compiler. If not specified, the system Clang will be used for generating bindings,
    ///   and the system compiler (likely GCC) would be used for building the MbedTLS C code itself
    /// - `clang_sysroot_path`: Optional path to the compiler sysroot directory. If not specified, the host sysroot will be used
    /// - `clang_target`: Optional target for Clang when generating bindings. If not specified, the "TARGET" env variable target will be used
    /// - `force_esp_riscv_toolchain`: If true, and if the target is a riscv32 target, force the use of the Espressif RISCV GCC toolchain
    ///   (`riscv32-esp-elf-gcc`) rather than the derived `riscv32-unknown-elf-gcc` toolchain which is the "official" RISC-V one
    ///   (https://github.com/riscv-collab/riscv-gnu-toolchain)
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hooks: EnumSet<Hook>,
        force_clang: bool,
        crate_root_path: PathBuf,
        cmake_rust_target: Option<String>,
        cmake_host_rust_target: Option<String>,
        clang_path: Option<PathBuf>,
        clang_sysroot_path: Option<PathBuf>,
        clang_target: Option<String>,
        force_esp_riscv_gcc: bool,
    ) -> Self {
        Self {
            hooks,
            cmake_configurer: CMakeConfigurer::new(
                force_clang,
                clang_sysroot_path.clone(),
                crate_root_path.join("mbedtls"),
                cmake_rust_target,
                cmake_host_rust_target,
                force_esp_riscv_gcc,
                crate_root_path.join("gen").join("toolchain.cmake"),
            ),
            crate_root_path,
            clang_path,
            clang_sysroot_path,
            clang_target,
        }
    }

    /// Generate bindings for mbedtls-rs-sys
    ///
    /// Arguments:
    /// - `out_path`: Path to write the bindings to
    /// - `include_dirs`: Paths to the include directories relevant to MbedTLS.
    /// - `copy_file_path`: Optional path to copy the generated bindings to
    ///   (e.g. for caching or pre-generation purposes)
    pub fn generate_bindings<I>(
        &self,
        out_path: &Path,
        include_dirs: I,
        copy_file_path: Option<&Path>,
    ) -> Result<PathBuf>
    where
        I: IntoIterator,
        I::Item: AsRef<Path>,
    {
        log::info!("Generating MbedTLS bindings");

        if let Some(clang_path) = &self.clang_path {
            // For bindgen
            std::env::set_var("CLANG_PATH", clang_path);
        }

        if let Some(cmake_rust_target) = &self.cmake_configurer.cmake_rust_target {
            // Necessary for bindgen. See this:
            // https://github.com/rust-lang/rust-bindgen/blob/af7fd38d5e80514406fb6a8bba2d407d252c30b9/bindgen/lib.rs#L711
            std::env::set_var("TARGET", cmake_rust_target);
        }

        let canon = |path: &Path| {
            // TODO: Is this really necessary?
            path.display()
                .to_string()
                .replace('\\', "/")
                .replace("//?/C:", "")
        };

        // Generate the bindings using `bindgen`:
        log::info!("Generating bindings");
        let mut builder = Builder::default()
            .use_core()
            .enable_function_attribute_detection()
            .derive_debug(false)
            .derive_default(true)
            .layout_tests(false)
            .allowlist_recursively(false)
            .allowlist_item("mbedtls_.+")
            .allowlist_item("MBEDTLS_.+")
            .allowlist_item("psa_.+")
            .allowlist_item("PSA_.+")
            .header(
                self.crate_root_path
                    .join("gen")
                    .join("include")
                    .join("include.h")
                    .to_string_lossy(),
            )
            .clang_args(
                include_dirs
                    .into_iter()
                    .map(|dir| format!("-I{}", canon(dir.as_ref()))),
            );

        if self.short_enums() {
            builder = builder.clang_arg("-fshort-enums");
        }

        if let Some(sysroot_path) = self
            .clang_sysroot_path
            .clone()
            .or_else(|| self.cmake_configurer.derive_sysroot())
        {
            builder = builder.clang_args([
                &format!("-I{}", canon(&sysroot_path.join("include"))),
                &format!("--sysroot={}", canon(&sysroot_path)),
            ]);
        }

        if let Some(target) = &self.clang_target {
            builder = builder.clang_arg(format!("--target={target}"));
        }

        let bindings = builder
            .generate()
            .map_err(|_| anyhow!("Failed to generate bindings"))?;

        let bindings_file = out_path.join("bindings.rs");

        // Write out the bindings to the appropriate path:
        log::info!("Writing out bindings to: {}", bindings_file.display());
        bindings.write_to_file(&bindings_file)?;

        // Format the bindings:
        Command::new("rustfmt")
            .arg(bindings_file.to_string_lossy().to_string())
            .arg("--config")
            .arg("normalize_doc_attributes=true")
            .output()?;

        if let Some(copy_file_path) = copy_file_path {
            log::info!("Copying bindings to {}", copy_file_path.display());
            std::fs::create_dir_all(copy_file_path.parent().unwrap())?;
            std::fs::copy(&bindings_file, copy_file_path)?;
        }

        Ok(bindings_file)
    }

    /// Returns the MbedTLS user config.
    pub fn generate_user_config(&self) -> MbedtlsUserConfig {
        let mut config = MbedtlsUserConfig::new();

        config
            .set("DEPRECATED_REMOVED", true)
            .set("HAVE_TIME", false)
            .set("HAVE_TIME_DATE", false)
            .set("PLATFORM_MEMORY", true)
            // We want to provide our own Rust-backed zeroization function.
            .set("PLATFORM_ZEROIZE_ALT", true)
            .set("AES_ROM_TABLES", true)
            .set("PK_PARSE_EC_COMPRESSED", false)
            .set("GENPRIME", false)
            .set("FS_IO", false)
            .set("NO_PLATFORM_ENTROPY", true)
            .set("PSA_CRYPTO_EXTERNAL_RNG", true)
            .set("PSA_KEY_STORE_DYNAMIC", false)
            .set("SSL_KEYING_MATERIAL_EXPORT", false)
            .set("AESNI_C", false)
            .set("AESCE_C", false)
            .set("NET_C", false)
            .set("PSA_CRYPTO_STORAGE_C", false)
            .set("PSA_ITS_FILE_C", false)
            .set("SHA3_C", false)
            .set("TIMING_C", false);

        self.hooks
            .iter()
            .for_each(|hook| hook.apply_to_config(&mut config));

        config
    }

    /// Compile MbedTLS.
    ///
    /// Uses CMake to compile MbedTLS and prepares the headers for consumption
    /// by bindgen and other crates.
    /// The tricky part is the MbedTLS configuration. In a CMake-based world,
    /// MbedTLS uses "public" compile definitions to bubble up the external
    /// config file as well as other relevant configuration options.
    /// This simply doesn't work well when using Cargo. To make everyone's life
    /// easier, we manually patch up the headers after compiling MbedTLS such
    /// that no other compile definitions are necessary when consuming the
    /// generated libraries and headers.
    ///
    /// Arguments:
    /// - `out_path`: Path to write the compiled libraries to
    pub fn compile(&self, out_path: &Path, copy_path: Option<&Path>) -> Result<MbedtlsArtifacts> {
        let user_config = self.generate_user_config();
        // Write the user config to a file in the output directory so we can
        // pass it to MbedTLS during compilation.
        let user_config_path = out_path.join("mbedtls_rs_sys_user_config.h");
        user_config.write_to_path(&user_config_path)?;

        let hook_header_dir = self.crate_root_path.join("gen").join("hook");

        let target_dir = out_path.join("mbedtls").join("build");
        std::fs::create_dir_all(&target_dir)?;
        let target_include_dir = target_dir.join("include");

        let target_lib_dir = out_path.join("mbedtls").join("lib");
        let lib_dir = copy_path.unwrap_or(&target_lib_dir);
        std::fs::create_dir_all(lib_dir)?;

        // Compile MbedTLS and generate libraries to link against
        log::info!("Compiling MbedTLS with accel {:?}", self.hooks);

        let mut config = self.cmake_configurer.configure(Some(lib_dir));

        config
            .define("USE_SHARED_MBEDTLS_LIBRARY", "OFF")
            .define("USE_STATIC_MBEDTLS_LIBRARY", "ON")
            .define("ENABLE_PROGRAMS", "OFF")
            .define("ENABLE_TESTING", "OFF")
            .define("CMAKE_EXPORT_COMPILE_COMMANDS", "ON")
            // Clang will complain about some documentation formatting in mbedtls
            .define("MBEDTLS_FATAL_WARNINGS", "OFF")
            .define("MBEDTLS_USER_CONFIG_FILE", user_config_path)
            .cflag(format!("-I{}", hook_header_dir.display()))
            .profile("Release")
            .out_dir(&target_dir);

        config.build();

        // Now that MbedTLS is compiled, manually append our user config to
        // mbedtls' default config header.
        // This removes the need for specifying 'MBEDTLS_USER_CONFIG_FILE'
        // going forward.
        user_config.append_to_path(&target_include_dir.join("mbedtls/mbedtls_config.h"))?;

        Ok(MbedtlsArtifacts {
            include_dirs: vec![target_include_dir, hook_header_dir],
            libraries: lib_dir.to_path_buf(),
        })
    }

    /// Re-run the build script if the file or directory has changed.
    #[allow(unused)]
    pub fn track(file_or_dir: &Path) {
        println!("cargo::rerun-if-changed={}", file_or_dir.display())
    }

    /// A heuristics (we don't have anything better) to signal to `bindgen` whether the GCC toolchain
    /// for the target emits short enums or not.
    ///
    /// This is necessary for `bindgen` to generate correct bindings for mbedTLS.
    /// See https://github.com/rust-lang/rust-bindgen/issues/711
    fn short_enums(&self) -> bool {
        let target = std::env::var("TARGET").unwrap();

        target.ends_with("-eabi") || target.ends_with("-eabihf")
    }
}

// TODO: Move to `embuild`
#[derive(Debug, Clone)]
pub struct CMakeConfigurer {
    pub force_clang: bool,
    pub clang_sysroot_path: Option<PathBuf>,
    pub project_path: PathBuf,
    pub cmake_rust_target: Option<String>,
    pub cmake_host_rust_target: Option<String>,
    pub force_esp_riscv_gcc: bool,
    pub empty_toolchain_file: PathBuf,
}

impl CMakeConfigurer {
    /// Create a new CMakeConfigurer
    ///
    /// Arguments:
    /// - `force_clang`: If true, force the use of Clang as the C/C++ compiler
    /// - `project_path`: Path to the root of the CMake project
    /// - `cmake_rust_target`: Optional target for CMake when building MbedTLS, with Rust target-triple syntax. If not specified, the "TARGET" env variable will be used
    /// - `cmake_host_rust_target`: Optional host target for the build
    /// - `force_esp_riscv_gcc`: If true, and if the target is a riscv32 target, force the use of the Espressif RISCV GCC toolchain
    ///   (`riscv32-esp-elf-gcc`) rather than the derived `riscv32-unknown-elf-gcc` toolchain which is the "official" RISC-V one
    ///   (https://github.com/riscv-collab/riscv-gnu-toolchain)
    pub const fn new(
        force_clang: bool,
        clang_sysroot_path: Option<PathBuf>,
        project_path: PathBuf,
        cmake_rust_target: Option<String>,
        cmake_host_rust_target: Option<String>,
        force_esp_riscv_gcc: bool,
        empty_toolchain_file: PathBuf,
    ) -> Self {
        Self {
            force_clang,
            clang_sysroot_path,
            project_path,
            cmake_rust_target,
            cmake_host_rust_target,
            force_esp_riscv_gcc,
            empty_toolchain_file,
        }
    }

    pub fn configure(&self, target_dir: Option<&Path>) -> Config {
        if let Some(cmake_rust_target) = &self.cmake_rust_target {
            // For `cc-rs`
            std::env::set_var("TARGET", cmake_rust_target);
        }

        let mut config = Config::new(&self.project_path);

        config
            // ... or else the build would fail with `arm-none-eabi-gcc` when testing the compiler
            .define("CMAKE_TRY_COMPILE_TARGET_TYPE", "STATIC_LIBRARY")
            .define("CMAKE_EXPORT_COMPILE_COMMANDS", "ON")
            .define("CMAKE_BUILD_TYPE", "MinSizeRel");

        if let Some(target_dir) = target_dir {
            config
                .define("CMAKE_ARCHIVE_OUTPUT_DIRECTORY", target_dir)
                .define("CMAKE_LIBRARY_OUTPUT_DIRECTORY", target_dir)
                .define("CMAKE_RUNTIME_OUTPUT_DIRECTORY", target_dir);
        }

        if let Some((compiler, _)) = self.derive_forced_c_compiler() {
            let mut cfg = cc::Build::new();
            cfg.compiler(&compiler);

            config
                .init_c_cfg(cfg.clone())
                .init_cxx_cfg(cfg)
                .define("CMAKE_C_COMPILER", &compiler)
                .define("CMAKE_CXX_COMPILER", compiler)
                .define("CMAKE_TOOLCHAIN_FILE", &self.empty_toolchain_file);
        } else if let Some(target) = &self.cmake_rust_target {
            let mut split = target.split('-');
            let target_arch = split.next().unwrap();
            let target_os = split.next().unwrap();

            let mut target_vendor = "unknown";
            let mut target_env = split.next().unwrap();

            if let Some(next) = split.next() {
                target_vendor = target_env;
                target_env = next;
            }

            std::env::set_var("CARGO_CFG_TARGET_ARCH", target_arch);
            std::env::set_var("CARGO_CFG_TARGET_OS", target_os);
            std::env::set_var("CARGO_CFG_TARGET_VENDOR", target_vendor);
            std::env::set_var("CARGO_CFG_TARGET_ENV", target_env);
        }

        for arg in self.derive_c_args() {
            config.cflag(&arg).cxxflag(arg);
        }

        if let Some(target) = &self.cmake_rust_target {
            config.target(target);
        }

        if let Some(host) = &self.cmake_host_rust_target {
            config.host(host);
        }

        config
    }

    pub fn derive_sysroot(&self) -> Option<PathBuf> {
        if self.force_clang {
            if let Some(clang_sysroot_path) = self.clang_sysroot_path.clone() {
                // If clang is used and there is a pre-defined sysroot path for it, use it
                return Some(clang_sysroot_path);
            }
        }

        // Only GCC has a sysroot, so try to locate the sysroot using GCC first
        let unforce_clang = Self {
            force_clang: false,
            ..self.clone()
        };

        let (compiler, gnu) = unforce_clang.derive_c_compiler();

        if gnu {
            let output = Command::new(compiler).arg("-print-sysroot").output().ok()?;

            if output.status.success() {
                let sysroot = String::from_utf8(output.stdout).ok()?.trim().to_string();

                (!sysroot.is_empty()).then_some(PathBuf::from(sysroot))
            } else {
                None
            }
        } else {
            None
        }
    }

    fn derive_c_compiler(&self) -> (PathBuf, bool) {
        if let Some((compiler, gnu)) = self.derive_forced_c_compiler() {
            return (compiler, gnu);
        }

        let mut build = cc::Build::new();
        build.opt_level(0);

        if let Some(target) = self.cmake_rust_target.as_ref() {
            build.target(target);
        }

        if let Some(host) = self.cmake_host_rust_target.as_ref() {
            build.host(host);
        }

        let compiler = build.get_compiler();

        (compiler.path().to_path_buf(), compiler.is_like_gnu())
    }

    fn derive_forced_c_compiler(&self) -> Option<(PathBuf, bool)> {
        if self.force_clang {
            Some((PathBuf::from("clang"), false))
        } else {
            match self.target().as_str() {
                "xtensa-esp32-none-elf" | "xtensa-esp32-espidf" => {
                    Some((PathBuf::from("xtensa-esp32-elf-gcc"), true))
                }
                "xtensa-esp32s2-none-elf" | "xtensa-esp32s2-espidf" => {
                    Some((PathBuf::from("xtensa-esp32s2-elf-gcc"), true))
                }
                "xtensa-esp32s3-none-elf" | "xtensa-esp32s3-espidf" => {
                    Some((PathBuf::from("xtensa-esp32s3-elf-gcc"), true))
                }
                "riscv32imc-unknown-none-elf"
                | "riscv32imc-esp-espidf"
                | "riscv32imac-unknown-none-elf"
                | "riscv32imac-esp-espidf"
                | "riscv32imafc-unknown-none-elf"
                | "riscv32imafc-esp-espidf" => {
                    if self.force_esp_riscv_gcc {
                        Some((PathBuf::from("riscv32-esp-elf-gcc"), true))
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }
    }

    fn derive_c_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        args.extend(
            self.derive_c_target_args()
                .iter()
                .map(|arg| arg.to_string()),
        );

        if self.force_clang {
            if let Some(sysroot_path) = self.derive_sysroot() {
                args.push("-fbuiltin".to_string());
                args.push(format!("-I{}", sysroot_path.join("include").display()));
                args.push(format!("--sysroot={}", sysroot_path.display()));
            }
        }

        args
    }

    fn derive_c_target_args(&self) -> &[&str] {
        if self.force_clang {
            match self.target().as_str() {
                "riscv32imc-unknown-none-elf" | "riscv32imc-esp-espidf" => {
                    &["--target=riscv32-esp-elf", "-march=rv32imc", "-mabi=ilp32"]
                }
                "riscv32imac-unknown-none-elf" | "riscv32imac-esp-espidf" => {
                    &["--target=riscv32-esp-elf", "-march=rv32imac", "-mabi=ilp32"]
                }
                "riscv32imafc-unknown-none-elf" | "riscv32imafc-esp-espidf" => &[
                    "--target=riscv32-esp-elf",
                    "-march=rv32imafc",
                    "-mabi=ilp32",
                ],
                "xtensa-esp32-none-elf" | "xtensa-esp32-espidf" => {
                    &["--target=xtensa-esp-elf", "-mcpu=esp32"]
                }
                "xtensa-esp32s2-none-elf" | "xtensa-esp32s2-espidf" => {
                    &["--target=xtensa-esp-elf", "-mcpu=esp32s2"]
                }
                "xtensa-esp32s3-none-elf" | "xtensa-esp32s3-espidf" => {
                    &["--target=xtensa-esp-elf", "-mcpu=esp32s3"]
                }
                _ => &[],
            }
        } else {
            match self.target().as_str() {
                "riscv32imc-unknown-none-elf" | "riscv32imc-esp-espidf" => {
                    &["-march=rv32imc", "-mabi=ilp32"]
                }
                "riscv32imac-unknown-none-elf" | "riscv32imac-esp-espidf" => {
                    &["-march=rv32imac", "-mabi=ilp32"]
                }
                "riscv32imafc-unknown-none-elf" | "riscv32imafc-esp-espidf" => {
                    &["-march=rv32imafc", "-mabi=ilp32"]
                }
                "xtensa-esp32-none-elf" | "xtensa-esp32-espidf" => &["-mlongcalls"],
                "xtensa-esp32s2-none-elf" | "xtensa-esp32s2-espidf" => &["-mlongcalls"],
                "xtensa-esp32s3-none-elf" | "xtensa-esp32s3-espidf" => &["-mlongcalls"],
                _ => &[],
            }
        }
    }

    fn target(&self) -> String {
        self.cmake_rust_target
            .clone()
            .unwrap_or_else(|| std::env::var("TARGET").unwrap().to_string())
    }
}
