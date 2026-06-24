use std::option::Option;
use std::path::{Path, PathBuf};
use std::process::Command;

use self::config::{MbedtlsUserConfig, Value};
use anyhow::{anyhow, Result};
use bindgen::Builder;
use cmake::Config;
use enumset::{enum_set, EnumSet, EnumSetType};

// This set MUST contain all opt-out hooks
pub const DEFAULT_HOOKS: EnumSet<Hook> =
    enum_set!(Hook::Sha1 | Hook::Sha256 | Hook::Sha512 | Hook::ExpMod);

mod config;
#[path = "features.rs"]
pub mod features;

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
    /// Timer support
    Timer,
    /// Wall clock support
    WallClock,
}

impl Hook {
    const fn work_area_size(self) -> Option<usize> {
        match self {
            Self::Sha1 => Some(208),
            Self::Sha256 => Some(208),
            Self::Sha512 => Some(304),
            Self::ExpMod => None,
            Self::Timer => None,
            Self::WallClock => None,
        }
    }

    /// Returns the config identifier corresponding to this hook.
    const fn config_ident(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1_ALT",
            Self::Sha256 => "SHA256_ALT",
            Self::Sha512 => "SHA512_ALT",
            Self::ExpMod => "MPI_EXP_MOD_ALT_FALLBACK",
            Self::Timer => "HAVE_TIME",
            Self::WallClock => "HAVE_TIME_DATE",
        }
    }

    /// Returns extra config options and values required for the hook the function properly.
    fn extra_options(self) -> Option<Vec<(&'static str, Value)>> {
        match self {
            Self::Sha1 | Self::Sha256 | Self::Sha512 | Self::ExpMod => None,
            Self::Timer => Some(vec![
                // using a mbedtls prefix to ensure we don't have conflicting 'time' symbols on std
                ("PLATFORM_STD_TIME", Value::from("mbedtls_sec_time")),
                // required to set MBEDTLS_PLATFORM_STD_TIME
                ("PLATFORM_TIME_ALT", Value::from(true)),
                ("PLATFORM_MS_TIME_ALT", Value::from(true)),
            ]),
            Self::WallClock => Some(vec![("PLATFORM_GMTIME_R_ALT", Value::from(true))]),
        }
    }

    /// Returns extra header files to include in the user config for this hook.
    const fn includes(self) -> Option<&'static [&'static str]> {
        match self {
            // Unlike crypto alts, platform_time.h has no _alt.h inclusion mechanism
            Hook::Timer => Some(&["time_alt.h"]),
            _ => None,
        }
    }

    fn apply_to_config(self, config: &mut MbedtlsUserConfig) {
        config.set(self.config_ident(), true);

        if let Some(extra_idents) = self.extra_options() {
            for entries in extra_idents {
                config.set(entries.0, entries.1);
            }
        }

        if let Some(includes) = self.includes() {
            for include in includes {
                config.add_include(include);
            }
        }

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

        if self.hooks.contains(Hook::Timer) {
            builder = builder
                .allowlist_item("time_t")
                .allowlist_item("__int_least64_t")
                .allowlist_item("__int64_t");
        }

        if self.hooks.contains(Hook::WallClock) {
            builder = builder.allowlist_item("tm");
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

        // Additive, feature-driven algorithm/module selection: `#undef` the
        // whole optional universe, then re-`#define` per enabled cargo feature.
        // See `features.rs` for the rationale (runtime cipher/digest dispatch
        // tables defeat `--gc-sections`, so unused algos must be compiled out).
        features::apply_features(&mut config);

        self.hooks
            .iter()
            .for_each(|hook| hook.apply_to_config(&mut config));

        config
    }

    /// The config the committed prebuilt libraries/bindings were produced with:
    /// the [`features::PREBUILT_FEATURES`] algorithm set plus [`DEFAULT_HOOKS`].
    fn prebuilt_config() -> MbedtlsUserConfig {
        let mut config = features::prebuilt_features_config();
        DEFAULT_HOOKS
            .iter()
            .for_each(|hook| hook.apply_to_config(&mut config));
        config
    }

    /// Decide whether the committed prebuilt libraries and bindings are valid
    /// for the given active features (read from `CARGO_FEATURE_*`) and `hooks`.
    ///
    /// Returns `Ok(())` if the active config is byte-for-byte equivalent to the
    /// prebuilt config (so the `.a` and bindings can be used as-is), or
    /// `Err(delta)` describing how they differ (so the caller can rebuild on the
    /// fly and explain why). This is exact in both directions: any added option
    /// (e.g. `kex-ecjpake` on top of `tls`), any removed option (a trimmed
    /// profile), or any hook change rejects the prebuilt artifacts.
    ///
    /// Takes `hooks` directly so the build script can call it before
    /// constructing a full [`MbedtlsBuilder`].
    pub fn prebuilt_validity(hooks: EnumSet<Hook>) -> Result<(), String> {
        let mut active = MbedtlsUserConfig::new();
        features::apply_features(&mut active);
        hooks
            .iter()
            .for_each(|hook| hook.apply_to_config(&mut active));

        let prebuilt = Self::prebuilt_config();
        let delta = active.effective_delta(&prebuilt);
        if delta.is_empty() {
            Ok(())
        } else {
            Err(delta)
        }
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
    /// - `out_path`: Path to use as a scratch space during building.
    /// - `copy_path`: Optional path to copy the generated libraries to (e.g. for caching or pre-generation purposes).
    ///   If not specified, the libraries will be placed in the output directory.
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
            .profile("MinSizeRel")
            .out_dir(&target_dir)
            // The `cmake` crate defaults to running `cmake --build . --target install`.
            // mbedtls' install target writes pkg-config files, CMake helpers, and
            // 3rdparty (everest/p256m) artifacts into the install prefix. Some host
            // setups (notably the rs-matter integration runners) fail during that
            // step. We harvest the build outputs directly from `target_dir` via the
            // CMAKE_*_OUTPUT_DIRECTORY defines, so the install target is unnecessary.
            .no_build_target(true);

        config.build();

        // Now that MbedTLS is compiled, materialize a writable copy of the
        // upstream `mbedtls_config.h` and append our user config to it.
        // This removes the need for specifying 'MBEDTLS_USER_CONFIG_FILE'
        // going forward.
        //
        // Since we skip the install target (see `.no_build_target(true)` above),
        // we seed the file from the upstream submodule headers and place it in
        // a dedicated scratch include dir that will shadow the upstream one via
        // include-search order.
        let upstream_include_dir = self.crate_root_path.join("mbedtls").join("include");
        let target_mbedtls_include_dir = target_include_dir.join("mbedtls");
        std::fs::create_dir_all(&target_mbedtls_include_dir)?;
        let target_config_file = target_mbedtls_include_dir.join("mbedtls_config.h");
        std::fs::copy(
            upstream_include_dir
                .join("mbedtls")
                .join("mbedtls_config.h"),
            &target_config_file,
        )?;
        user_config.append_to_path(&target_config_file)?;

        if let Some(copy_path) = copy_path {
            // If a copy path is specified, also copy the generated config header there.
            let include_dir = copy_path.join("include").join("mbedtls");
            std::fs::create_dir_all(&include_dir)?;
            std::fs::copy(&target_config_file, include_dir.join("mbedtls_config.h"))?;
        }

        Ok(MbedtlsArtifacts {
            include_dirs: vec![target_include_dir, upstream_include_dir, hook_header_dir],
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
            // MbedTLS's CMake build runs Python helper scripts (e.g. to locate the
            // `framework` directory). Python writes `__pycache__/*.pyc` caches next
            // to those scripts, i.e. inside the crate source tree. `cargo publish`
            // verifies the extracted package was not modified by build.rs and aborts
            // when it finds those stray `.pyc` files, so disable bytecode caching.
            .env("PYTHONDONTWRITEBYTECODE", "1")
            // ... or else the build would fail with `arm-none-eabi-gcc` when testing the compiler
            .define("CMAKE_TRY_COMPILE_TARGET_TYPE", "STATIC_LIBRARY")
            .define("CMAKE_EXPORT_COMPILE_COMMANDS", "ON")
            .define("CMAKE_BUILD_TYPE", "MinSizeRel");

        if let Some(target_dir) = target_dir {
            config
                .define("CMAKE_ARCHIVE_OUTPUT_DIRECTORY", target_dir)
                .define("CMAKE_LIBRARY_OUTPUT_DIRECTORY", target_dir)
                .define("CMAKE_RUNTIME_OUTPUT_DIRECTORY", target_dir)
                // Multi-config generators (Ninja Multi-Config, Visual Studio, Xcode)
                // ignore `CMAKE_BUILD_TYPE` and the unsuffixed *_OUTPUT_DIRECTORY
                // vars at build time. Restrict the generated configs to
                // `MinSizeRel` (matching the single-config `CMAKE_BUILD_TYPE`
                // above and `compile()`'s `.profile("MinSizeRel")`) and pin the
                // per-config output dirs to `target_dir` so the build script can
                // locate the produced static libs.
                .define("CMAKE_CONFIGURATION_TYPES", "MinSizeRel")
                .define("CMAKE_ARCHIVE_OUTPUT_DIRECTORY_MINSIZEREL", target_dir)
                .define("CMAKE_LIBRARY_OUTPUT_DIRECTORY_MINSIZEREL", target_dir)
                .define("CMAKE_RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL", target_dir);
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
            let output = Command::new(&compiler)
                .arg("-print-sysroot")
                .output()
                .ok()?;

            if output.status.success() {
                let sysroot = String::from_utf8(output.stdout).ok()?.trim().to_string();

                if !sysroot.is_empty() {
                    return Some(PathBuf::from(sysroot));
                }
            }

            // Some packaged GCC cross-toolchains (e.g. PlatformIO's
            // `toolchain-riscv32-esp` / `toolchain-xtensa-esp32s3`, both based
            // on crosstool-NG esp-2021r2-patch5 / GCC 8.4.0) print an empty
            // string for `-print-sysroot` even though the sysroot is present
            // on disk. Fall back to deriving the prefix from
            // `-print-search-dirs` (the `install:` line points at
            // `<prefix>/lib/gcc/<triple>/<version>/`) and then joining the
            // target triple.
            let install_dir = Command::new(compiler)
                .arg("-print-search-dirs")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with("install:"))
                        .map(|l| PathBuf::from(l.trim_start_matches("install:").trim()))
                });

            if let Some(install_dir) = install_dir {
                // install_dir = <prefix>/lib/gcc/<triple>/<version>/
                // Walk up 4 levels (version -> triple -> gcc -> lib) to recover <prefix>.
                if let Some(prefix) = install_dir
                    .parent() // <version>
                    .and_then(|p| p.parent()) // <triple>
                    .and_then(|p| p.parent()) // gcc
                    .and_then(|p| p.parent())
                // lib  ->  <prefix>
                {
                    if let Some(triple) = self.derive_gcc_target_triple() {
                        // Two common layouts:
                        //   - crosstool-NG / PlatformIO (ESP toolchains):
                        //       `<prefix>/<triple>/include/`
                        //   - Debian / Ubuntu native packaging of
                        //     `gcc-arm-none-eabi`:
                        //       `<prefix>/lib/<triple>/include/`
                        // Probe each in turn, accept the first whose
                        // `include/stdio.h` exists.
                        for candidate in [prefix.join(triple), prefix.join("lib").join(triple)] {
                            if candidate.join("include").join("stdio.h").exists() {
                                return Some(candidate);
                            }
                        }
                    }
                }
            }

            None
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
            Some((
                std::env::var_os("CLANG_PATH")
                    .filter(|path| !path.is_empty())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("clang")),
                false,
            ))
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

    /// Returns the GCC cross-toolchain triple for ESP cross targets, mirroring
    /// the compiler binary names in `derive_forced_c_compiler`. Returns `None`
    /// for host GCC or any target where no fixed cross-triple is known
    /// (e.g. unforced RISC-V, where `cc-rs` selects the compiler).
    fn derive_gcc_target_triple(&self) -> Option<&'static str> {
        match self.target().as_str() {
            "xtensa-esp32-none-elf" | "xtensa-esp32-espidf" => Some("xtensa-esp32-elf"),
            "xtensa-esp32s2-none-elf" | "xtensa-esp32s2-espidf" => Some("xtensa-esp32s2-elf"),
            "xtensa-esp32s3-none-elf" | "xtensa-esp32s3-espidf" => Some("xtensa-esp32s3-elf"),
            "riscv32imc-unknown-none-elf"
            | "riscv32imc-esp-espidf"
            | "riscv32imac-unknown-none-elf"
            | "riscv32imac-esp-espidf"
            | "riscv32imafc-unknown-none-elf"
            | "riscv32imafc-esp-espidf"
                if self.force_esp_riscv_gcc =>
            {
                Some("riscv32-esp-elf")
            }
            // ARM bare-metal Rust targets all map to the same `arm-none-eabi`
            // GCC cross-toolchain (Cortex-M architecture is selected via
            // `-mcpu` / `-march` flags, not via separate compilers).
            "thumbv6m-none-eabi"
            | "thumbv7m-none-eabi"
            | "thumbv7em-none-eabi"
            | "thumbv7em-none-eabihf"
            | "thumbv8m.base-none-eabi"
            | "thumbv8m.main-none-eabi"
            | "thumbv8m.main-none-eabihf" => Some("arm-none-eabi"),
            _ => None,
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
