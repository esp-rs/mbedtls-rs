use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Result};
use bindgen::Builder;
use cmake::Config;
use enumset::{EnumSet, EnumSetType};

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
    pub fn generate_bindings(
        &self,
        out_path: &Path,
        copy_file_path: Option<&Path>,
    ) -> Result<PathBuf> {
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
            .blocklist_function("strtold")
            .blocklist_function("_strtold_r")
            .blocklist_function("v.*printf")
            .blocklist_function("v.*scanf")
            .blocklist_function("_v.*printf_r")
            .blocklist_function("_v.*scanf_r")
            .blocklist_function("q.*cvt")
            .blocklist_function("q.*cvt_r")
            .header(
                self.crate_root_path
                    .join("gen")
                    .join("include")
                    .join("include.h")
                    .to_string_lossy(),
            )
            .clang_args([
                &format!(
                    "-I{}",
                    canon(&self.crate_root_path.join("mbedtls").join("include"))
                ),
                &format!(
                    "-I{}",
                    canon(&self.crate_root_path.join("gen").join("include"))
                ),
            ]);

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

        for hook in self.hooks {
            let def = self.hook_def(hook);

            builder = builder.clang_arg(format!("-D{def}"));

            if let Some(size_def) = self.hook_work_area_size_def(hook) {
                builder = builder.clang_arg(format!("-D{def}_WORK_AREA_SIZE={size_def}"));
            }
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

    /// Compile mbedtls
    ///
    /// Arguments:
    /// - `out_path`: Path to write the compiled libraries to
    pub fn compile(&self, out_path: &Path, copy_path: Option<&Path>) -> Result<PathBuf> {
        let target_dir = out_path.join("mbedtls").join("build");
        std::fs::create_dir_all(&target_dir)?;

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
            .define(
                "MBEDTLS_CONFIG_FILE",
                self.crate_root_path
                    .join("gen")
                    .join("include")
                    .join("config.h"),
            )
            .cflag(format!(
                "-I{}",
                self.crate_root_path.join("gen").join("include").display()
            ))
            .cflag("-DMBEDTLS_CONFIG_FILE='<config.h>'")
            .cxxflag("-DMBEDTLS_CONFIG_FILE='<config.h>'")
            .profile("Release")
            .out_dir(&target_dir);

        for hook in self.hooks {
            let def = self.hook_def(hook);

            config.cflag(format!("-D{def}")).cxxflag(format!("-D{def}"));

            if let Some(size_def) = self.hook_work_area_size_def(hook) {
                config
                    .cflag(format!("-D{def}_WORK_AREA_SIZE={size_def}"))
                    .cxxflag(format!("-D{def}_WORK_AREA_SIZE={size_def}"));
            }
        }

        config.build();

        Ok(lib_dir.to_path_buf())
    }

    /// Re-run the build script if the file or directory has changed.
    #[allow(unused)]
    pub fn track(file_or_dir: &Path) {
        println!("cargo::rerun-if-changed={}", file_or_dir.display())
    }

    fn hook_def(&self, hook: Hook) -> &'static str {
        match hook {
            Hook::Sha1 => "MBEDTLS_SHA1_ALT",
            Hook::Sha256 => "MBEDTLS_SHA256_ALT",
            Hook::Sha512 => "MBEDTLS_SHA512_ALT",
            Hook::ExpMod => "MBEDTLS_MPI_EXP_MOD_ALT_FALLBACK",
        }
    }

    fn hook_work_area_size_def(&self, hook: Hook) -> Option<usize> {
        match hook {
            Hook::Sha1 => Some(208),
            Hook::Sha256 => Some(208),
            Hook::Sha512 => Some(304),
            _ => None,
        }
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
