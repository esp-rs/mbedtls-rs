//! Raw bindings to the MbedTLS library.
//!
//! # External dependencies
//!
//! MbedTLS depends on the following functions from the C standard library:
//!
//! - `calloc`
//! - `free`
//! - `memchr`
//! - `memcmp`
//! - `memcpy`
//! - `memmove`
//! - `memset`
//! - `printf`
//! - `putchar`
//! - `puts`
//! - `rand`
//! - `snprintf`
//! - `strchr`
//! - `strcmp`
//! - `strlen`
//! - `strncmp`
//! - `strncpy`
//! - `strstr`
//! - `vsnprintf`
//!
//! This crate does not provide implementations of these functions. It's up to
//! the consumer to ensure that they are available at link time. On most
//! platforms, these functions are provided by the host environment's libc
//! implementation, so no additional work is needed.
//! On embedded platforms, you may need to link a suitable libc implementation
//! like [tinyrlibc](https://github.com/rust-embedded-community/tinyrlibc).
//!
//! Note that depending on what features of MbedTLS you use, you won't need
//! all of these functions. The list represents the full set of functions that
//! MbedTLS may call.
//! The linker error messages will indicate which specific functions are
//! missing, so you can focus on providing those first.
//!
//! Additionally, the following list of MbedTLS functions are left
//! unimplemented in this crate:
//!
//! - `mbedtls_platform_zeroize`
//! - `mbedtls_psa_external_get_random`
//!
//! These functions are provided by `mbedtls-rs`. If you're building C code
//! that depends on MbedTLS, make sure to link against `mbedtls-rs` to get
//! these implementations.

#![no_std]
#![allow(clippy::uninlined_format_args)]
#![allow(
    rustdoc::bare_urls,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_html_tags,
    rustdoc::invalid_rust_codeblocks,
    reason = "Documentation is generated from the C header files"
)]
#![allow(unknown_lints)]

pub use bindings::*;
pub use error::*;

pub(crate) mod fmt;

mod error;
#[cfg(not(target_os = "espidf"))]
mod extra_impls; // TODO: Figure out if we still need this

#[cfg(not(target_os = "espidf"))]
pub mod accel;
#[cfg(not(target_os = "espidf"))]
pub mod hook;
pub mod self_test;

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    unnecessary_transmutes,
    clippy::all
)]
mod bindings {
    #[cfg(not(target_os = "espidf"))]
    include!(env!("MBEDTLS_RS_SYS_BINDINGS_FILE"));

    #[cfg(target_os = "espidf")]
    pub use esp_idf_sys::*;
}
