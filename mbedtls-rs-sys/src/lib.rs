//! Raw bindings to the MbedTLS library.
//!
//! # Usage by other FFI crates
//!
//! FFI crates that link C libraries which in turn depend on MbedTLS can use
//! this crate for their build process.
//! This crate exposes the `include` metadata key, which contains a list of
//! include directories relevant to MbedTLS. Use [`std::env::split_paths`] when
//! parsing this metadata key, and pass the resulting paths to the C compiler.

#![no_std]
#![allow(clippy::uninlined_format_args)]
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
