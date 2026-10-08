//! Example of a TLS client whose trust comes from a verify callback
//! instead of a parsed `ca_chain`.
//!
//! The trust store (in `common/ca_bundle.rs`) is a flash-resident CA
//! bundle in esp-idf's `x509_crt_bundle` binary format: only each root's
//! subject Name and SubjectPublicKeyInfo, with an offset index, so the
//! handshake binary-searches roots directly in the bundle and parses only
//! the one key the peer chain needs. The sample verification callback
//! decides which roots are trusted, while MbedTLS still runs the standard
//! chain and hostname verification.
//!
//! This example connects to `https://httpbin.org/ip` and performs a simple
//! HTTPS 1.0 GET request.

use std::net::{TcpStream, ToSocketAddrs};

use embedded_io_adapters::std::FromStd;

use mbedtls_rs::blocking::io::Write;
use mbedtls_rs::blocking::Session;
use mbedtls_rs::{ClientSessionConfig, SessionConfig, Tls};

use log::info;

#[path = "../bootstrap.rs"]
mod bootstrap;
#[path = "../../../common/ca_bundle.rs"]
mod ca_bundle;
#[path = "../../../common/std_rng.rs"]
mod rng;

/// The roots the callback trusts: the full Mozilla set (see
/// `examples/common/certs/README.md` for how it is generated) as a
/// flash-resident bundle.
const ROOT_CA: &[u8] = include_bytes!("../../../common/certs/ca-bundle.bin");

fn main() {
    bootstrap::bootstrap();

    info!("Initializing TLS");

    let mut rng = rng::StdRng;
    // SAFETY: `rng` is declared before `tls` and outlives it; `tls` is dropped
    // at the end of this scope and never leaked, so the borrow stays valid for
    // the whole lifetime of the global RNG slot.
    let mut tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();

    tls.set_debug(1);

    info!("Validating the flash-resident CA bundle");

    // A pure validation pass over the bundle's headers; nothing is copied
    // or parsed. Declared before the session: the callback reaches it
    // through `p_ctx`, and the session is dropped first.
    let ca_bundle = ca_bundle::CaBundle::new(ROOT_CA).unwrap();

    let server_name = c"httpbin.org";

    info!("Resolving server {}", server_name.to_str().unwrap());

    let socket_addr = format!("{}:443", server_name.to_str().unwrap())
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    info!("Using socket addr {}", socket_addr);

    info!("Creating TCP connection");

    let socket = TcpStream::connect(socket_addr).unwrap();

    info!("Creating TLS session");

    let conf = SessionConfig::Client(ClientSessionConfig {
        verify_callback: Some(ca_bundle.verify_callback()),
        server_name: Some(server_name),
        ..ClientSessionConfig::new()
    });

    let mut session = Session::new(tls.reference(), FromStd::new(socket), &conf).unwrap();

    info!("Requesting GET /ip from server");

    session.write_all(b"GET /ip HTTP/1.0\r\nHost: ").unwrap();
    session.write_all(server_name.to_bytes()).unwrap();
    session.write_all(b"\r\n\r\n").unwrap();

    info!("Reading response\nHTTP RESPONSE START >>>>>>>>");

    let mut buf = [0u8; 1024];
    loop {
        let len = session.read(&mut buf).unwrap();
        if len == 0 {
            break;
        }

        info!("{}", core::str::from_utf8(&buf[..len]).unwrap_or("???"));
    }

    info!("\nHTTP RESPONSE END <<<<<<<<");

    session.close().unwrap();

    info!("Done");
}
