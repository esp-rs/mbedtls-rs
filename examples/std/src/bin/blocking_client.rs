//! Example of a client connection to a server, using the blocking API.
//!
//! This example connects to `https://httpbin.org/ip` and then to `https://certauth.cryptomix.com/json/` (mTLS)
//! and performs a simple HTTPS 1.0 GET request to each.

use std::net::{TcpStream, ToSocketAddrs};

use embedded_io_adapters::std::FromStd;

use mbedtls_rs::Tls;

use log::info;

#[path = "../bootstrap.rs"]
mod bootstrap;
#[path = "../../../common/blocking_client.rs"]
mod client;
#[path = "../../../common/std_rng.rs"]
mod rng;

fn main() {
    bootstrap::bootstrap();

    info!("Initializing TLS");

    let mut rng = rng::StdRng;
    // SAFETY: `rng` is declared before `tls` and outlives it; `tls` is dropped
    // at the end of this scope and never leaked, so the borrow stays valid for
    // the whole lifetime of the global RNG slot.
    let mut tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();

    tls.set_debug(1);

    for (index, (server_name_cstr, server_path, mtls)) in [
        (c"httpbin.org", "/ip", false),
        (c"certauth.cryptomix.com", "/json/", true),
    ]
    .into_iter()
    .enumerate()
    {
        let server_name = server_name_cstr.to_str().unwrap();

        info!(
            "\n\n\n\nREQUEST {}, MTLS: {} =============================",
            index, mtls
        );

        info!("Resolving server {}", server_name);

        let socket_addr = format!("{}:443", server_name)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();

        info!("Using socket addr {}", socket_addr);

        info!("Creating TCP connection");

        let socket = TcpStream::connect(socket_addr).unwrap();

        let mut buf = [0u8; 1024];

        client::request(
            tls.reference(),
            FromStd::new(socket),
            server_name_cstr,
            server_path,
            mtls,
            &mut buf,
        )
        .unwrap();
    }
}
