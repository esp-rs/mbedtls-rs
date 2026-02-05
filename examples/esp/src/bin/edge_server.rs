//! Example of an HTTPS server, using the `edge-nal` support in `mbedtls-rs`.
//!
//! This example runs a simple HTTPS server that answers with a fixed text message to all HTTP GET / requests.
//!
//! Since the server certificates are self-signed, the easiest way to test is with:
//! ```sh
//! curl -k https://<ip-printed-by-this-example>/
//! ```
//!
//! Alternatively, accept the self-signed certificate warning in the browser.

#![no_std]
#![no_main]
#![recursion_limit = "256"]

use edge_http::io::server::Server;

use edge_nal_embassy::{Tcp, TcpBuffers};

use embassy_executor::Spawner;

use embassy_net::StackResources;

use esp_alloc::heap_allocator;
use esp_backtrace as _;

use tinyrlibc as _;

use crate::bootstrap::RECLAIMED_RAM;

#[path = "../bootstrap.rs"]
mod bootstrap;
#[path = "../../../common/edge_server.rs"]
mod server;

const HEAP_SIZE: usize = 160 * 1024;

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    heap_allocator!(size: HEAP_SIZE - RECLAIMED_RAM);

    let stack_resources = mk_static!(StackResources<4>, StackResources::new());

    let (mut tls, stack, mut accel, ..) =
        bootstrap::bootstrap_stack(spawner, stack_resources).await;

    tls.set_debug(1);

    let _accel_queue = accel.start();

    let tcp_buffers = mk_static!(TcpBuffers<2, 1024, 1024>, TcpBuffers::new());

    let tcp = Tcp::new(stack, tcp_buffers);

    server::run(&tls, tcp, &mut Server::<2, 2048, 32>::new(), 443).await;
}
