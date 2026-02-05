//! Example of a client connection to a server, using the `edge-nal` support in `mbedtls-rs`.
//!
//! This example connects to `https://httpbin.org/ip` and then to `https://certauth.cryptomix.com/json/` (mTLS)
//! and performs a simple HTTPS 1.1 GET request to each.

#![no_std]
#![no_main]
#![recursion_limit = "256"]

use edge_nal_embassy::{Dns, Tcp, TcpBuffers};

use embassy_executor::Spawner;

use embassy_net::StackResources;

use esp_alloc::heap_allocator;
use esp_backtrace as _;

use log::info;

use tinyrlibc as _;

use crate::bootstrap::RECLAIMED_RAM;

#[path = "../bootstrap.rs"]
mod bootstrap;
#[path = "../../../common/edge_client.rs"]
mod client;

const HEAP_SIZE: usize = 140 * 1024;

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    heap_allocator!(size: HEAP_SIZE - RECLAIMED_RAM);

    let stack_resources = mk_static!(StackResources<3>, StackResources::new());

    let (mut tls, stack, mut accel, ..) =
        bootstrap::bootstrap_stack(spawner, stack_resources).await;

    tls.set_debug(1);

    let _accel_queue = accel.start();

    let tcp_buffers = mk_static!(TcpBuffers<2, 1024, 1024>, TcpBuffers::new());

    let dns = Dns::new(stack);
    let tcp = Tcp::new(stack, tcp_buffers);

    for (index, (server_name_cstr, server_path, mtls)) in [
        (c"httpbin.org", "/ip", false),
        (c"certauth.cryptomix.com", "/json/", true),
    ]
    .into_iter()
    .enumerate()
    {
        info!(
            "\n\n\n\nREQUEST {}, MTLS: {} =============================",
            index, mtls
        );

        client::request(
            &tls,
            tcp,
            dns,
            &mut [0; 4096],
            server_name_cstr,
            server_path,
            mtls,
        )
        .await;
    }
}
