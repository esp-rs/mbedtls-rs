//! Example demonstrating certificate time validation using the async API.
//!
//! This example connects to `https://httpbin.org/ip` twice to verify that:
//! 1. Certificate validation succeeds with correct time
//! 2. Certificate validation fails when time is manipulated (simulating an expired certificate)

#![no_std]
#![no_main]
#![recursion_limit = "256"]

use core::net::SocketAddr;

use embassy_executor::Spawner;

use embassy_net::tcp::TcpSocket;
use embassy_net::StackResources;

use esp_alloc::heap_allocator;
use esp_backtrace as _;

use log::info;

use tinyrlibc as _;

use crate::bootstrap::RECLAIMED_RAM;

#[path = "../bootstrap.rs"]
mod bootstrap;
#[path = "../../../common/client.rs"]
mod client;

const HEAP_SIZE: usize = 140 * 1024;

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    heap_allocator!(size: HEAP_SIZE - RECLAIMED_RAM);

    let stack_resources = mk_static!(StackResources<3>, StackResources::new());

    let (mut tls, stack, mut accel, rtc) =
        bootstrap::bootstrap_stack(spawner, stack_resources).await;

    tls.set_debug(1);

    let _accel_queue = accel.start();

    for (index, (server_name_cstr, server_path, expired_cert)) in [
        (c"httpbin.org", "/ip", false),
        (c"httpbin.org", "/ip", true),
    ]
    .into_iter()
    .enumerate()
    {
        let server_name = server_name_cstr.to_str().unwrap();

        info!(
            "\n\n\n\nREQUEST {}, EXPIRED_CERT: {} =============================",
            index, expired_cert
        );

        if expired_cert {
            // double current time to cause certificate validation to fail
            rtc.set_current_time_us(rtc.current_time_us() * 2);
        }

        info!("Resolving server {}", server_name);

        let ip = *stack
            .dns_query(server_name, embassy_net::dns::DnsQueryType::A)
            .await
            .unwrap()
            .iter()
            .next()
            .unwrap();

        info!("Using IP addr {}", ip);

        info!("Creating TCP connection");

        let mut rx_buf = [0; 1024];
        let mut tx_buf = [0; 1024];

        let mut socket = TcpSocket::new(stack, &mut rx_buf, &mut tx_buf);

        //socket.set_timeout(Some(Duration::from_secs(10)));
        socket
            .connect(SocketAddr::new(ip.into(), 443))
            .await
            .unwrap();

        let mut buf = [0u8; 1024];

        match client::request(
            tls.reference(),
            socket,
            server_name_cstr,
            server_path,
            false,
            &mut buf,
        )
        .await
        {
            Ok(()) => {
                if expired_cert {
                    panic!("request should have failed with failed certificate validation");
                }
            }
            Err(e) => {
                if !expired_cert {
                    panic!("request should have succeeded: {}", e);
                }
            }
        }
    }
}
