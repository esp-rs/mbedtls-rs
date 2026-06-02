#![no_std]
#![no_main]
#![recursion_limit = "256"]

use embassy_executor::Spawner;

use esp_alloc::heap_allocator;

use esp_backtrace as _;

use esp_hal::ram;
use esp_hal::sha::ShaBackend;
use esp_hal::timer::timg::TimerGroup;

use esp_metadata_generated::memory_range;

use log::{error, info};

use tinyrlibc as _;

extern crate alloc;

const HEAP_SIZE: usize = 140 * 1024;

const RECLAIMED_RAM: usize =
    memory_range!("DRAM2_UNINIT").end - memory_range!("DRAM2_UNINIT").start;

esp_bootloader_esp_idf::esp_app_desc!();

#[esp_rtos::main]
async fn main(_s: Spawner) {
    esp_println::logger::init_logger(log::LevelFilter::Info);

    info!("Starting...");

    heap_allocator!(size: HEAP_SIZE - RECLAIMED_RAM);
    heap_allocator!(#[ram(reclaimed)] size: RECLAIMED_RAM);

    let peripherals = esp_hal::init(esp_hal::Config::default());

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(
        timg0.timer0,
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT)
            .software_interrupt0,
    );

    let mut sha = ShaBackend::new(peripherals.SHA);
    let _sha_backend = sha.start();

    let mut hw_result = [0u8; 20];
    let mut sw_result = [0u8; 20];

    let data: &[&str] = &[
        "hello world",
        "The quick brown fox jumps over the lazy dog",
        "sderjgrwrt;klhngfh;kf;lkjfgbmsd'mstrklshjrwssderjgrwrt;klhngfh;kf;lkjfgbmsd'mstrklshjrwssderjgrwrt;klhngfh;kf;lkjfgbmsd'mstrklshjrwssderjgrwrt;klhngfh;kf;lkjfgbmsd'mstrklshjrwssderjgrwrt;klhngfh;kf;lkjfgbmsd'mstrklshjrwssderjgrwrt;klhngfh;kf;lkjfgbmsd'mstrklshjrws",
    ];

    for input in data {
        info!("============\nInput: {:x?}", input);

        {
            use sha1::Digest;

            let mut sha1 = esp_hal::sha::Sha1Context::new();

            Digest::update(&mut sha1, input.as_bytes());

            hw_result.copy_from_slice(&sha1.finalize());
        }
        {
            use sha1::Digest;

            let mut sha1 = sha1::Sha1::new();

            Digest::update(&mut sha1, input.as_bytes());

            sw_result.copy_from_slice(&sha1.finalize());
        }

        info!("SW SHA-1 = {:x?}", sw_result);
        info!("HW SHA-1 = {:x?}", hw_result);

        if hw_result != sw_result {
            error!("HW/SW SHA-1 mismatch!");
        } else {
            info!("HW/SW SHA-1 match.");
        }
    }
}
