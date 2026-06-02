//! Print target-specific alignments of the primitive types

#![no_std]
#![no_main]

use embassy_executor::Spawner;

use esp_alloc as _;

use esp_backtrace as _;

use esp_hal::timer::timg::TimerGroup;

#[path = "../../../common/alignment.rs"]
mod alignment;

esp_bootloader_esp_idf::esp_app_desc!();

#[esp_rtos::main]
async fn main(_s: Spawner) {
    esp_println::logger::init_logger(log::LevelFilter::Info);

    let peripherals = esp_hal::init(esp_hal::Config::default());

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(
        timg0.timer0,
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT)
            .software_interrupt0,
    );

    alignment::print_alignments();
}
