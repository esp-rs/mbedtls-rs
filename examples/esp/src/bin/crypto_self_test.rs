//! Run crypto self tests to ensure their functionality and benchmark hardware acceleration

#![no_std]
#![no_main]
#![recursion_limit = "256"]

use core::cell::RefCell;
use core::ffi::c_int;
use core::fmt::Write as _;

use critical_section::Mutex;

use embassy_executor::Spawner;

use esp_alloc::heap_allocator;

use esp_backtrace as _;

use esp_hal::ram;
use esp_hal::timer::timg::TimerGroup;

use esp_metadata_generated::memory_range;
use mbedtls_rs::sys::hook::backend::esp::EspAccel;
use mbedtls_rs::sys::self_test::MbedtlsSelfTest;

use esp_radio as _;

use log::{error, info};

use tinyrlibc as _;

extern crate alloc;

const HEAP_SIZE: usize = 140 * 1024;

const RECLAIMED_RAM: usize =
    memory_range!("DRAM2_UNINIT").end - memory_range!("DRAM2_UNINIT").start;

esp_bootloader_esp_idf::esp_app_desc!();

static RNG: Mutex<RefCell<Option<esp_hal::rng::Rng>>> = Mutex::new(RefCell::new(None));

#[esp_rtos::main]
async fn main(_s: Spawner) {
    esp_println::logger::init_logger(log::LevelFilter::Info);

    info!("Starting...");

    heap_allocator!(size: HEAP_SIZE - RECLAIMED_RAM);
    heap_allocator!(#[ram(reclaimed)] size: RECLAIMED_RAM);

    let peripherals = esp_hal::init(esp_hal::Config::default());

    critical_section::with(|cs| {
        *RNG.borrow(cs).borrow_mut() = Some(esp_hal::rng::Rng::new());
    });

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    let mut sw_cycles = [0; 20];
    let mut hw_cycles = [0; 20];

    run_tests(false, &mut sw_cycles);
    let ecdsa_sw = run_ecdsa_bench(false);

    // Configure every accelerator the chip has; each `with_*` exists only on
    // the chips with the corresponding peripheral.
    let accel = EspAccel::new();
    #[cfg(not(feature = "esp32"))]
    let accel = accel.with_sha(peripherals.SHA);
    #[cfg(not(feature = "esp32c2"))]
    let accel = accel.with_rsa(peripherals.RSA).with_aes(peripherals.AES);
    #[cfg(any(
        feature = "esp32c2",
        feature = "esp32c5",
        feature = "esp32c6",
        feature = "esp32h2"
    ))]
    let accel = accel.with_ecc(peripherals.ECC);
    let mut accel = accel;

    let accel_queue = accel.start();
    // Hook exactly the algorithms whose work queues are being serviced.
    let _hooked = unsafe { accel_queue.hook() };

    run_tests(true, &mut hw_cycles);
    let ecdsa_hw = run_ecdsa_bench(true);

    // | Hash Algorithm | Software (cycles) | Hardware (cycles) | Hardware Faster (x times) |
    // |----------------|-------------------|-------------------|---------------------------|
    // | SHA-1          |      3,390,785    |         896,889   |           3.78            |
    // | SHA-224        |      8,251,799    |         898,344   |           9.19            |
    // | SHA-256        |      8,237,932    |         901,709   |           9.14            |
    // | SHA-384        |     13,605,806    |         799,532   |           17.02           |
    // | SHA-512        |     13,588,104    |         801,556   |           16.95           |

    info!("=== SUMMARY ===");
    info!("| Hash Algorithm | Software (cycles) | Hardware (cycles) | Hardware Faster (x times) |");
    info!("|----------------|-------------------|-------------------|---------------------------|");
    for (index, test) in enumset::EnumSet::<MbedtlsSelfTest>::all()
        .iter()
        .enumerate()
    {
        let mut test_name = heapless::String::<14>::new();
        write!(&mut test_name, "{:?}", test).unwrap();

        info!(
            "| {:14} | {:17} | {:17} | {:25.2} |",
            test_name,
            sw_cycles[index],
            hw_cycles[index],
            if hw_cycles[index] != 0 {
                (sw_cycles[index] as f64) / (hw_cycles[index] as f64)
            } else {
                0.0
            }
        );
    }

    // The production-shaped ECDSA figures (cycles per operation; see
    // `run_ecdsa_bench` for why these are more honest than the ECP self-test).
    if let (Some(sw), Some(hw)) = (ecdsa_sw, ecdsa_hw) {
        for (name, s, h) in [("P256-Sign", sw.0, hw.0), ("P256-Verify", sw.1, hw.1)] {
            info!(
                "| {:14} | {:17} | {:17} | {:25.2} |",
                name,
                s,
                h,
                if h != 0 { s as f64 / h as f64 } else { 0.0 }
            );
        }
    }
}

fn run_tests(hw_accel: bool, summary: &mut [u64]) {
    info!(
        ">>> Running tests {} hardware acceleration",
        if hw_accel { "WITH" } else { "WITHOUT" }
    );

    for mut test in enumset::EnumSet::<MbedtlsSelfTest>::all() {
        let before = cycles();

        if !test.run(true) {
            error!("Self-test {:?} failed!", test);
        }

        let after = cycles();

        let cycles = after.saturating_sub(before);

        let mut test_name = heapless::String::<14>::new();
        write!(&mut test_name, "{:?}", test).unwrap();

        info!("Test {:14} took {:17?} cycles", test_name, cycles);

        summary[test as usize] = cycles;
    }
}

/// The production-shaped ECDSA P-256 benchmark (see
/// [`EcdsaP256Bench`](mbedtls_rs::sys::self_test::EcdsaP256Bench) for why it
/// is more honest about hardware acceleration than the ECP self-test).
///
/// Returns the average `(sign, verify)` cycles per operation.
fn run_ecdsa_bench(hw_accel: bool) -> Option<(u64, u64)> {
    use mbedtls_rs::sys::self_test::EcdsaP256Bench;

    const ITERS: u32 = 4;

    info!(
        ">>> Running ECDSA-P256 bench {} hardware acceleration",
        if hw_accel { "WITH" } else { "WITHOUT" }
    );

    let mut rng = |buf: &mut [u8]| {
        critical_section::with(|cs| {
            let mut rng = RNG.borrow(cs).borrow_mut();
            let rng = rng.as_mut().unwrap();

            for chunk in buf.chunks_mut(4) {
                let word = rng.random().to_le_bytes();
                chunk.copy_from_slice(&word[..chunk.len()]);
            }
        })
    };

    let Some(mut bench) = EcdsaP256Bench::new(&mut rng) else {
        error!("ECDSA-P256 bench setup failed!");
        return None;
    };

    let mut ok = true;

    let mut sign_total = 0;
    for _ in 0..ITERS {
        let before = cycles();
        ok &= bench.sign();
        sign_total += cycles().saturating_sub(before);

        if !ok {
            break;
        }
    }

    let mut verify_total = 0;
    for _ in 0..ITERS {
        if !ok {
            break;
        }

        let before = cycles();
        ok &= bench.verify();
        verify_total += cycles().saturating_sub(before);
    }

    if !ok {
        error!("ECDSA-P256 bench failed!");
        return None;
    }

    let sign = sign_total / ITERS as u64;
    let verify = verify_total / ITERS as u64;

    info!("ECDSA-P256 sign   took {:17?} cycles/op", sign);
    info!("ECDSA-P256 verify took {:17?} cycles/op", verify);

    Some((sign, verify))
}

fn cycles() -> u64 {
    #[cfg(any(feature = "esp32", feature = "esp32s2", feature = "esp32s3"))]
    {
        esp_hal::xtensa_lx::timer::get_cycle_count() as u64
    }

    #[cfg(not(any(feature = "esp32", feature = "esp32s2", feature = "esp32s3")))]
    {
        use esp_hal::timer::systimer::{SystemTimer, Unit};
        SystemTimer::unit_value(Unit::Unit0)
    }
}

// The RSA self-tests unfortunately directly use the `rand` symbol
#[no_mangle]
unsafe extern "C" fn rand() -> c_int {
    critical_section::with(|cs| {
        (RNG.borrow(cs).borrow_mut().as_mut().unwrap().random() % i32::MAX as u32) as _
    })
}
