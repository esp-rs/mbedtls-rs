//! An `esp-hal` bootstrapping code shared by all network examples

use embassy_executor::Spawner;

use embassy_net::{Stack, StackResources};

#[cfg(not(feature = "esp32c5"))]
use embassy_net::Runner;

#[cfg(not(feature = "esp32c5"))]
use embassy_time::Duration;
#[cfg(not(feature = "esp32c5"))]
use embassy_time::Timer;

#[cfg(not(feature = "esp32c5"))]
use esp_alloc::heap_allocator;

use esp_backtrace as _;

#[cfg(not(feature = "esp32c5"))]
use esp_hal::ram;
#[cfg(not(feature = "esp32c5"))]
use esp_hal::rng::Trng;
#[cfg(not(feature = "esp32c5"))]
use esp_hal::rng::TrngSource;
use esp_hal::rtc_cntl::Rtc;
#[cfg(not(feature = "esp32c5"))]
use esp_hal::timer::timg::TimerGroup;

#[cfg(not(feature = "esp32c5"))]
use mbedtls_rs::sys::hook::backend::embassy::timer::EmbassyTimer;
#[cfg(not(feature = "esp32c5"))]
use mbedtls_rs::sys::hook::backend::esp::wall_clock::EspRtcWallClock;
use mbedtls_rs::sys::hook::backend::esp::EspAccel;
use mbedtls_rs::Tls;

use esp_metadata_generated::memory_range;

use esp_radio as _;
#[cfg(not(feature = "esp32c5"))]
use esp_radio::wifi::scan::ScanConfig;
#[cfg(not(feature = "esp32c5"))]
use esp_radio::wifi::sta::StationConfig;
#[cfg(not(feature = "esp32c5"))]
use esp_radio::wifi::Config;
#[cfg(not(feature = "esp32c5"))]
use esp_radio::wifi::ControllerConfig;
#[cfg(not(feature = "esp32c5"))]
use esp_radio::wifi::Interface;
#[cfg(not(feature = "esp32c5"))]
use esp_radio::wifi::WifiController;

#[cfg(not(feature = "esp32c5"))]
use log::{error, info};

extern crate alloc;

#[macro_export]
macro_rules! mk_static {
    ($t:ty) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        STATIC_CELL.uninit()
    }};
    ($t:ty,$val:expr) => {{
        mk_static!($t).write($val)
    }};
}

pub const RECLAIMED_RAM: usize =
    memory_range!("DRAM2_UNINIT").end - memory_range!("DRAM2_UNINIT").start;

esp_bootloader_esp_idf::esp_app_desc!();

#[cfg(not(feature = "esp32c5"))]
const WIFI_SSID: &str = env!("WIFI_SSID");
#[cfg(not(feature = "esp32c5"))]
const WIFI_PASS: &str = env!("WIFI_PASS");
#[cfg(not(feature = "esp32c5"))]
const CURRENT_TIME_MS: &str = env!("CURRENT_TIME_MS");

// esp32c5: esp-hal v1.1 does not yet wire the TRNG (`rng_trng_supported` cfg
// unset) nor the LP_TIMER driver (`lp_timer_driver_supported` cfg unset), both
// of which this bootstrap depends on. The c5 path of `bootstrap_stack` therefore
// panics at runtime per maintainer ask; the rest of the examples crate still
// builds for c5 so CI catches regressions in the chip-independent code.
// Re-enable once esp-hal lands the c5 drivers.
#[cfg(feature = "esp32c5")]
pub async fn bootstrap_stack<const SOCKETS: usize>(
    _spawner: Spawner,
    _stack_resources: &'static mut StackResources<SOCKETS>,
) -> (
    Tls<'static>,
    Stack<'static>,
    EspAccel<'static>,
    &'static Rtc<'static>,
) {
    panic!(
        "esp32c5 example bootstrap unsupported: \
         esp-hal v1.1 lacks TRNG and LP_TIMER drivers for c5"
    );
}

#[cfg(not(feature = "esp32c5"))]
pub async fn bootstrap_stack<const SOCKETS: usize>(
    spawner: Spawner,
    stack_resources: &'static mut StackResources<SOCKETS>,
) -> (
    Tls<'static>,
    Stack<'static>,
    EspAccel<'static>,
    &'static Rtc<'static>,
) {
    esp_println::logger::init_logger(log::LevelFilter::Info);

    info!("Starting...");

    heap_allocator!(#[ram(reclaimed)] size: RECLAIMED_RAM);

    let peripherals =
        esp_hal::init(esp_hal::Config::default().with_cpu_clock(esp_hal::clock::CpuClock::max()));

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(
        timg0.timer0,
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT)
            .software_interrupt0,
    );

    // Create static Embassy timer and "hook it" to mbedtls
    let timer = mk_static!(EmbassyTimer, EmbassyTimer);
    unsafe {
        mbedtls_rs::sys::hook::timer::hook_timer(Some(timer));
    }

    // Setup RTC for EspRtcWallClock
    let rtc = &*mk_static!(Rtc, Rtc::new(peripherals.LPWR));

    // In a real-life scenario NTP or equivalent should be used here to initialize the RTC
    rtc.set_current_time_us(
        CURRENT_TIME_MS
            .parse::<u64>()
            .expect("Failed to parse CURRENT_TIME_MS")
            * 1000, // Convert milliseconds to microseconds
    );

    // Make EspRtcWallClock static and "hook it" to mbedtls
    let clock = mk_static!(EspRtcWallClock<&Rtc>, EspRtcWallClock::new(rtc));
    unsafe {
        mbedtls_rs::sys::hook::wall_clock::hook_wall_clock(Some(clock));
    }

    #[cfg(not(any(feature = "esp32", feature = "esp32c2")))]
    let accel = EspAccel::new(peripherals.SHA, peripherals.RSA);

    #[cfg(feature = "esp32")]
    let accel = EspAccel::new(peripherals.RSA);

    #[cfg(feature = "esp32c2")]
    let accel = EspAccel::new(peripherals.SHA);

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);

    let trng = mk_static!(Trng, Trng::try_new().unwrap());

    let station_config = Config::Station(
        StationConfig::default()
            .with_ssid(WIFI_SSID)
            .with_password(WIFI_PASS.into()),
    );

    // Configure and start the Wifi first
    info!("Starting wifi");
    let (mut controller, wifi_interfaces) = esp_radio::wifi::new(
        peripherals.WIFI,
        ControllerConfig::default().with_initial_config(station_config),
    )
    .unwrap();
    info!("Wifi configured and started!");
    let config = embassy_net::Config::dhcpv4(Default::default());

    let seed = (trng.random() as u64) << 32 | trng.random() as u64;

    // Init network stack
    let (stack, runner) = embassy_net::new(wifi_interfaces.station, config, stack_resources, seed);

    info!("Scan");
    let scan_config = ScanConfig::default().with_max(10);
    let result = controller.scan_async(&scan_config).await.unwrap();
    for ap in result {
        info!("{:?}", ap);
    }

    spawner.spawn(connection(controller).unwrap());
    spawner.spawn(net_task(runner).unwrap());

    wait_ip(stack).await;

    (Tls::new(trng).unwrap(), stack, accel, rtc)
}

#[cfg(not(feature = "esp32c5"))]
async fn wait_ip(stack: Stack<'_>) {
    loop {
        if stack.is_link_up() {
            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }

    info!("Waiting to get IP address...");
    loop {
        if let Some(config) = stack.config_v4() {
            info!("Got IP: {}", config.address);
            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }
}

#[cfg(not(feature = "esp32c5"))]
#[embassy_executor::task]
async fn connection(mut controller: WifiController<'static>) {
    info!("start connection task");

    loop {
        info!("About to connect...");

        match controller.connect_async().await {
            Ok(info) => {
                info!("Wifi connected to {:?}", info);

                // wait until we're no longer connected
                let info = controller.wait_for_disconnect_async().await.ok();
                error!("Disconnected: {:?}", info);
            }
            Err(e) => {
                error!("Failed to connect to wifi: {e:?}");
            }
        }

        Timer::after(Duration::from_millis(5000)).await
    }
}

#[cfg(not(feature = "esp32c5"))]
#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, Interface<'static>>) {
    runner.run().await
}
