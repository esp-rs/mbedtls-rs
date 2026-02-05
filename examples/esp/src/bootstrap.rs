//! An `esp-hal` bootstrapping code shared by all network examples

use embassy_executor::Spawner;

use embassy_net::{Runner, Stack, StackResources};

use embassy_time::Duration;
use embassy_time::Timer;

use esp_alloc::heap_allocator;

use esp_backtrace as _;

use esp_hal::ram;
use esp_hal::rng::Trng;
use esp_hal::rng::TrngSource;
use esp_hal::timer::timg::TimerGroup;

use mbedtls_rs::sys::accel::esp::EspAccel;
use mbedtls_rs::Tls;
use mbedtls_rs::sys::clock::esp::EspRtcWallClock;
use mbedtls_rs::sys::timer::embassy::EmbassyTimer;

use esp_metadata_generated::memory_range;

use esp_radio as _;
use esp_radio::wifi::scan::ScanConfig;
use esp_radio::wifi::sta::StationConfig;
use esp_radio::wifi::ModeConfig;
use esp_radio::wifi::WifiController;
use esp_radio::wifi::WifiDevice;
use esp_radio::wifi::WifiEvent;

use log::info;

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

const WIFI_SSID: &str = env!("WIFI_SSID");
const WIFI_PASS: &str = env!("WIFI_PASS");
const CURRENT_TIME_MS: &str = env!("CURRENT_TIME_MS");

pub async fn bootstrap_stack<const SOCKETS: usize>(
    spawner: Spawner,
    stack_resources: &'static mut StackResources<SOCKETS>,
) -> (Tls<'static>, Stack<'static>, EspAccel<'static>) {
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

    // TODO feature gate?
    {
        let timer = mk_static!(EmbassyTimer, EmbassyTimer::default());
        unsafe {
            mbedtls_rs::sys::hook::timer::hook_timer(Some(timer));
        }
    }

    // TODO feature gate?
    {
        let rtc = mk_static!(
            esp_hal::rtc_cntl::Rtc,
            esp_hal::rtc_cntl::Rtc::new(peripherals.LPWR)
        );

        // In a real-life scenario NTP or equivalent should be used here to initialize the RTC
        rtc.set_current_time_us(
            CURRENT_TIME_MS
                .parse::<u64>()
                .expect("Failed to parse CURRENT_TIME_MS")
                * 1000, // Convert milliseconds to microseconds
        );

        let clock = mk_static!(EspRtcWallClock, EspRtcWallClock::new(rtc));
        unsafe {
            mbedtls_rs::sys::hook::wall_clock::hook_wall_clock(Some(clock));
        }
    }

    #[cfg(not(any(feature = "esp32", feature = "esp32c2")))]
    let accel = EspAccel::new(peripherals.SHA, peripherals.RSA);

    #[cfg(feature = "esp32")]
    let accel = EspAccel::new(peripherals.RSA);

    #[cfg(feature = "esp32c2")]
    let accel = EspAccel::new(peripherals.SHA);

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);

    let trng = mk_static!(Trng, Trng::try_new().unwrap());

    // Configure and start the Wifi first
    let (controller, wifi_interfaces) =
        esp_radio::wifi::new(peripherals.WIFI, esp_radio::wifi::Config::default()).unwrap();
    let config = embassy_net::Config::dhcpv4(Default::default());

    let seed = (trng.random() as u64) << 32 | trng.random() as u64;

    // Init network stack
    let (stack, runner) = embassy_net::new(wifi_interfaces.station, config, stack_resources, seed);

    spawner.spawn(connection(controller)).ok();
    spawner.spawn(net_task(runner)).ok();

    wait_ip(stack).await;

    (Tls::new(trng).unwrap(), stack, accel)
}

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

#[embassy_executor::task]
async fn connection(mut controller: WifiController<'static>) {
    info!("Start connection task");
    info!("Device capabilities: {:?}", controller.capabilities());

    loop {
        if matches!(controller.is_connected(), Ok(true)) {
            // wait until we're no longer connected
            controller
                .wait_for_event(WifiEvent::StationDisconnected)
                .await;
            Timer::after(Duration::from_millis(5000)).await
        }

        if !matches!(controller.is_started(), Ok(true)) {
            let station_config = ModeConfig::Station(
                StationConfig::default()
                    .with_ssid(WIFI_SSID.into())
                    .with_password(WIFI_PASS.into()),
            );
            controller.set_config(&station_config).unwrap();
            info!("Starting wifi");
            controller.start_async().await.unwrap();
            info!("Wifi started!");

            info!("Scan");
            let scan_config = ScanConfig::default().with_max(10);
            let result = controller
                .scan_with_config_async(scan_config)
                .await
                .unwrap();
            for ap in result {
                info!("{:?}", ap);
            }
        }
        info!("About to connect...");

        match controller.connect_async().await {
            Ok(_) => info!("Wifi connected!"),
            Err(e) => {
                info!("Failed to connect to wifi: {e:?}");
                Timer::after(Duration::from_millis(5000)).await
            }
        }
    }
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, WifiDevice<'static>>) {
    runner.run().await
}
