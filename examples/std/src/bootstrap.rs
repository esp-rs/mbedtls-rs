#[cfg(not(target_os = "espidf"))]
pub fn bootstrap() {
    env_logger::init();
}

#[cfg(target_os = "espidf")]
#[cold]
#[inline(never)]
pub fn bootstrap() {
    use esp_idf_svc::eventloop::EspSystemEventLoop;
    use esp_idf_svc::hal::peripherals::Peripherals;
    use esp_idf_svc::io::vfs::MountedEventfs;
    use esp_idf_svc::nvs::EspDefaultNvsPartition;
    use esp_idf_svc::wifi::*;

    use log::info;

    const WIFI_SSID: &str = env!("WIFI_SSID");
    const WIFI_PASS: &str = env!("WIFI_PASS");

    esp_idf_svc::log::EspLogger::initialize_default();

    let peripherals = Peripherals::take().unwrap();
    let sys_loop = EspSystemEventLoop::take().unwrap();
    let nvs = EspDefaultNvsPartition::take().unwrap();

    let mut wifi = Box::new(
        BlockingWifi::wrap(
            EspWifi::new(peripherals.modem, sys_loop.clone(), Some(nvs)).unwrap(),
            sys_loop,
        )
        .unwrap(),
    );

    let wifi_configuration: Configuration = Configuration::Client(ClientConfiguration {
        auth_method: AuthMethod::WPA2Personal,
        ssid: WIFI_SSID.try_into().unwrap(),
        password: WIFI_PASS.try_into().unwrap(),
        ..Default::default()
    });

    wifi.set_configuration(&wifi_configuration).unwrap();

    wifi.start().unwrap();
    info!("Wifi started");

    wifi.connect().unwrap();
    info!("Wifi connected");

    wifi.wait_netif_up().unwrap();
    info!("Wifi netif up");

    let ip_info = wifi.wifi().sta_netif().get_ip_info().unwrap();

    info!("Wifi DHCP info: {ip_info:?}");

    // Keep the wifi driver active by not dropping it
    core::mem::forget(wifi);

    // Ditto for event_fs which is used by `async-io-mini`
    let event_fs = MountedEventfs::mount(2).unwrap();
    core::mem::forget(event_fs);
}

#[allow(unused)]
pub fn block_on<F: core::future::Future>(fut: F) -> F::Output {
    #[cfg(not(target_os = "espidf"))]
    let res = futures_lite::future::block_on(fut);
    #[cfg(target_os = "espidf")]
    let res = esp_idf_svc::hal::task::block_on(fut);

    res
}
