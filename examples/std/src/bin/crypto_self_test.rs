//! Run crypto self tests to ensure their functionality

use std::time::Instant;

use mbedtls_rs::sys::self_test::MbedtlsSelfTest;

use log::{error, info};

fn main() {
    #[cfg(not(target_os = "espidf"))]
    env_logger::init();
    #[cfg(target_os = "espidf")]
    esp_idf_svc::log::EspLogger::initialize_default();

    info!("Running MbedTLS self tests...");

    info!("TESTS OUTPUT >>>>>>>>");

    for mut test in enumset::EnumSet::<MbedtlsSelfTest>::all() {
        info!("Testing {:?}", test);

        let before = Instant::now();

        if !test.run(true) {
            error!("Self-test {:?} failed!", test);
        }

        info!("Took {:?}", before.elapsed());
    }

    info!("<<<<<<<< TESTS OUTPUT");
    info!("Done");
}
