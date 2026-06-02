//! Print target-specific alignments of the primitive types

#[path = "../../../common/alignment.rs"]
mod alignment;

fn main() {
    #[cfg(not(target_os = "espidf"))]
    env_logger::init();
    #[cfg(target_os = "espidf")]
    esp_idf_svc::log::EspLogger::initialize_default();

    alignment::print_alignments();
}
