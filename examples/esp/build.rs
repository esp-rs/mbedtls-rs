use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let current_time_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis();

    println!("cargo:rustc-env=CURRENT_TIME_MS={}", current_time_ms);
}
