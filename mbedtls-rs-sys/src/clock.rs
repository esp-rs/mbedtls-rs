#[cfg(any(
    feature = "wall-clock-esp32",
    feature = "wall-clock-esp32c2",
    feature = "wall-clock-esp32c3",
    feature = "wall-clock-esp32c6",
    feature = "wall-clock-esp32h2",
    feature = "wall-clock-esp32s2",
    feature = "wall-clock-esp32s3",
))]
pub mod esp;
