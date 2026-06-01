use core::convert::Infallible;

use rand::{Rng, TryCryptoRng, TryRng};

/// A standard, crypto-compliant random number generator using the `rand` crate which is `Send`.
pub struct StdRng;

impl TryRng for StdRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(rand::rng().next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(rand::rng().next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        rand::rng().fill_bytes(dst);
        Ok(())
    }
}

impl TryCryptoRng for StdRng {}
