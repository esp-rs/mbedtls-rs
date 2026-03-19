//! Modular exponentiation using ESP hardware acceleration.

use core::ffi::c_int;

#[cfg(not(any(feature = "esp32c3", feature = "esp32c6", feature = "esp32h2")))]
use crypto_bigint::U4096;
use crypto_bigint::{U1024, U2048, U512};
#[cfg(not(feature = "esp32"))]
use crypto_bigint::{U256, U384};
use esp_hal::rsa::{operand_sizes, RsaContext};

use crate::hook::exp_mod::MbedtlsMpiExpMod;
use crate::{
    mbedtls_mpi, mbedtls_mpi_add_mpi, mbedtls_mpi_cmp_int, mbedtls_mpi_exp_mod_soft,
    mbedtls_mpi_free, mbedtls_mpi_grow, mbedtls_mpi_init, mbedtls_mpi_lset, mbedtls_mpi_mod_mpi,
    mbedtls_mpi_set_bit, merr, MbedtlsError,
};

#[cfg(not(feature = "esp32"))]
const SOC_RSA_MIN_BIT_LEN: usize = 256;
#[cfg(feature = "esp32")]
const SOC_RSA_MIN_BIT_LEN: usize = 512;

#[cfg(not(any(feature = "esp32c3", feature = "esp32c6", feature = "esp32h2")))]
const SOC_RSA_MAX_BIT_LEN: usize = 4096;
#[cfg(any(feature = "esp32c3", feature = "esp32c6", feature = "esp32h2"))]
const SOC_RSA_MAX_BIT_LEN: usize = 3072;

// Bad input parameters to function.
// TODO const MBEDTLS_ERR_MPI_BAD_INPUT_DATA: c_int = -0x0004;

macro_rules! modular_exponentiate {
    ($op:ty, $x:expr, $y:expr, $m:expr, $rinv:expr, $z:expr, $x_words:expr, $y_words:expr, $m_words:expr, $op_size:expr) => {{
        const OP_SIZE: usize = $op_size;

        let mut rsa = RsaContext::new();

        #[cfg(not(feature = "esp32"))]
        rsa.enable_acceleration();
        #[cfg(not(feature = "esp32"))]
        rsa.enable_search_acceleration();

        let mut base = [0u32; OP_SIZE];
        copy_bytes($x.private_p, base.as_mut_ptr(), $x_words);

        let mut exponent = [0u32; OP_SIZE];
        copy_bytes($y.private_p, exponent.as_mut_ptr(), $y_words);

        let mut modulus = [0u32; OP_SIZE];
        copy_bytes($m.private_p, modulus.as_mut_ptr(), $m_words);

        let mut r = [0u32; OP_SIZE];
        copy_bytes($rinv.private_p, r.as_mut_ptr(), mpi_words($rinv));

        let mut out = [0u32; OP_SIZE];
        rsa.modular_exponentiate::<$op>(
            &base,
            &exponent,
            &modulus,
            &r,
            compute_mprime($m),
            &mut out,
        )
        .wait_blocking();

        copy_bytes(out.as_ptr(), (*$z).private_p, $m_words);
    }};
}

/// Modular exponentiation using ESP hardware acceleration.
pub struct EspExpMod(());

impl Default for EspExpMod {
    fn default() -> Self {
        Self::new()
    }
}

impl EspExpMod {
    /// Create a new `EspExpMod` instance.
    pub const fn new() -> Self {
        Self(())
    }

    /// Calculate the number of words used for a hardware operation.
    ///
    /// For every chip except `feature = "esp32"`, this will return `words`
    /// For `feature = "esp32"`, this will return the number of words rounded up to the 512 block count.
    const fn calculate_hw_words(words: usize) -> usize {
        // Round up number of words to nearest
        // 512 bit (16 word) block count.
        #[cfg(feature = "esp32")]
        return (words + 0xF) & !0xF;
        #[cfg(not(feature = "esp32"))]
        words
    }

    /// Calculate Rinv = RR^2 mod M, where:
    ///
    ///  R = b^n where b = 2^32, n=num_words,
    ///  R = 2^N (where N=num_bits)
    ///  RR = R^2 = 2^(2*N) (where N=num_bits=num_words*32)
    ///
    /// This calculation is computationally expensive (mbedtls_mpi_mod_mpi)
    /// so caller should cache the result where possible.
    ///
    /// DO NOT call this function while holding esp_mpi_enable_hardware_hw_op().
    fn calculate_rinv(prec_rr: &mut mbedtls_mpi, m: &mbedtls_mpi, num_words: usize) -> c_int {
        let mut rr = mbedtls_mpi {
            private_s: 0,
            private_n: 0,
            private_p: core::ptr::null_mut(),
        };

        unsafe { mbedtls_mpi_init(&mut rr) };

        unwrap!(merr!(unsafe {
            mbedtls_mpi_set_bit(&mut rr, num_words * 32 * 2, 1)
        }));
        unwrap!(merr!(unsafe { mbedtls_mpi_mod_mpi(prec_rr, &rr, m) }));

        unsafe { mbedtls_mpi_free(&mut rr) };

        0
    }
}

impl MbedtlsMpiExpMod for EspExpMod {
    fn exp_mod(
        &self,
        z: &mut mbedtls_mpi,
        x: &mbedtls_mpi,
        y: &mbedtls_mpi,
        m: &mbedtls_mpi,
        mut prec_rr: Option<&mut mbedtls_mpi>,
    ) -> Result<(), MbedtlsError> {
        let x_words = mpi_words(x);
        let y_words = mpi_words(y);
        let m_words = mpi_words(m);

        // All numbers must be the lame length, so choose longest number as
        // cardinal length of operation
        let num_words = Self::calculate_hw_words(m_words.max(x_words.max(y_words)));

        if num_words * 32 < SOC_RSA_MIN_BIT_LEN || num_words * 32 > SOC_RSA_MAX_BIT_LEN {
            unwrap!(merr!(unsafe {
                mbedtls_mpi_exp_mod_soft(
                    z,
                    x,
                    y,
                    m,
                    prec_rr.as_mut().map(|rr| *rr as *mut _).unwrap_or_default(),
                )
            }));

            return Ok(());
        }

        if m.private_p.is_null() {
            todo!("Handle this null");
        }

        unsafe {
            if mbedtls_mpi_cmp_int(m, 0) <= 0 || m.private_p.read() & 1 == 0 {
                panic!(); // TODO
                          // return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
            }

            if mbedtls_mpi_cmp_int(y, 0) < 0 {
                panic!(); // TODO
                          // return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
            }

            if mbedtls_mpi_cmp_int(y, 0) == 0 {
                mbedtls_mpi_lset(z, 1);
            }
        }

        let mut rinv_new = mbedtls_mpi {
            private_s: 0,
            private_n: 0,
            private_p: core::ptr::null_mut(),
        };

        // Determine rinv, either `prec_rr` for cached value or the local `rinv_new`
        let rinv: &mut mbedtls_mpi = if let Some(prec_rr) = prec_rr.as_mut() {
            prec_rr
        } else {
            unsafe { mbedtls_mpi_init(&mut rinv_new) };
            &mut rinv_new
        };

        if rinv.private_p.is_null() {
            Self::calculate_rinv(rinv, m, num_words);
        }

        unwrap!(merr!(unsafe { mbedtls_mpi_grow(z, m_words) }));

        match num_words {
            #[cfg(not(feature = "esp32"))]
            U256::LIMBS => modular_exponentiate!(
                operand_sizes::Op256,
                x,
                y,
                m,
                rinv,
                z,
                x_words,
                y_words,
                m_words,
                U256::LIMBS
            ),
            #[cfg(not(feature = "esp32"))]
            U384::LIMBS => modular_exponentiate!(
                operand_sizes::Op384,
                x,
                y,
                m,
                rinv,
                z,
                x_words,
                y_words,
                m_words,
                U384::LIMBS
            ),
            U512::LIMBS => modular_exponentiate!(
                operand_sizes::Op512,
                x,
                y,
                m,
                rinv,
                z,
                x_words,
                y_words,
                m_words,
                U512::LIMBS
            ),
            U1024::LIMBS => modular_exponentiate!(
                operand_sizes::Op1024,
                x,
                y,
                m,
                rinv,
                z,
                x_words,
                y_words,
                m_words,
                U1024::LIMBS
            ),
            U2048::LIMBS => modular_exponentiate!(
                operand_sizes::Op2048,
                x,
                y,
                m,
                rinv,
                z,
                x_words,
                y_words,
                m_words,
                U2048::LIMBS
            ),
            #[cfg(not(any(feature = "esp32c3", feature = "esp32c6", feature = "esp32h2")))]
            U4096::LIMBS => modular_exponentiate!(
                operand_sizes::Op4096,
                x,
                y,
                m,
                rinv,
                z,
                x_words,
                y_words,
                m_words,
                U4096::LIMBS
            ),
            _ => unreachable!(),
        }

        assert_eq!(x.private_s, 1);

        // Compensate for negative X
        if x.private_s == -1 && unsafe { y.private_p.read() & 1 } != 0 {
            z.private_s = -1;
            unwrap!(merr!(unsafe { mbedtls_mpi_add_mpi(z, m, z) }));
        } else {
            z.private_s = 1;
        }

        if prec_rr.is_none() {
            unsafe { mbedtls_mpi_free(&mut rinv_new) };
        }

        Ok(())
    }
}

fn compute_mprime(m: &mbedtls_mpi) -> u32 {
    let mut t: u64 = 1;
    let mut two_2_i_minus_1: u64 = 2; // 2^(i-1)
    let mut two_2_i: u64 = 4; // 2^i
    let n = unsafe { m.private_p.read() } as u64;

    for _ in 2..=32 {
        if n * t % two_2_i >= two_2_i_minus_1 {
            t += two_2_i_minus_1;
        }

        two_2_i_minus_1 <<= 1;
        two_2_i <<= 1;
    }

    (u32::MAX as u64 - t + 1) as u32
}

/// Return the number of words actually used to represent an mpi number.
#[inline(always)]
fn mpi_words(x: &mbedtls_mpi) -> usize {
    for index in (0..usize::from(x.private_n)).rev() {
        if unsafe { x.private_p.add(index).read() } != 0 {
            return index + 1;
        }
    }

    0
}

/// A fast copying of non-overlapping bytes from source to destination
#[inline(always)]
fn copy_bytes<T>(src: *const T, dst: *mut T, count: usize)
where
    T: Copy,
{
    unsafe { core::ptr::copy_nonoverlapping(src, dst, count) };
}
