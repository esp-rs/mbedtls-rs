//! ECP (P-192/P-256) implementation using the ESP32XX ECC accelerator.
//!
//! Ops are posted to the `esp-hal` ECC work queue (see
//! `esp_hal::ecc::EccBackend`), whose driver must be running for the
//! duration of use - this is ensured by `EspAccel`/`EspAccelQueue`.
//!
//! Operands the accelerator cannot handle (other curves, out-of-range
//! scalars/coordinates, non-affine points) are delegated to the MbedTLS
//! software implementation, so behavior stays identical to the un-hooked
//! build for everything the hardware does not cover.

use core::ffi::c_void;

use esp_hal::ecc::EllipticCurve;

use mbedtls_rs_sys::hook::ecp::{MbedtlsEcpRestartCtx, MbedtlsFRng};
use mbedtls_rs_sys::{
    mbedtls_ecp_group, mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP192R1,
    mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1, mbedtls_ecp_point, mbedtls_mpi,
    mbedtls_mpi_cmp_int, mbedtls_mpi_cmp_mpi, mbedtls_mpi_lset, mbedtls_mpi_read_binary_le,
    mbedtls_mpi_write_binary_le, merr, MbedtlsError, MBEDTLS_ERR_ECP_INVALID_KEY,
};

/// The largest curve operand size (P-256), in bytes
const MAX_SIZE: usize = 32;

/// ECP implementation using the ESP32XX ECC accelerator (P-192 and P-256),
/// falling back to the MbedTLS software implementation for anything else.
pub struct EspEcc(());

impl EspEcc {
    /// Create a new `EspEcc` instance
    pub const fn new() -> Self {
        Self(())
    }
}

impl Default for EspEcc {
    fn default() -> Self {
        Self::new()
    }
}

/// Map the MbedTLS group to a hardware-supported curve
fn curve(grp: &mbedtls_ecp_group) -> Option<EllipticCurve> {
    #[allow(non_upper_case_globals)]
    match grp.id {
        mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP192R1 => Some(EllipticCurve::P192),
        mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1 => Some(EllipticCurve::P256),
        _ => None,
    }
}

/// Serialize an MPI to the fixed-size little-endian representation used by
/// the accelerator. `None` if the value does not fit.
fn to_le(mpi: &mbedtls_mpi, size: usize) -> Option<[u8; MAX_SIZE]> {
    let mut buf = [0; MAX_SIZE];

    merr!(unsafe { mbedtls_mpi_write_binary_le(mpi, buf.as_mut_ptr(), size) })
        .ok()
        .map(|_| buf)
}

/// Whether the point has affine (Z == 1) representation and in-range,
/// non-negative coordinates - i.e. whether it can be fed to the accelerator
fn hw_point_operands(
    grp: &mbedtls_ecp_group,
    pt: &mbedtls_ecp_point,
    size: usize,
) -> Option<([u8; MAX_SIZE], [u8; MAX_SIZE])> {
    // Affine representation required
    if unsafe { mbedtls_mpi_cmp_int(&pt.private_Z, 1) } != 0 {
        return None;
    }

    // Coordinates must be in [0, P)
    if unsafe { mbedtls_mpi_cmp_int(&pt.private_X, 0) } < 0
        || unsafe { mbedtls_mpi_cmp_int(&pt.private_Y, 0) } < 0
        || unsafe { mbedtls_mpi_cmp_mpi(&pt.private_X, &grp.P) } >= 0
        || unsafe { mbedtls_mpi_cmp_mpi(&pt.private_Y, &grp.P) } >= 0
    {
        return None;
    }

    Some((to_le(&pt.private_X, size)?, to_le(&pt.private_Y, size)?))
}

#[cfg(mbedtls_hook = "ecp_mul")]
impl mbedtls_rs_sys::hook::ecp::MbedtlsEcpMul for EspEcc {
    unsafe fn mul(
        &self,
        grp: &mut mbedtls_ecp_group,
        r: &mut mbedtls_ecp_point,
        m: &mbedtls_mpi,
        p: &mbedtls_ecp_point,
        f_rng: MbedtlsFRng,
        p_rng: *mut c_void,
        rs_ctx: *mut MbedtlsEcpRestartCtx,
    ) -> Result<(), MbedtlsError> {
        let soft = |grp: &mut mbedtls_ecp_group, r: &mut mbedtls_ecp_point| unsafe {
            mbedtls_rs_sys::hook::ecp::ecp_mul_soft(grp, r, m, p, f_rng, p_rng, rs_ctx)
        };

        let Some(curve) = curve(grp) else {
            return soft(grp, r);
        };
        let size = curve.size();

        // The accelerator computes k * P for scalars in [1, N); everything
        // else (incl. the point-at-infinity results) goes to software
        if unsafe { mbedtls_mpi_cmp_int(m, 0) } <= 0
            || unsafe { mbedtls_mpi_cmp_mpi(m, &grp.N) } >= 0
        {
            return soft(grp, r);
        }

        let (Some(k), Some((px, py))) = (to_le(m, size), hw_point_operands(grp, p, size)) else {
            return soft(grp, r);
        };

        let mut rx = [0; MAX_SIZE];
        let mut ry = [0; MAX_SIZE];

        let on_curve = {
            // Verify-and-multiply: rejects points that are not on the curve
            let Ok(op) = EllipticCurve::affine_point_verification_multiplication(
                curve,
                &k[..size],
                &px[..size],
                &py[..size],
            ) else {
                return soft(grp, r);
            };

            let Ok(mut op) = op.with_affine_point_result(&mut rx[..size], &mut ry[..size]) else {
                return soft(grp, r);
            };

            op.process().wait_blocking();

            op.point_on_curve()
        };

        if !on_curve {
            // Keep behavior identical to the un-hooked build for invalid
            // points
            return soft(grp, r);
        }

        merr!(unsafe { mbedtls_mpi_read_binary_le(&mut r.private_X, rx.as_ptr(), size) })?;
        merr!(unsafe { mbedtls_mpi_read_binary_le(&mut r.private_Y, ry.as_ptr(), size) })?;
        merr!(unsafe { mbedtls_mpi_lset(&mut r.private_Z, 1) })?;

        Ok(())
    }
}

#[cfg(mbedtls_hook = "ecp_verify")]
impl mbedtls_rs_sys::hook::ecp::MbedtlsEcpVerify for EspEcc {
    fn check_pubkey(
        &self,
        grp: &mbedtls_ecp_group,
        pt: &mbedtls_ecp_point,
    ) -> Result<(), MbedtlsError> {
        let Some(curve) = curve(grp) else {
            return mbedtls_rs_sys::hook::ecp::ecp_check_pubkey_soft(grp, pt);
        };
        let size = curve.size();

        // Delegate the error paths (infinity, non-affine, out-of-range
        // coordinates) to software for canonical error codes
        let Some((px, py)) = hw_point_operands(grp, pt, size) else {
            return mbedtls_rs_sys::hook::ecp::ecp_check_pubkey_soft(grp, pt);
        };

        let Ok(mut op) = EllipticCurve::affine_point_verification(curve, &px[..size], &py[..size])
        else {
            return mbedtls_rs_sys::hook::ecp::ecp_check_pubkey_soft(grp, pt);
        };

        op.process().wait_blocking();

        if op.point_on_curve() {
            Ok(())
        } else {
            Err(MbedtlsError::new(MBEDTLS_ERR_ECP_INVALID_KEY))
        }
    }
}
