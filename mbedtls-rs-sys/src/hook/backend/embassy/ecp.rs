//! Elliptic-curve implementations delegating to the `embassy-crypto` curve
//! drivers:
//! - [`EmbassyEcp`]: the ECP scalar multiplication, over the arithmetic
//!   drivers (`P256Arith`, `P384Arith`)
//! - [`EmbassyEcdsa`]: ECDSA signing and verification, over the ECDSA drivers
//!   (`P256Ecdsa`, `P384Ecdsa`)
//! - [`EmbassyEcdh`]: ECDH key generation and shared secrets, over the ECDH
//!   drivers (`P256Ecdh`, `P384Ecdh`)
//!
//! Each is generic over the set of curves it serves (see [`EmbassyCurves`]),
//! and uses the drivers of those curves only.
//!
//! Operands the drivers are not given - other curves, scalars (private keys,
//! signature components) outside `[1, n)`, non-affine points, coordinates
//! outside `[0, p)` - are delegated to the MbedTLS software implementation,
//! and so are the operations a driver rejects (e.g. for a public key not on
//! the curve) or fails, except for signatures that do not verify. Behavior -
//! error codes included - thus stays identical to the un-hooked build for
//! everything the drivers do not cover.
//!
//! The drivers are constant-time by contract, so the MbedTLS coordinate
//! blinding (and its RNG) is not needed. The ECDSA drivers draw their
//! signature nonces from the `embassy-crypto` `Rng` driver, also by contract:
//! their signatures are randomized, even where MbedTLS asks for deterministic
//! (RFC 6979) ones - as `mbedtls_ecdsa_write_signature`, and thus the PK and
//! TLS layers, do with the `alg-ecdsa` feature (`MBEDTLS_ECDSA_DETERMINISTIC`).

use core::marker::PhantomData;

use crate::{
    mbedtls_ecp_group, mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1,
    mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP384R1, mbedtls_ecp_point, mbedtls_ecp_point_cmp,
    mbedtls_mpi, mbedtls_mpi_cmp_int, mbedtls_mpi_cmp_mpi, mbedtls_mpi_lset,
    mbedtls_mpi_read_binary, mbedtls_mpi_write_binary, merr, MbedtlsError,
    MBEDTLS_ERR_ECP_VERIFY_FAILED,
};

/// A set of curves served by `embassy-crypto` drivers, as used by
/// [`EmbassyEcp`], [`EmbassyEcdsa`] and [`EmbassyEcdh`].
///
/// Implemented by [`P256`] and [`P384`], and by pairs of sets: `(P256, P384)`
/// serves both curves.
///
/// The operations return `None` - leaving their outputs untouched - if the
/// curve of `grp` is not in the set, or the operands are not ones the drivers
/// are given (see the module docs); the caller then falls back to the software
/// implementation.
pub trait EmbassyCurves {
    /// Whether the curve of `grp` is in the set
    fn serves(grp: &mbedtls_ecp_group) -> bool;

    /// `r = m * p`, with the arithmetic driver of the curve
    fn mul(
        grp: &mbedtls_ecp_group,
        r: &mut mbedtls_ecp_point,
        m: &mbedtls_mpi,
        p: &mbedtls_ecp_point,
    ) -> Option<Result<(), MbedtlsError>>;

    /// The ECDSA signature `(r, s)` of the message hash `hash` with the
    /// private key `d`, with the ECDSA driver of the curve
    fn ecdsa_sign(
        grp: &mbedtls_ecp_group,
        r: &mut mbedtls_mpi,
        s: &mut mbedtls_mpi,
        d: &mbedtls_mpi,
        hash: &[u8],
    ) -> Option<Result<(), MbedtlsError>>;

    /// Verify the ECDSA signature `(r, s)` of the message hash `hash` with
    /// the public key `q`, with the ECDSA driver of the curve.
    ///
    /// Signatures that do not verify are reported with
    /// `MBEDTLS_ERR_ECP_VERIFY_FAILED`.
    fn ecdsa_verify(
        grp: &mbedtls_ecp_group,
        hash: &[u8],
        q: &mbedtls_ecp_point,
        r: &mbedtls_mpi,
        s: &mbedtls_mpi,
    ) -> Option<Result<(), MbedtlsError>>;

    /// The ECDH public key `q = d * G` of the private key `d`, with the ECDH
    /// driver of the curve
    fn ecdh_public_key(
        grp: &mbedtls_ecp_group,
        q: &mut mbedtls_ecp_point,
        d: &mbedtls_mpi,
    ) -> Option<Result<(), MbedtlsError>>;

    /// The ECDH shared secret `z` of the private key `d` and the peer's
    /// public key `q` (the X coordinate of `d * q`), with the ECDH driver of
    /// the curve
    fn ecdh_shared_secret(
        grp: &mbedtls_ecp_group,
        z: &mut mbedtls_mpi,
        q: &mbedtls_ecp_point,
        d: &mbedtls_mpi,
    ) -> Option<Result<(), MbedtlsError>>;
}

impl<A, B> EmbassyCurves for (A, B)
where
    A: EmbassyCurves,
    B: EmbassyCurves,
{
    fn serves(grp: &mbedtls_ecp_group) -> bool {
        A::serves(grp) || B::serves(grp)
    }

    fn mul(
        grp: &mbedtls_ecp_group,
        r: &mut mbedtls_ecp_point,
        m: &mbedtls_mpi,
        p: &mbedtls_ecp_point,
    ) -> Option<Result<(), MbedtlsError>> {
        A::mul(grp, r, m, p).or_else(|| B::mul(grp, r, m, p))
    }

    fn ecdsa_sign(
        grp: &mbedtls_ecp_group,
        r: &mut mbedtls_mpi,
        s: &mut mbedtls_mpi,
        d: &mbedtls_mpi,
        hash: &[u8],
    ) -> Option<Result<(), MbedtlsError>> {
        A::ecdsa_sign(grp, r, s, d, hash).or_else(|| B::ecdsa_sign(grp, r, s, d, hash))
    }

    fn ecdsa_verify(
        grp: &mbedtls_ecp_group,
        hash: &[u8],
        q: &mbedtls_ecp_point,
        r: &mbedtls_mpi,
        s: &mbedtls_mpi,
    ) -> Option<Result<(), MbedtlsError>> {
        A::ecdsa_verify(grp, hash, q, r, s).or_else(|| B::ecdsa_verify(grp, hash, q, r, s))
    }

    fn ecdh_public_key(
        grp: &mbedtls_ecp_group,
        q: &mut mbedtls_ecp_point,
        d: &mbedtls_mpi,
    ) -> Option<Result<(), MbedtlsError>> {
        A::ecdh_public_key(grp, q, d).or_else(|| B::ecdh_public_key(grp, q, d))
    }

    fn ecdh_shared_secret(
        grp: &mbedtls_ecp_group,
        z: &mut mbedtls_mpi,
        q: &mbedtls_ecp_point,
        d: &mbedtls_mpi,
    ) -> Option<Result<(), MbedtlsError>> {
        A::ecdh_shared_secret(grp, z, q, d).or_else(|| B::ecdh_shared_secret(grp, z, q, d))
    }
}

macro_rules! embassy_curve {
    ($(#[$meta:meta])* $name:ident, $curve:ident, $group_id:ident, $size:literal) => {
        $(#[$meta])*
        pub enum $name {}

        impl EmbassyCurves for $name {
            fn serves(grp: &mbedtls_ecp_group) -> bool {
                grp.id == $group_id
            }

            fn mul(
                grp: &mbedtls_ecp_group,
                r: &mut mbedtls_ecp_point,
                m: &mbedtls_mpi,
                p: &mbedtls_ecp_point,
            ) -> Option<Result<(), MbedtlsError>> {
                use embassy_crypto::$curve::{Point, Scalar};

                if !Self::serves(grp) {
                    return None;
                }

                let k = Scalar::from_bytes(&scalar_operand::<$size>(grp, m)?.0).ok()?;

                let result = if unsafe { mbedtls_ecp_point_cmp(p, &grp.G) } == 0 {
                    Point::mul_base(&k)
                } else {
                    let (x, y) = point_operands::<$size>(grp, p)?;

                    // Checks that the point is on the curve
                    Point::from_xy(&x, &y).ok()?.mul(&k)
                };

                // `k` is in `[1, n)` and the curve has prime order, so the
                // result is never the point at infinity
                let result = result.to_affine()?;

                Some(write_point(r, &result.x, &result.y))
            }

            fn ecdsa_sign(
                grp: &mbedtls_ecp_group,
                r: &mut mbedtls_mpi,
                s: &mut mbedtls_mpi,
                d: &mbedtls_mpi,
                hash: &[u8],
            ) -> Option<Result<(), MbedtlsError>> {
                use embassy_crypto::$curve::SigningKey;

                if !Self::serves(grp) {
                    return None;
                }

                let signature = SigningKey::from_bytes(&scalar_operand::<$size>(grp, d)?.0)
                    .ok()?
                    .sign_prehash(&hash_operand::<$size>(hash))
                    .ok()?;

                Some(write_signature(r, s, signature.r(), signature.s()))
            }

            fn ecdsa_verify(
                grp: &mbedtls_ecp_group,
                hash: &[u8],
                q: &mbedtls_ecp_point,
                r: &mbedtls_mpi,
                s: &mbedtls_mpi,
            ) -> Option<Result<(), MbedtlsError>> {
                use embassy_crypto::$curve::{Signature, VerifyingKey};

                if !Self::serves(grp) {
                    return None;
                }

                let (x, y) = point_operands::<$size>(grp, q)?;
                let signature = Signature::from_scalars(
                    &scalar_operand::<$size>(grp, r)?.0,
                    &scalar_operand::<$size>(grp, s)?.0,
                )
                .ok()?;

                // Checks that the public key is on the curve
                match VerifyingKey::from_xy(&x, &y)
                    .verify_prehash(&hash_operand::<$size>(hash), &signature)
                {
                    Ok(()) => Some(Ok(())),
                    Err(embassy_crypto::Error::InvalidSignature) => {
                        Some(Err(MbedtlsError::new(MBEDTLS_ERR_ECP_VERIFY_FAILED)))
                    }
                    Err(_) => None,
                }
            }

            fn ecdh_public_key(
                grp: &mbedtls_ecp_group,
                q: &mut mbedtls_ecp_point,
                d: &mbedtls_mpi,
            ) -> Option<Result<(), MbedtlsError>> {
                use embassy_crypto::$curve::SecretKey;

                if !Self::serves(grp) {
                    return None;
                }

                let public = SecretKey::from_bytes(&scalar_operand::<$size>(grp, d)?.0)
                    .ok()?
                    .public_key()
                    .ok()?;

                Some(write_point(q, public.x(), public.y()))
            }

            fn ecdh_shared_secret(
                grp: &mbedtls_ecp_group,
                z: &mut mbedtls_mpi,
                q: &mbedtls_ecp_point,
                d: &mbedtls_mpi,
            ) -> Option<Result<(), MbedtlsError>> {
                use embassy_crypto::$curve::{PublicKey, SecretKey};

                if !Self::serves(grp) {
                    return None;
                }

                let (x, y) = point_operands::<$size>(grp, q)?;
                let secret = SecretKey::from_bytes(&scalar_operand::<$size>(grp, d)?.0)
                    .ok()?
                    // Checks that the peer's public key is on the curve
                    .diffie_hellman(&PublicKey::from_xy(&x, &y))
                    .ok()?;

                Some(write_mpi(z, secret.as_bytes()))
            }
        }
    };
}

embassy_curve!(
    /// NIST P-256 (secp256r1), served by the `embassy-crypto` `P256Arith`,
    /// `P256Ecdsa` and `P256Ecdh` drivers
    P256,
    p256,
    mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1,
    32
);

embassy_curve!(
    /// NIST P-384 (secp384r1), served by the `embassy-crypto` `P384Arith`,
    /// `P384Ecdsa` and `P384Ecdh` drivers
    P384,
    p384,
    mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP384R1,
    48
);

/// A big-endian scalar operand, wiped when dropped as it may be a private key
struct SecretOperand<const N: usize>([u8; N]);

impl<const N: usize> Drop for SecretOperand<N> {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            // Volatile, so that the wipe is not optimized away
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
    }
}

/// Serialize an MPI to the fixed-size big-endian representation used by the
/// drivers. `None` if the value does not fit.
fn to_be<const N: usize>(mpi: &mbedtls_mpi) -> Option<[u8; N]> {
    let mut buf = [0; N];

    merr!(unsafe { mbedtls_mpi_write_binary(mpi, buf.as_mut_ptr(), N) })
        .ok()
        .map(|_| buf)
}

/// The scalar (a multiplier, a private key, a signature component), if it is
/// in `[1, n)` - the range MbedTLS accepts for those
fn scalar_operand<const N: usize>(
    grp: &mbedtls_ecp_group,
    m: &mbedtls_mpi,
) -> Option<SecretOperand<N>> {
    if unsafe { mbedtls_mpi_cmp_int(m, 0) } <= 0 || unsafe { mbedtls_mpi_cmp_mpi(m, &grp.N) } >= 0 {
        return None;
    }

    to_be(m).map(SecretOperand)
}

/// The coordinates of the point, if it has affine (Z == 1) representation
/// and in-range, non-negative coordinates
fn point_operands<const N: usize>(
    grp: &mbedtls_ecp_group,
    pt: &mbedtls_ecp_point,
) -> Option<([u8; N], [u8; N])> {
    if unsafe { mbedtls_mpi_cmp_int(&pt.private_Z, 1) } != 0 {
        return None;
    }

    if unsafe { mbedtls_mpi_cmp_int(&pt.private_X, 0) } < 0
        || unsafe { mbedtls_mpi_cmp_int(&pt.private_Y, 0) } < 0
        || unsafe { mbedtls_mpi_cmp_mpi(&pt.private_X, &grp.P) } >= 0
        || unsafe { mbedtls_mpi_cmp_mpi(&pt.private_Y, &grp.P) } >= 0
    {
        return None;
    }

    Some((to_be(&pt.private_X)?, to_be(&pt.private_Y)?))
}

/// The message hash as the `N`-byte digest the ECDSA drivers take: its
/// leftmost `N` bytes, left-padded with zeros if shorter - the integer ECDSA
/// signs, for curves whose order is `N` bytes wide
fn hash_operand<const N: usize>(hash: &[u8]) -> [u8; N] {
    let mut digest = [0; N];
    let len = hash.len().min(N);

    digest[N - len..].copy_from_slice(&hash[..len]);

    digest
}

fn write_mpi(mpi: &mut mbedtls_mpi, value: &[u8]) -> Result<(), MbedtlsError> {
    merr!(unsafe { mbedtls_mpi_read_binary(mpi, value.as_ptr(), value.len()) })?;

    Ok(())
}

fn write_point(r: &mut mbedtls_ecp_point, x: &[u8], y: &[u8]) -> Result<(), MbedtlsError> {
    write_mpi(&mut r.private_X, x)?;
    write_mpi(&mut r.private_Y, y)?;
    merr!(unsafe { mbedtls_mpi_lset(&mut r.private_Z, 1) })?;

    Ok(())
}

fn write_signature(
    r: &mut mbedtls_mpi,
    s: &mut mbedtls_mpi,
    r_value: &[u8],
    s_value: &[u8],
) -> Result<(), MbedtlsError> {
    write_mpi(r, r_value)?;
    write_mpi(s, s_value)
}

/// ECP scalar multiplication delegating to the `embassy-crypto` arithmetic
/// drivers of the curves in `C` - by default P-256 only, e.g.
/// `EmbassyEcp<(P256, P384)>` serves P-384 as well - and to the MbedTLS
/// software implementation for everything else.
pub struct EmbassyEcp<C = P256>(PhantomData<fn() -> C>);

impl<C> EmbassyEcp<C> {
    /// Create a new `EmbassyEcp` instance
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<C> Default for EmbassyEcp<C> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "nohook-ecp-mul"))]
impl<C> crate::hook::ecp::MbedtlsEcpMul for EmbassyEcp<C>
where
    C: EmbassyCurves,
{
    unsafe fn mul(
        &self,
        grp: &mut mbedtls_ecp_group,
        r: &mut mbedtls_ecp_point,
        m: &mbedtls_mpi,
        p: &mbedtls_ecp_point,
        f_rng: crate::hook::ecp::MbedtlsFRng,
        p_rng: *mut core::ffi::c_void,
        rs_ctx: *mut crate::hook::ecp::MbedtlsEcpRestartCtx,
    ) -> Result<(), MbedtlsError> {
        match C::mul(grp, r, m, p) {
            Some(result) => result,
            None => unsafe { crate::hook::ecp::ecp_mul_soft(grp, r, m, p, f_rng, p_rng, rs_ctx) },
        }
    }
}

/// ECDSA delegating to the `embassy-crypto` ECDSA drivers of the curves in
/// `C` - by default P-256 only, e.g. `EmbassyEcdsa<(P256, P384)>` serves
/// P-384 as well - and to the MbedTLS software implementation for everything
/// else.
pub struct EmbassyEcdsa<C = P256>(PhantomData<fn() -> C>);

impl<C> EmbassyEcdsa<C> {
    /// Create a new `EmbassyEcdsa` instance
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<C> Default for EmbassyEcdsa<C> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(
    feature = "alg-ecdsa",
    not(feature = "nohook-ecdsa"),
    not(feature = "ecp-restartable")
))]
impl<C> crate::hook::ecdsa::MbedtlsEcdsa for EmbassyEcdsa<C>
where
    C: EmbassyCurves,
{
    unsafe fn sign(
        &self,
        grp: &mut mbedtls_ecp_group,
        r: &mut mbedtls_mpi,
        s: &mut mbedtls_mpi,
        d: &mbedtls_mpi,
        hash: &[u8],
        f_rng: crate::hook::ecp::MbedtlsFRng,
        p_rng: *mut core::ffi::c_void,
    ) -> Result<(), MbedtlsError> {
        match C::ecdsa_sign(grp, r, s, d, hash) {
            Some(result) => result,
            None => unsafe {
                crate::hook::ecdsa::ecdsa_sign_soft(grp, r, s, d, hash, f_rng, p_rng)
            },
        }
    }

    fn verify(
        &self,
        grp: &mut mbedtls_ecp_group,
        hash: &[u8],
        q: &mbedtls_ecp_point,
        r: &mbedtls_mpi,
        s: &mbedtls_mpi,
    ) -> Result<(), MbedtlsError> {
        match C::ecdsa_verify(grp, hash, q, r, s) {
            Some(result) => result,
            None => crate::hook::ecdsa::ecdsa_verify_soft(grp, hash, q, r, s),
        }
    }
}

/// ECDH delegating to the `embassy-crypto` ECDH drivers of the curves in `C`
/// - by default P-256 only, e.g. `EmbassyEcdh<(P256, P384)>` serves P-384 as
///   well - and to the MbedTLS software implementation for everything else.
///
/// The private keys of the generated key pairs are drawn from the RNG
/// MbedTLS passes, as in the software implementation.
pub struct EmbassyEcdh<C = P256>(PhantomData<fn() -> C>);

impl<C> EmbassyEcdh<C> {
    /// Create a new `EmbassyEcdh` instance
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<C> Default for EmbassyEcdh<C> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(
    feature = "alg-ecdh",
    not(feature = "nohook-ecdh"),
    not(feature = "ecp-restartable")
))]
impl<C> crate::hook::ecdh::MbedtlsEcdh for EmbassyEcdh<C>
where
    C: EmbassyCurves,
{
    unsafe fn gen_public(
        &self,
        grp: &mut mbedtls_ecp_group,
        d: &mut mbedtls_mpi,
        q: &mut mbedtls_ecp_point,
        f_rng: crate::hook::ecp::MbedtlsFRng,
        p_rng: *mut core::ffi::c_void,
    ) -> Result<(), MbedtlsError> {
        if !C::serves(grp) {
            return unsafe { crate::hook::ecdh::ecdh_gen_public_soft(grp, d, q, f_rng, p_rng) };
        }

        merr!(unsafe { crate::mbedtls_ecp_gen_privkey(grp, d, f_rng, p_rng) })?;

        match C::ecdh_public_key(grp, q, d) {
            Some(result) => result,
            None => {
                // As the software implementation does
                let grp: *mut mbedtls_ecp_group = grp;
                merr!(unsafe {
                    crate::mbedtls_ecp_mul(grp, q, d, &raw const (*grp).G, f_rng, p_rng)
                })?;

                Ok(())
            }
        }
    }

    unsafe fn compute_shared(
        &self,
        grp: &mut mbedtls_ecp_group,
        z: &mut mbedtls_mpi,
        q: &mbedtls_ecp_point,
        d: &mbedtls_mpi,
        f_rng: crate::hook::ecp::MbedtlsFRng,
        p_rng: *mut core::ffi::c_void,
    ) -> Result<(), MbedtlsError> {
        match C::ecdh_shared_secret(grp, z, q, d) {
            Some(result) => result,
            None => unsafe {
                crate::hook::ecdh::ecdh_compute_shared_soft(grp, z, q, d, f_rng, p_rng)
            },
        }
    }
}
