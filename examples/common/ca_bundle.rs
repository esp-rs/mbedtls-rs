//! A sample implementation of the verification callback for
//! `ClientSessionConfig::verify_callback`: how a caller plugs in its own
//! source of trust instead of a parsed `ca_chain`.
//!
//! The trust store is a flash-resident bundle in esp-idf's
//! `x509_crt_bundle` binary format (the format of the `x509_crt_bundle.bin`
//! built into esp-idf firmware): each root contributes only its
//! DER-encoded subject Name and SubjectPublicKeyInfo, packed with an offset
//! index, so a handshake binary-searches roots directly in flash and only
//! materializes the one public key the peer chain actually needs. Generate
//! the binary with esp-idf's `gen_crt_bundle.py` from any PEM/DER
//! certificate list (see `examples/common/certs/README.md`).
//!
//! The callback follows esp-idf's `esp_crt_verify_callback`. MbedTLS still
//! runs its standard chain verification (expiry, signatures, hostname,
//! profile); the callback only intervenes when a certificate's sole
//! problem is an untrusted issuer, which is what the placeholder CA chain
//! installed alongside the callback reports for the self-signed top of
//! the peer chain. Any other verdict stands exactly as MbedTLS judged it.
//! Trust is then established by finding a root in the store whose subject
//! Name equals that certificate's issuer Name and verifying the
//! certificate's signature with the root's public key.
//!
//! Note what that means for cross-signed chains: the root the callback
//! has to carry is the one that signed the chain top the server actually
//! sent, which can differ from the root a parsed `ca_chain` would use
//! (Mbed TLS completes a chain by matching an intermediate's issuer
//! against the trust store, so a cross-signed variant is never reached).
//! A server behind a rotating cross-signature needs both roots in the
//! bundle.
//!
//! Wire format (all integers little-endian, as produced by
//! `gen_crt_bundle.py`):
//!
//! ```text
//! [u32 offset] * count      // offsets of the entries, ascending with the sorted Names
//! entry: [u16 name_len][u16 key_len][Name DER][SubjectPublicKeyInfo DER]
//! ```
//!
//! There is no explicit count field: the first offset is the size of the
//! offset index itself, so `count = offsets[0] / 4`.

use core::ffi::{c_int, c_void};

use mbedtls_rs::sys::*;
use mbedtls_rs::VerifyCallback;

/// Minimum size: one offset entry plus one entry header.
const OFFSET_LEN: usize = 4;
const ENTRY_HEADER_LEN: usize = 4;

/// A validated view over a flash-resident CA bundle. Holds no state beyond
/// the slice, so it is zero-cost to create and copy.
pub struct CaBundle<'a> {
    data: &'a [u8],
    count: usize,
}

impl<'a> CaBundle<'a> {
    /// Validate the layout without allocating: the first offset must be a
    /// non-zero multiple of 4, every indexed offset must match a sequential
    /// walk of the entry region, the Names must be sorted (the
    /// binary-search precondition), and the walk must consume the buffer
    /// exactly.
    pub fn new(data: &'a [u8]) -> Result<Self, &'static str> {
        if data.len() < OFFSET_LEN {
            return Err("CA bundle too small");
        }
        // The first offset doubles as the index size, hence the entry count.
        let index_end = read_u32(data, 0) as usize;
        if index_end == 0 || index_end % OFFSET_LEN != 0 {
            return Err("CA bundle index invalid");
        }
        let count = index_end / OFFSET_LEN;
        if count == 0 || index_end > data.len() {
            return Err("CA bundle empty index");
        }
        let bundle = Self { data, count };
        let mut offset = index_end;
        let mut previous: Option<&[u8]> = None;
        for index in 0..count {
            if offset != bundle.entry_offset(index) {
                return Err("CA bundle index mismatch");
            }
            let (name, _, end) = bundle.entry(index).ok_or("CA bundle entry invalid")?;
            if let Some(previous) = previous {
                if previous > name {
                    return Err("CA bundle unsorted");
                }
            }
            previous = Some(name);
            offset = end;
        }
        if offset != data.len() {
            return Err("CA bundle trailing bytes");
        }
        Ok(bundle)
    }

    fn entry_offset(&self, index: usize) -> usize {
        read_u32(self.data, index * OFFSET_LEN) as usize
    }

    /// `(Name, SubjectPublicKeyInfo, entry end)` for entry `index`, or
    /// `None` when the entry header or lengths run past the buffer.
    fn entry(&self, index: usize) -> Option<(&'a [u8], &'a [u8], usize)> {
        let data = self.data;
        let offset = self.entry_offset(index);
        // Checked arithmetic: a corrupted offset must not wrap on a 32-bit
        // target and slip past the bounds check.
        let header_end = offset.checked_add(ENTRY_HEADER_LEN)?;
        if header_end > data.len() {
            return None;
        }
        let name_len = read_u16(data, offset) as usize;
        let key_len = read_u16(data, offset + 2) as usize;
        let name_at = header_end;
        let key_at = name_at.checked_add(name_len)?;
        let end = key_at.checked_add(key_len)?;
        if end > data.len() {
            return None;
        }
        Some((&data[name_at..key_at], &data[key_at..end], end))
    }

    fn entry_name(&self, index: usize) -> Option<&'a [u8]> {
        self.entry(index).map(|(name, _, _)| name)
    }

    /// Every SubjectPublicKeyInfo whose subject Name equals `issuer`, in
    /// entry order. An empty iterator means no root signed the chain.
    pub fn lookup(&self, issuer: &[u8]) -> SpkiIter<'a, '_> {
        // Leftmost binary search over the sorted Names.
        let mut low = 0;
        let mut high = self.count;
        while low < high {
            let middle = (low + high) / 2;
            match self.entry_name(middle).unwrap_or(&[]).cmp(issuer) {
                core::cmp::Ordering::Less => low = middle + 1,
                _ => high = middle,
            }
        }
        let mut end = low;
        while end < self.count && self.entry_name(end).unwrap_or(&[]) == issuer {
            end += 1;
        }
        SpkiIter {
            bundle: self,
            next: low,
            end,
        }
    }

    /// The verification callback for this bundle, to be set as
    /// `ClientSessionConfig::verify_callback`.
    ///
    /// The returned callback borrows `self` through `p_ctx`: the bundle
    /// must stay alive, and be left alone, for as long as any session
    /// configured with it lives. A bundle over a `static` slice satisfies
    /// this trivially.
    pub fn verify_callback(&self) -> VerifyCallback {
        VerifyCallback {
            f: verify,
            p_ctx: self as *const _ as *mut c_void,
        }
    }
}

/// Iterator over the SubjectPublicKeyInfos of all entries matching a Name.
pub struct SpkiIter<'a, 'b> {
    bundle: &'b CaBundle<'a>,
    next: usize,
    end: usize,
}

impl<'a> Iterator for SpkiIter<'a, '_> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.end {
            return None;
        }
        let (_, spki, _) = self.bundle.entry(self.next)?;
        self.next += 1;
        Some(spki)
    }
}

fn read_u16(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}

fn read_u32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([
        data[at],
        data[at + 1],
        data[at + 2],
        data[at + 3],
    ])
}

/// The sample verification callback.
///
/// Returns `0` to keep MbedTLS's verdict (accepting the certificate when
/// `*flags` is left at zero, or keeping whatever problems MbedTLS found
/// otherwise), and `MBEDTLS_ERR_X509_FATAL_ERROR` to abort the handshake
/// when no root in the bundle backs the certificate.
unsafe extern "C" fn verify(
    p_ctx: *mut c_void,
    crt: *mut mbedtls_x509_crt,
    _depth: c_int,
    flags: *mut u32,
) -> c_int {
    // MbedTLS passes `p_ctx` through untouched; treat it as the shared
    // borrow `verify_callback` handed out.
    let bundle = unsafe { &*(p_ctx as *const CaBundle<'_>) };
    let child = unsafe { &*crt };
    // A weak hash on a would-be trusted root is fine: acceptance is
    // decided by the actual signature check below. Any other problem
    // (expired, wrong hostname, bad signature...) is left as MbedTLS
    // judged it.
    if unsafe { *flags } & !MBEDTLS_X509_BADCERT_BAD_MD
        != MBEDTLS_X509_BADCERT_NOT_TRUSTED
    {
        return 0;
    }
    let issuer = unsafe {
        core::slice::from_raw_parts(child.issuer_raw.p, child.issuer_raw.len)
    };
    for spki in bundle.lookup(issuer) {
        if unsafe { check_signature(child, spki) } {
            unsafe { *flags &= !MBEDTLS_X509_BADCERT_NOT_TRUSTED };
            return 0;
        }
    }
    MBEDTLS_ERR_X509_FATAL_ERROR as c_int
}

/// Whether `child`'s signature verifies with a root's SubjectPublicKeyInfo
/// (esp-idf's `esp_crt_check_signature`): parse only that key (the
/// transient allocation of a handshake), hash the child's TBSCertificate
/// with the child's signature hash algorithm, and verify the child's
/// signature.
unsafe fn check_signature(child: &mbedtls_x509_crt, spki: &[u8]) -> bool {
    // A zeroed `mbedtls_x509_crt` is the state `mbedtls_x509_crt_init`
    // leaves behind; `mbedtls_x509_crt_free` releases whatever
    // `mbedtls_pk_parse_public_key` allocated into `pk`.
    let mut parent: mbedtls_x509_crt = unsafe { core::mem::zeroed() };
    unsafe { mbedtls_x509_crt_init(&mut parent) };
    let verified = unsafe { check_signature_inner(&mut parent, child, spki) };
    unsafe { mbedtls_x509_crt_free(&mut parent) };
    verified
}

unsafe fn check_signature_inner(
    parent: &mut mbedtls_x509_crt,
    child: &mbedtls_x509_crt,
    spki: &[u8],
) -> bool {
    if unsafe { mbedtls_pk_parse_public_key(&mut parent.pk, spki.as_ptr(), spki.len()) } != 0 {
        return false;
    }
    if unsafe { mbedtls_pk_can_do(&parent.pk, child.private_sig_pk) } == 0 {
        return false;
    }
    let md_info = unsafe { mbedtls_md_info_from_type(child.private_sig_md) };
    if md_info.is_null() {
        return false;
    }
    let mut hash = [0u8; MBEDTLS_MD_MAX_SIZE as usize];
    if unsafe { mbedtls_md(md_info, child.tbs.p, child.tbs.len, hash.as_mut_ptr()) } != 0 {
        return false;
    }
    // `private_sig_opts` carries the RSASSA-PSS parameters when the child
    // is signed with PSS.
    let verified = unsafe {
        mbedtls_pk_verify_ext(
            child.private_sig_pk,
            child.private_sig_opts as *const c_void,
            &mut parent.pk,
            child.private_sig_md,
            hash.as_ptr(),
            mbedtls_md_get_size(md_info) as usize,
            child.private_sig.p,
            child.private_sig.len,
        )
    };
    verified == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &[u8], key: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(key.len() as u16).to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(key);
        out
    }

    /// Assemble a bundle from `(name, key)` pairs, sorted by name like the
    /// generator does.
    fn bundle(pairs: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut sorted: Vec<_> = pairs.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        let mut out = Vec::new();
        out.resize(4 * sorted.len(), 0);
        let index_end = out.len();
        for (index, (name, key)) in sorted.iter().enumerate() {
            let offset = out.len();
            out[4 * index..4 * index + 4].copy_from_slice(&(offset as u32).to_le_bytes());
            out.extend_from_slice(&entry(name, key));
        }
        out[0..4].copy_from_slice(&(index_end as u32).to_le_bytes());
        out
    }

    #[test]
    fn lookup_finds_matching_issuer() {
        let data = bundle(&[(b"issuer-a", b"key-a"), (b"issuer-b", b"key-b")]);
        let parsed = CaBundle::new(&data).expect("valid");
        let keys: Vec<&[u8]> = parsed.lookup(b"issuer-b").collect();
        assert_eq!(keys, vec![&b"key-b"[..]]);
    }

    #[test]
    fn lookup_misses_unknown_issuer() {
        let data = bundle(&[(b"issuer-a", b"key-a")]);
        let parsed = CaBundle::new(&data).expect("valid");
        assert_eq!(parsed.lookup(b"issuer-z").count(), 0);
        assert_eq!(parsed.lookup(b"issuer").count(), 0);
        assert_eq!(parsed.lookup(b"").count(), 0);
    }

    #[test]
    fn duplicate_names_yield_all_keys_in_order() {
        let data = bundle(&[
            (b"same", b"key-first"),
            (b"same", b"key-second"),
            (b"other", b"key-other"),
        ]);
        let parsed = CaBundle::new(&data).expect("valid");
        let keys: Vec<&[u8]> = parsed.lookup(b"same").collect();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&&b"key-first"[..]));
        assert!(keys.contains(&&b"key-second"[..]));
    }

    #[test]
    fn lookup_uses_binary_search_over_many_entries() {
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..300u32)
            .map(|n| {
                (
                    format!("issuer-{:03}", n).into_bytes(),
                    n.to_le_bytes().to_vec(),
                )
            })
            .collect();
        let refs: Vec<(&[u8], &[u8])> = pairs
            .iter()
            .map(|(n, k)| (n.as_slice(), k.as_slice()))
            .collect();
        let data = bundle(&refs);
        let parsed = CaBundle::new(&data).expect("valid");
        for n in [0u32, 1, 150, 299] {
            let keys: Vec<&[u8]> = parsed
                .lookup(format!("issuer-{:03}", n).as_bytes())
                .collect();
            assert_eq!(keys, vec![n.to_le_bytes().as_slice()]);
        }
        assert_eq!(parsed.lookup(b"issuer-300").count(), 0);
    }

    #[test]
    fn rejects_broken_layouts() {
        assert!(CaBundle::new(&[]).is_err());
        assert!(CaBundle::new(&[0, 0, 0, 0]).is_err());
        assert!(CaBundle::new(&[1, 0, 0, 0]).is_err());
        assert!(CaBundle::new(&[3, 0, 0, 0]).is_err());
        // Count claims two entries but only one is present.
        let one = bundle(&[(b"a", b"k")]);
        let mut two_count = one.clone();
        // First offset says 8 (two index entries) but the walk never finds
        // the second entry.
        two_count[0] = 8;
        assert!(CaBundle::new(&two_count).is_err());
        // Trailing bytes after the last entry.
        let mut trailing = one.clone();
        trailing.push(0);
        assert!(CaBundle::new(&trailing).is_err());
    }
}
