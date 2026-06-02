//! Provide extra implementations to the generated bindings
#[cfg(feature = "x509-parse")]
use core::ffi::{c_char, c_int, CStr};

#[cfg(feature = "x509-parse")]
impl core::fmt::Debug for crate::bindings::mbedtls_x509_time {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            // ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.mon, self.day, self.hour, self.min, self.sec
        )
    }
}

#[cfg(feature = "x509-parse")]
impl core::fmt::Debug for crate::bindings::mbedtls_x509_crt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut crt: *const crate::bindings::mbedtls_x509_crt = self;
        let mut index = 0;
        let mut buf = [0u8; 1024];
        while !crt.is_null() {
            index += 1;
            buf.fill(0);
            let buf_ptr = buf.as_mut_ptr() as *mut c_char;
            let ret: c_int = unsafe {
                crate::bindings::mbedtls_x509_crt_info(buf_ptr, buf.len() - 1, c"".as_ptr(), crt)
            };
            if ret < 0 {
                writeln!(
                    f,
                    "Certificate #{}: mbedtls_x509_crt_info failed with code {}",
                    index, ret
                )?;
            } else {
                let cstr = unsafe { CStr::from_ptr(buf_ptr) };
                match cstr.to_str() {
                    Ok(s) => write!(f, "\nCertificate #{}:\n{}", index, s)?,
                    Err(_) => {
                        writeln!(f, "\nCertificate #{}: mbedtls_x509_crt_info returned invalid UTF-8 in output", index)?;
                        let slice = &buf[..buf.iter().position(|&b| b == 0).unwrap_or(buf.len())];
                        for line in slice.split(|&b| b == b'\n') {
                            writeln!(f, "{:?}", core::str::from_utf8(line))?;
                        }
                    }
                }
            }
            crt = unsafe { (*crt).next };
        }
        Ok(())
    }
}

#[cfg(feature = "pk")]
impl core::fmt::Debug for crate::bindings::mbedtls_pk_context {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // TODO: Implement helpful debug
        write!(f, "mbedtls_pk_context {{ .. }}")
    }
}
