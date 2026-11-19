#ifndef __WINDOWS_H__
#define __WINDOWS_H__

/*
 * The part of <windows.h> MbedTLS uses with the options this crate allows:
 * `SecureZeroMemory`, for `mbedtls_platform_zeroize` on `_WIN32`. As in the
 * Windows SDK, it is inline: volatile stores the compiler cannot remove.
 */

#include <stddef.h>

static __inline void *SecureZeroMemory(void *ptr, size_t cnt)
{
    volatile unsigned char *p = (volatile unsigned char *) ptr;

    while (cnt--) {
        *p++ = 0;
    }

    return ptr;
}

#endif
