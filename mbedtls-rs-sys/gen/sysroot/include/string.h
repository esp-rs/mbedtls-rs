#ifndef __STRING_H__
#define __STRING_H__

// For `size_t` (used by the `memset` wrapper below).
#include <stddef.h>

#define memcpy __builtin_memcpy
#define memcmp __builtin_memcmp

// `memset` must be a real (inline) function rather than a `#define` to
// `__builtin_memset`, because MbedTLS's default `mbedtls_platform_zeroize`
// (`library/platform_util.c`) takes its address (`memset_func = memset`). With
// the `#define`, that expands to `&__builtin_memset`, which Clang rejects under
// `-fbuiltin` ("builtin functions must be directly called"); taking the address
// of this inline wrapper is fine. `static inline` gives it internal linkage, so
// it never emits a global `memset` symbol and cannot collide with a libc
// `memset` at link time.
//
// (Providing this is what lets MbedTLS compile its own — stronger, portable —
// `mbedtls_platform_zeroize`, so `MBEDTLS_PLATFORM_ZEROIZE_ALT` no longer has to
// be forced on.)
static inline void *memset(void *s, int c, size_t n) {
  return __builtin_memset(s, c, n);
}

#define memmove __builtin_memmove

#define strlen __builtin_strlen
#define strcmp __builtin_strcmp
#define strncmp __builtin_strncmp
#define strstr __builtin_strstr
#define strchr __builtin_strchr
#define strncpy __builtin_strncpy

#endif
