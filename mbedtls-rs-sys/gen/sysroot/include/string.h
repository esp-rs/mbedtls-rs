#ifndef __STRING_H__
#define __STRING_H__

// For `size_t` (used by the `memset` declaration below).
#include <stddef.h>

#define memcpy __builtin_memcpy
#define memcmp __builtin_memcmp

// `memset` is *declared* but intentionally NOT defined here (and is NOT a
// `#define` to `__builtin_memset`). MbedTLS's default `mbedtls_platform_zeroize`
// (`library/platform_util.c`) takes its address (`memset_func = memset`); a
// `#define memset __builtin_memset` would make that `&__builtin_memset`, which
// Clang rejects under `-fbuiltin` ("builtin functions must be directly called").
//
// A bare declaration sidesteps that: `&memset` references an ordinary external
// symbol (resolved at link time — by libc on std targets, by the `tinyrlibc`
// polyfill on `core`-only targets), while *direct* `memset(...)` calls are still
// lowered to the `__builtin_memset` fast path by `-fbuiltin`. Providing a body
// here would be a trap: under `-fbuiltin`, `__builtin_memset` with a runtime
// length lowers back to a *call to `memset`*, so any in-header definition risks
// recursing into itself (a `jmp memset` spin in `mbedtls_platform_zeroize`).
// Leaving it undefined avoids that class of bug entirely.
//
// (This is what lets MbedTLS compile its own — stronger, portable —
// `mbedtls_platform_zeroize`, so `MBEDTLS_PLATFORM_ZEROIZE_ALT` no longer has to
// be forced on.)
void *memset(void *s, int c, size_t n);

#define memmove __builtin_memmove

#define strlen __builtin_strlen
#define strcmp __builtin_strcmp
#define strncmp __builtin_strncmp
#define strstr __builtin_strstr
#define strchr __builtin_strchr
#define strncpy __builtin_strncpy

#endif
