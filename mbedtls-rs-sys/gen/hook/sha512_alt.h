#include <stdint.h>

typedef struct mbedtls_sha512_context {
   __attribute__((aligned(16))) unsigned char work_area[MBEDTLS_SHA512_ALT_WORK_AREA_SIZE];
    unsigned char is384;
} mbedtls_sha512_context;
