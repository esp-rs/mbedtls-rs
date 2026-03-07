#include <stdint.h>

typedef struct mbedtls_sha256_context {
   __attribute__((aligned(16))) unsigned char work_area[MBEDTLS_SHA256_ALT_WORK_AREA_SIZE];
    unsigned char is224;
} mbedtls_sha256_context;
