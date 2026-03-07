#include <stdint.h>

typedef struct mbedtls_sha1_context {
    __attribute__((aligned(16))) unsigned char work_area[MBEDTLS_SHA1_ALT_WORK_AREA_SIZE];
} mbedtls_sha1_context;
