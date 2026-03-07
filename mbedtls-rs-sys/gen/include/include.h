#include "mbedtls/platform.h"

#include "mbedtls/aes.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ccm.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/cipher.h"
#include "mbedtls/cmac.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/dhm.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecjpake.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/lms.h"
#include "mbedtls/md.h"
#include "mbedtls/md5.h"
#include "mbedtls/nist_kw.h"
#include "mbedtls/oid.h"
#include "mbedtls/pem.h"
#include "mbedtls/pk.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/pkcs7.h"
#include "mbedtls/pkcs12.h"
#include "mbedtls/poly1305.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/ssl_ciphersuites.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/ssl_ticket.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509.h"

#include "psa/crypto.h"

// Provides a function prototype to generate bindings for mbedtls_mpi_exp_mod_soft()
#if defined(MBEDTLS_MPI_EXP_MOD_ALT_FALLBACK)
int mbedtls_mpi_exp_mod_soft(
    mbedtls_mpi *X, 
    const mbedtls_mpi *A,
    const mbedtls_mpi *E, 
    const mbedtls_mpi *N,
    mbedtls_mpi *prec_RR
);
#endif
