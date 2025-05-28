#include <openssl/evp.h>

#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/sm2.h>

#include "internal.h"

#if !defined(OPENSSL_NO_SM2)
const EVP_PKEY_ASN1_METHOD sm2_asn1_meth = {
    EVP_PKEY_SM2,
    // 1.2.156.10197.1.301
    {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x01, 0x01},
    9,
    &sm2_pkey_meth,
    #if 0

    sm2_pub_decode,
    sm2_pub_encode,
    sm2_pub_cmp,

    sm2_priv_decode,
    sm2_priv_encode,

    /*set_priv_raw=*/sm2_set_priv_raw,
    /*set_pub_raw=*/sm2_set_pub_raw,
    /*get_priv_raw=*/sm2_get_priv_raw,
    /*get_pub_raw=*/sm2_get_pub_raw,
    sm2_set1_tls_encodedpoint,
    sm2_get1_tls_encodedpoint,

    sm2_opaque,

    int_sm2_size,
    sm2_bits,

    ec_missing_parameters,
    ec_copy_parameters,
    ec_cmp_parameters,

    int_sm2_free,
#endif
};
#endif
