#ifndef OPENSSL_HEADER_CRYPTO_FIPSMODULE_SM4_INTERNAL_H
#define OPENSSL_HEADER_CRYPTO_FIPSMODULE_SM4_INTERNAL_H

#include <stdlib.h>
#include <openssl/sm4.h>

#include "../bcm_interface.h"
#include "../../internal.h"

using sm4_block128_f = void (*)(const uint8_t in[16], uint8_t out[16],
                                         const SM4_KEY *key);

using sm4_cbc128_f = void (*)(const uint8_t *in, uint8_t *out, size_t len,
                         const SM4_KEY *key, uint8_t ivec[16], int enc);

// ctr128_f is the type of a function that performs CTR-mode encryption.
using sm4_ctr128_f = void(*)(const uint8_t *in, uint8_t *out, size_t blocks,
                         const SM4_KEY *key, const uint8_t ivec[16]);

// CRYPTO_cbc128_encrypt encrypts |len| bytes from |in| to |out| using the
// given IV and block cipher in CBC mode. The input need not be a multiple of
// 128 bits long, but the output will round up to the nearest 128 bit multiple,
// zero padding the input if needed. The IV will be updated on return.
void CRYPTO_cbc128_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                           const SM4_KEY *key, uint8_t ivec[16],
                           sm4_block128_f block);

// CRYPTO_cbc128_decrypt decrypts |len| bytes from |in| to |out| using the
// given IV and block cipher in CBC mode. If |len| is not a multiple of 128
// bits then only that many bytes will be written, but a multiple of 128 bits
// is always read from |in|. The IV will be updated on return.
void CRYPTO_cbc128_decrypt(const uint8_t *in, uint8_t *out, size_t len,
                           const SM4_KEY *key, uint8_t ivec[16],
                           sm4_block128_f block);

void CRYPTO_ctr128_encrypt_ctr32(const uint8_t *in, uint8_t *out, size_t len,
                                 const SM4_KEY *key, uint8_t ivec[16],
                                 uint8_t ecount_buf[16], unsigned int *num,
                                 sm4_ctr128_f func);

#endif // OPENSSL_HEADER_CRYPTO_FIPSMODULE_AES_INTERNAL_H