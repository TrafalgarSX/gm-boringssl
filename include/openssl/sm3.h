/*
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* This header can move into provider when legacy support is removed */
#ifndef OPENSSL_SM3_H
# define OPENSSL_SM3_H
# pragma once

#include <openssl/base.h>

# ifndef OPENSSL_NO_SM3
#  include <stddef.h>
#  ifdef  __cplusplus
extern "C" {
#  endif // __cplusplus

#  define SM3_DIGEST_LENGTH 32
#  define SM3_CBLOCK      64

struct sm3state_st {
   uint32_t h[8];
   uint32_t Nl, Nh;
   uint8_t data[SM3_CBLOCK];
   unsigned int num, md_len;
};

OPENSSL_EXPORT int SM3_Init(SM3_CTX *c);

OPENSSL_EXPORT int SM3_Update(SM3_CTX *c, const void *data, size_t len);

OPENSSL_EXPORT int SM3_Final(uint8_t md[SM3_DIGEST_LENGTH], SM3_CTX *c);

OPENSSL_EXPORT uint8_t *SM3(const uint8_t *data, size_t len, uint8_t out[SM3_DIGEST_LENGTH]);

OPENSSL_EXPORT void SM3_Transform(SM3_CTX *c, const uint8_t *data);

#  ifdef  __cplusplus
}
#  endif  //  __cplusplus
# endif // OPENSSL_NO_SM3

#endif /* OPENSSL_SM3_H */
