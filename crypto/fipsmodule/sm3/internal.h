#ifndef OPENSSL_HEADER_SM3_INTERNAL_H
#define OPENSSL_HEADER_SM3_INTERNAL_H

#include <openssl/base.h>

#include "../../internal.h"

#if defined(__cplusplus)
extern "C" {
#endif

#if !defined(OPENSSL_NO_ASM) && defined(OPENSSL_AARCH64)

#define SM3_ASM_HW
OPENSSL_INLINE int sm3_hw_capable(void) {
  return CRYPTO_is_ARMv8_SM3_capable();
}

#endif

#if defined(SM3_ASM_HW)
void sm3_block_data_order_hw(uint32_t state[8], const uint8_t *data,
                             size_t num);
#endif

void sm3_block_data_order_soft(uint32_t state[8], const uint8_t *data,
                               size_t num);

#if defined(__cplusplus)
}
#endif

#endif  //