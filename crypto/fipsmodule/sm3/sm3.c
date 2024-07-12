/*
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <openssl/sm3.h>

#include <openssl/mem.h>

#include "../../internal.h"
#include "../digest/md32_common.h"
#include "../service_indicator/internal.h"
#include "internal.h"

int SM3_Init(SM3_CTX *c) {
  OPENSSL_memset(c, 0, sizeof(*c));
  c->A[0] = 0x7380166fUL;
  c->A[1] = 0x4914b2b9UL;
  c->A[2] = 0x172442d7UL;
  c->A[3] = 0xda8a0600UL;
  c->A[4] = 0xa96f30bcUL;
  c->A[5] = 0x163138aaUL;
  c->A[6] = 0xe38dee4dUL;
  c->A[7] = 0xb0fb0e4eUL;
  return 1;
}

uint8_t *SM3(const uint8_t *data, size_t len, uint8_t out[SM3_DIGEST_LENGTH]) {
  SM3_CTX ctx;
  SM3_Init(&ctx);
  SM3_Update(&ctx, data, len);
  SM3_Final(out, &ctx);
  OPENSSL_cleanse(&ctx, sizeof(ctx));
  return out;
}

#define P0(X) (X ^ CRYPTO_rotl_u32(X, 9) ^ CRYPTO_rotl_u32(X, 17))
#define P1(X) (X ^ CRYPTO_rotl_u32(X, 15) ^ CRYPTO_rotl_u32(X, 23))

#define FF0(X, Y, Z) (X ^ Y ^ Z)
#define GG0(X, Y, Z) (X ^ Y ^ Z)

#define FF1(X, Y, Z) ((X & Y) | ((X | Y) & Z))
#define GG1(X, Y, Z) ((Z ^ (X & (Y ^ Z))))

#define EXPAND(W0, W7, W13, W3, W10) \
  (P1(W0 ^ W7 ^ CRYPTO_rotl_u32(W13, 15)) ^ CRYPTO_rotl_u32(W3, 7) ^ W10)

#define RND(A, B, C, D, E, F, G, H, TJ, Wi, Wj, FF, GG)        \
  do {                                                         \
    const uint32_t A12 = CRYPTO_rotl_u32(A, 12);               \
    const uint32_t A12_SM = A12 + E + TJ;                      \
    const uint32_t SS1 = CRYPTO_rotl_u32(A12_SM, 7);           \
    const uint32_t TT1 = FF(A, B, C) + D + (SS1 ^ A12) + (Wj); \
    const uint32_t TT2 = GG(E, F, G) + H + SS1 + Wi;           \
    B = CRYPTO_rotl_u32(B, 9);                                 \
    D = TT1;                                                   \
    F = CRYPTO_rotl_u32(F, 19);                                \
    H = P0(TT2);                                               \
  } while (0)

#define R1(A, B, C, D, E, F, G, H, TJ, Wi, Wj) \
  RND(A, B, C, D, E, F, G, H, TJ, Wi, Wj, FF0, GG0)

#define R2(A, B, C, D, E, F, G, H, TJ, Wi, Wj) \
  RND(A, B, C, D, E, F, G, H, TJ, Wi, Wj, FF1, GG1)

#if !defined(SM3_ASM)
static void sm3_block_data_order(uint32_t state[8], const uint8_t *p,
                                 size_t num);
#endif

void SM3_Transform(SM3_CTX *c, const uint8_t *data) {
  sm3_block_data_order(c->A, data, 1);
}

int SM3_Update(SM3_CTX *c, const void *data, size_t len) {
  crypto_md32_update(sm3_block_data_order, c->A, c->data, SM3_CBLOCK, &c->num,
                     &c->Nh, &c->Nl, data, len);
  return 1;
}

static void sm3_output_state(uint8_t out[SM3_DIGEST_LENGTH],
                             const SM3_CTX *ctx) {
  for (size_t i = 0; i < 8; i++) {
    CRYPTO_store_u32_be(out + i * 4, ctx->A[i]);
  }
}

int SM3_Final(uint8_t *out, SM3_CTX *c) {
  crypto_md32_final(&sm3_block_data_order, c->A, c->data, SM3_DIGEST_LENGTH,
                    &c->num, c->Nh, c->Nl, 1);
  sm3_output_state(out, c);
  FIPS_service_indicator_update_state();
  return 1;
}

// wired marco 
#if !defined(SM3_ASM)

void sm3_block_data_order_soft(uint32_t state[8], const uint8_t *p,
                               size_t num) {
  const uint8_t *data = p;
  register uint32_t A, B, C, D, E, F, G, H;

  uint32_t W00, W01, W02, W03, W04, W05, W06, W07, W08, W09, W10, W11, W12, W13,
      W14, W15;

  for (; num--;) {
    A = state[0];
    B = state[1];
    C = state[2];
    D = state[3];
    E = state[4];
    F = state[5];
    G = state[6];
    H = state[7];

    /*
     * We have to load all message bytes immediately since SM3 reads
     * them slightly out of order.
     */
    W00 = CRYPTO_load_u32_be(data);
    data += 4;
    W01 = CRYPTO_load_u32_be(data);
    data += 4;
    W02 = CRYPTO_load_u32_be(data);
    data += 4;
    W03 = CRYPTO_load_u32_be(data);
    data += 4;
    W04 = CRYPTO_load_u32_be(data);
    data += 4;
    W05 = CRYPTO_load_u32_be(data);
    data += 4;
    W06 = CRYPTO_load_u32_be(data);
    data += 4;
    W07 = CRYPTO_load_u32_be(data);
    data += 4;
    W08 = CRYPTO_load_u32_be(data);
    data += 4;
    W09 = CRYPTO_load_u32_be(data);
    data += 4;
    W10 = CRYPTO_load_u32_be(data);
    data += 4;
    W11 = CRYPTO_load_u32_be(data);
    data += 4;
    W12 = CRYPTO_load_u32_be(data);
    data += 4;
    W13 = CRYPTO_load_u32_be(data);
    data += 4;
    W14 = CRYPTO_load_u32_be(data);
    data += 4;
    W15 = CRYPTO_load_u32_be(data);
    data += 4;

    R1(A, B, C, D, E, F, G, H, 0x79CC4519, W00, W00 ^ W04);
    W00 = EXPAND(W00, W07, W13, W03, W10);
    R1(D, A, B, C, H, E, F, G, 0xF3988A32, W01, W01 ^ W05);
    W01 = EXPAND(W01, W08, W14, W04, W11);
    R1(C, D, A, B, G, H, E, F, 0xE7311465, W02, W02 ^ W06);
    W02 = EXPAND(W02, W09, W15, W05, W12);
    R1(B, C, D, A, F, G, H, E, 0xCE6228CB, W03, W03 ^ W07);
    W03 = EXPAND(W03, W10, W00, W06, W13);
    R1(A, B, C, D, E, F, G, H, 0x9CC45197, W04, W04 ^ W08);
    W04 = EXPAND(W04, W11, W01, W07, W14);
    R1(D, A, B, C, H, E, F, G, 0x3988A32F, W05, W05 ^ W09);
    W05 = EXPAND(W05, W12, W02, W08, W15);
    R1(C, D, A, B, G, H, E, F, 0x7311465E, W06, W06 ^ W10);
    W06 = EXPAND(W06, W13, W03, W09, W00);
    R1(B, C, D, A, F, G, H, E, 0xE6228CBC, W07, W07 ^ W11);
    W07 = EXPAND(W07, W14, W04, W10, W01);
    R1(A, B, C, D, E, F, G, H, 0xCC451979, W08, W08 ^ W12);
    W08 = EXPAND(W08, W15, W05, W11, W02);
    R1(D, A, B, C, H, E, F, G, 0x988A32F3, W09, W09 ^ W13);
    W09 = EXPAND(W09, W00, W06, W12, W03);
    R1(C, D, A, B, G, H, E, F, 0x311465E7, W10, W10 ^ W14);
    W10 = EXPAND(W10, W01, W07, W13, W04);
    R1(B, C, D, A, F, G, H, E, 0x6228CBCE, W11, W11 ^ W15);
    W11 = EXPAND(W11, W02, W08, W14, W05);
    R1(A, B, C, D, E, F, G, H, 0xC451979C, W12, W12 ^ W00);
    W12 = EXPAND(W12, W03, W09, W15, W06);
    R1(D, A, B, C, H, E, F, G, 0x88A32F39, W13, W13 ^ W01);
    W13 = EXPAND(W13, W04, W10, W00, W07);
    R1(C, D, A, B, G, H, E, F, 0x11465E73, W14, W14 ^ W02);
    W14 = EXPAND(W14, W05, W11, W01, W08);
    R1(B, C, D, A, F, G, H, E, 0x228CBCE6, W15, W15 ^ W03);
    W15 = EXPAND(W15, W06, W12, W02, W09);
    R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W00, W00 ^ W04);
    W00 = EXPAND(W00, W07, W13, W03, W10);
    R2(D, A, B, C, H, E, F, G, 0x3B14F50F, W01, W01 ^ W05);
    W01 = EXPAND(W01, W08, W14, W04, W11);
    R2(C, D, A, B, G, H, E, F, 0x7629EA1E, W02, W02 ^ W06);
    W02 = EXPAND(W02, W09, W15, W05, W12);
    R2(B, C, D, A, F, G, H, E, 0xEC53D43C, W03, W03 ^ W07);
    W03 = EXPAND(W03, W10, W00, W06, W13);
    R2(A, B, C, D, E, F, G, H, 0xD8A7A879, W04, W04 ^ W08);
    W04 = EXPAND(W04, W11, W01, W07, W14);
    R2(D, A, B, C, H, E, F, G, 0xB14F50F3, W05, W05 ^ W09);
    W05 = EXPAND(W05, W12, W02, W08, W15);
    R2(C, D, A, B, G, H, E, F, 0x629EA1E7, W06, W06 ^ W10);
    W06 = EXPAND(W06, W13, W03, W09, W00);
    R2(B, C, D, A, F, G, H, E, 0xC53D43CE, W07, W07 ^ W11);
    W07 = EXPAND(W07, W14, W04, W10, W01);
    R2(A, B, C, D, E, F, G, H, 0x8A7A879D, W08, W08 ^ W12);
    W08 = EXPAND(W08, W15, W05, W11, W02);
    R2(D, A, B, C, H, E, F, G, 0x14F50F3B, W09, W09 ^ W13);
    W09 = EXPAND(W09, W00, W06, W12, W03);
    R2(C, D, A, B, G, H, E, F, 0x29EA1E76, W10, W10 ^ W14);
    W10 = EXPAND(W10, W01, W07, W13, W04);
    R2(B, C, D, A, F, G, H, E, 0x53D43CEC, W11, W11 ^ W15);
    W11 = EXPAND(W11, W02, W08, W14, W05);
    R2(A, B, C, D, E, F, G, H, 0xA7A879D8, W12, W12 ^ W00);
    W12 = EXPAND(W12, W03, W09, W15, W06);
    R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W13, W13 ^ W01);
    W13 = EXPAND(W13, W04, W10, W00, W07);
    R2(C, D, A, B, G, H, E, F, 0x9EA1E762, W14, W14 ^ W02);
    W14 = EXPAND(W14, W05, W11, W01, W08);
    R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W15, W15 ^ W03);
    W15 = EXPAND(W15, W06, W12, W02, W09);
    R2(A, B, C, D, E, F, G, H, 0x7A879D8A, W00, W00 ^ W04);
    W00 = EXPAND(W00, W07, W13, W03, W10);
    R2(D, A, B, C, H, E, F, G, 0xF50F3B14, W01, W01 ^ W05);
    W01 = EXPAND(W01, W08, W14, W04, W11);
    R2(C, D, A, B, G, H, E, F, 0xEA1E7629, W02, W02 ^ W06);
    W02 = EXPAND(W02, W09, W15, W05, W12);
    R2(B, C, D, A, F, G, H, E, 0xD43CEC53, W03, W03 ^ W07);
    W03 = EXPAND(W03, W10, W00, W06, W13);
    R2(A, B, C, D, E, F, G, H, 0xA879D8A7, W04, W04 ^ W08);
    W04 = EXPAND(W04, W11, W01, W07, W14);
    R2(D, A, B, C, H, E, F, G, 0x50F3B14F, W05, W05 ^ W09);
    W05 = EXPAND(W05, W12, W02, W08, W15);
    R2(C, D, A, B, G, H, E, F, 0xA1E7629E, W06, W06 ^ W10);
    W06 = EXPAND(W06, W13, W03, W09, W00);
    R2(B, C, D, A, F, G, H, E, 0x43CEC53D, W07, W07 ^ W11);
    W07 = EXPAND(W07, W14, W04, W10, W01);
    R2(A, B, C, D, E, F, G, H, 0x879D8A7A, W08, W08 ^ W12);
    W08 = EXPAND(W08, W15, W05, W11, W02);
    R2(D, A, B, C, H, E, F, G, 0x0F3B14F5, W09, W09 ^ W13);
    W09 = EXPAND(W09, W00, W06, W12, W03);
    R2(C, D, A, B, G, H, E, F, 0x1E7629EA, W10, W10 ^ W14);
    W10 = EXPAND(W10, W01, W07, W13, W04);
    R2(B, C, D, A, F, G, H, E, 0x3CEC53D4, W11, W11 ^ W15);
    W11 = EXPAND(W11, W02, W08, W14, W05);
    R2(A, B, C, D, E, F, G, H, 0x79D8A7A8, W12, W12 ^ W00);
    W12 = EXPAND(W12, W03, W09, W15, W06);
    R2(D, A, B, C, H, E, F, G, 0xF3B14F50, W13, W13 ^ W01);
    W13 = EXPAND(W13, W04, W10, W00, W07);
    R2(C, D, A, B, G, H, E, F, 0xE7629EA1, W14, W14 ^ W02);
    W14 = EXPAND(W14, W05, W11, W01, W08);
    R2(B, C, D, A, F, G, H, E, 0xCEC53D43, W15, W15 ^ W03);
    W15 = EXPAND(W15, W06, W12, W02, W09);
    R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W00, W00 ^ W04);
    W00 = EXPAND(W00, W07, W13, W03, W10);
    R2(D, A, B, C, H, E, F, G, 0x3B14F50F, W01, W01 ^ W05);
    W01 = EXPAND(W01, W08, W14, W04, W11);
    R2(C, D, A, B, G, H, E, F, 0x7629EA1E, W02, W02 ^ W06);
    W02 = EXPAND(W02, W09, W15, W05, W12);
    R2(B, C, D, A, F, G, H, E, 0xEC53D43C, W03, W03 ^ W07);
    W03 = EXPAND(W03, W10, W00, W06, W13);
    R2(A, B, C, D, E, F, G, H, 0xD8A7A879, W04, W04 ^ W08);
    R2(D, A, B, C, H, E, F, G, 0xB14F50F3, W05, W05 ^ W09);
    R2(C, D, A, B, G, H, E, F, 0x629EA1E7, W06, W06 ^ W10);
    R2(B, C, D, A, F, G, H, E, 0xC53D43CE, W07, W07 ^ W11);
    R2(A, B, C, D, E, F, G, H, 0x8A7A879D, W08, W08 ^ W12);
    R2(D, A, B, C, H, E, F, G, 0x14F50F3B, W09, W09 ^ W13);
    R2(C, D, A, B, G, H, E, F, 0x29EA1E76, W10, W10 ^ W14);
    R2(B, C, D, A, F, G, H, E, 0x53D43CEC, W11, W11 ^ W15);
    R2(A, B, C, D, E, F, G, H, 0xA7A879D8, W12, W12 ^ W00);
    R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W13, W13 ^ W01);
    R2(C, D, A, B, G, H, E, F, 0x9EA1E762, W14, W14 ^ W02);
    R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W15, W15 ^ W03);

    state[0] ^= A;
    state[1] ^= B;
    state[2] ^= C;
    state[3] ^= D;
    state[4] ^= E;
    state[5] ^= F;
    state[6] ^= G;
    state[7] ^= H;
  }
}

static void sm3_block_data_order(uint32_t state[8], const uint8_t *p,
                                 size_t num) {
#if defined(SM3_ASM_HW)
  if (sm3_hw_capable()) {
    sm3_block_data_order_hw(state, data, num);
    return;
  }
#endif
  sm3_block_data_order_soft(state, p, num);
}

#endif  // !SM3_ASM

/**
为什么这段代码会出现在 #endif // !SHA1_ASM
的条件编译块中，这可能是因为整个代码块是在一个更大的条件编译逻辑中，其中
!SHA1_ASM
指的是当没有启用特定的汇编优化时的情况。
这样的设计允许代码在不同的编译配置下灵活地选择最合适的实现方式：
如果支持并启用了汇编优化，则使用汇编实现的版本；
如果不支持或未启用汇编优化，但硬件支持特定的加速指令集，那么使用对应的硬件加速版本；
如果两者都不可用，最后回退到纯软件实现。
*/

#undef P0
#undef P1
#undef FF0
#undef GG0
#undef FF1
#undef GG1
#undef EXPAND
#undef RND
#undef R1
#undef R2
