/*
 * Copyright 2006-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/asn1t.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/ecdsa.h>
#include <openssl/obj.h>
#include <openssl/sm2.h>
#include <openssl/sm2err.h>

#include "internal.h"
// #include "internal/sm2.h"
// #include "internal/sm2err.h"

/* EC pkey context structure */

typedef struct {
    /* message digest */
    const EVP_MD *md;
    /* Key and paramgen group */
    EC_GROUP *gen_group;
} SM2_PKEY_CTX;

static int pkey_sm2_init(EVP_PKEY_CTX *ctx)
{
    SM2_PKEY_CTX *dctx;

    if ((dctx = OPENSSL_zalloc(sizeof(*dctx))) == NULL) {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    ctx->data = dctx;
    return 1;
}

static void pkey_sm2_cleanup(EVP_PKEY_CTX *ctx)
{
    SM2_PKEY_CTX *dctx = ctx->data;

    if (dctx != NULL) {
        EC_GROUP_free(dctx->gen_group);
        OPENSSL_free(dctx);
        ctx->data = NULL;
    }
}

static int pkey_sm2_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    SM2_PKEY_CTX *dctx, *sctx;

    if (!pkey_sm2_init(dst))
        return 0;
    sctx = src->data;
    dctx = dst->data;
    if (sctx->gen_group != NULL) {
        dctx->gen_group = EC_GROUP_dup(sctx->gen_group);
        if (dctx->gen_group == NULL) {
            pkey_sm2_cleanup(dst);
            return 0;
        }
    }
    dctx->md = sctx->md;

    return 1;
}

static int pkey_sm2_sign(EVP_PKEY_CTX *ctx, uint8_t *sig, size_t *siglen,
                         const uint8_t *tbs, size_t tbslen)
{
    int ret;
    unsigned int sltmp;
    EC_KEY *ec = ctx->pkey->pkey;
    const int sig_sz = ECDSA_size(ec);

    if (sig_sz <= 0) {
        return 0;
    }

    if (sig == NULL) {
        *siglen = (size_t)sig_sz;
        return 1;
    }

    if (*siglen < (size_t)sig_sz) {
        OPENSSL_PUT_ERROR(SM2, SM2_R_BUFFER_TOO_SMALL);
        return 0;
    }

    ret = ossl_sm2_internal_sign(tbs, tbslen, sig, &sltmp, ec);

    if (ret <= 0)
        return ret;
    *siglen = (size_t)sltmp;
    return 1;
}

static int pkey_sm2_verify(EVP_PKEY_CTX *ctx,
                           const uint8_t *sig, size_t siglen,
                           const uint8_t *tbs, size_t tbslen)
{
    EC_KEY *ec = ctx->pkey->pkey;

    return ossl_sm2_internal_verify(tbs, tbslen, sig, siglen, ec);
}

static int pkey_sm2_encrypt(EVP_PKEY_CTX *ctx,
                            uint8_t *out, size_t *outlen,
                            const uint8_t *in, size_t inlen)
{
    EC_KEY *ec = ctx->pkey->pkey;
    SM2_PKEY_CTX *dctx = ctx->data;
    const EVP_MD *md = (dctx->md == NULL) ? EVP_sm3() : dctx->md;

    if (out == NULL) {
        if (!ossl_sm2_ciphertext_size(ec, md, inlen, outlen))
            return -1;
        else
            return 1;
    }

    return ossl_sm2_encrypt(ec, md, in, inlen, out, outlen);
}

static int pkey_sm2_decrypt(EVP_PKEY_CTX *ctx,
                            uint8_t *out, size_t *outlen,
                            const uint8_t *in, size_t inlen)
{
    EC_KEY *ec = ctx->pkey->pkey;
    SM2_PKEY_CTX *dctx = ctx->data;
    const EVP_MD *md = (dctx->md == NULL) ? EVP_sm3() : dctx->md;

    if (out == NULL) {
        if (!ossl_sm2_ciphertext_size(ec, md, inlen, outlen))
            return -1;
        else
            return 1;
    }

    return ossl_sm2_decrypt(ec, md, in, inlen, out, outlen);
}

static int pkey_sm2_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    SM2_PKEY_CTX *dctx = ctx->data;
    EC_GROUP *group;

    switch (type) {
    case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
        group = EC_GROUP_new_by_curve_name(p1);
        if (group == NULL) {
            OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_CURVE);
            return 0;
        }
        EC_GROUP_free(dctx->gen_group);
        dctx->gen_group = group;
        return 1;
#if 0 // TODO
    case EVP_PKEY_CTRL_EC_PARAM_ENC:
        if (dctx->gen_group == NULL) {
            OPENSSL_PUT_ERROR(SM2, SM2_R_NO_PARAMETERS_SET);
            return 0;
        }
        EC_GROUP_set_asn1_flag(dctx->gen_group, p1);
        return 1;
#endif
    case EVP_PKEY_CTRL_MD:
        dctx->md = p2;
        return 1;

    case EVP_PKEY_CTRL_GET_MD:
        *(const EVP_MD **)p2 = dctx->md;
        return 1;

    default:
        return -2;

    }
}

static int pkey_ec_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {
  SM2_PKEY_CTX *dctx = ctx->data;
  const EC_GROUP *group = dctx->gen_group;
  if (group == NULL) {
    if (ctx->pkey == NULL) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_NO_PARAMETERS_SET);
      return 0;
    }
    group = EC_KEY_get0_group(ctx->pkey->pkey);
  }
  EC_KEY *ec = EC_KEY_new();
  if (ec == NULL ||
      !EC_KEY_set_group(ec, group) ||
      !EC_KEY_generate_key(ec)) {
    EC_KEY_free(ec);
    return 0;
  }
  EVP_PKEY_assign_SM2_KEY(pkey, ec);
  return 1;
}

static int pkey_ec_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {
  SM2_PKEY_CTX *dctx = ctx->data;
  if (dctx->gen_group == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_NO_PARAMETERS_SET);
    return 0;
  }
  EC_KEY *ec = EC_KEY_new();
  if (ec == NULL ||
      !EC_KEY_set_group(ec, dctx->gen_group)) {
    EC_KEY_free(ec);
    return 0;
  }
  EVP_PKEY_assign_SM2_KEY(pkey, ec);
  return 1;
}

const EVP_PKEY_METHOD sm2_pkey_meth = {
    EVP_PKEY_SM2,
    pkey_sm2_init,
    pkey_sm2_copy,
    pkey_sm2_cleanup,
    pkey_ec_keygen, // keygen not supported
    pkey_sm2_sign,
    NULL, // sign_message not supported
    pkey_sm2_verify,
    NULL, // verify_message not supported
    NULL, // verify_recover not supported
    pkey_sm2_encrypt,
    pkey_sm2_decrypt,
    NULL, // derive not supported
    pkey_ec_paramgen, // paramgen not supported
    pkey_sm2_ctrl,
};

int EVP_PKEY_CTX_set_sm2_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid) {
  return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM2, EVP_PKEY_OP_TYPE_GEN,
                           EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, nid, NULL);
}

