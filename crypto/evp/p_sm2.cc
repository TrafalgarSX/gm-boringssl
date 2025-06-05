/*
 * Copyright 2006-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/asn1t.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/sm2.h>
#include <openssl/sm2err.h>
#include <string.h>


#include "internal.h"
// #include "internal/sm2.h"
// #include "internal/sm2err.h"

/* EC pkey context structure */

typedef struct {
  /* message digest */
  const EVP_MD *md;
  /* Key and paramgen group */
  const EC_GROUP *gen_group;
  /* Distinguishing Identifier, ISO/IEC 15946-3 */
  uint8_t *id;
  size_t id_len;
  /* id_set indicates if the 'id' field is set (1) or not (0) */
  int id_set;
} SM2_PKEY_CTX;

static int pkey_sm2_init(EVP_PKEY_CTX *ctx) {
  SM2_PKEY_CTX *dctx =
      reinterpret_cast<SM2_PKEY_CTX *>(OPENSSL_zalloc(sizeof(SM2_PKEY_CTX)));
  if (!dctx) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  ctx->data = dctx;
  return 1;
}

static void pkey_sm2_cleanup(EVP_PKEY_CTX *ctx) {
  SM2_PKEY_CTX *dctx = reinterpret_cast<SM2_PKEY_CTX *>(ctx->data);
  if (!dctx) {
    return;
  }
  OPENSSL_free(dctx->id);
  OPENSSL_free(dctx);
  ctx->data = NULL;
}

static int pkey_sm2_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src) {
  if (!pkey_sm2_init(dst)) {
    return 0;
  }

  SM2_PKEY_CTX *dctx = reinterpret_cast<SM2_PKEY_CTX *>(dst->data);
  const SM2_PKEY_CTX *sctx = reinterpret_cast<SM2_PKEY_CTX *>(src->data);

  if (sctx->id != NULL) {
    dctx->id = reinterpret_cast<uint8_t*>(OPENSSL_malloc(sctx->id_len));
    if (dctx->id == NULL) {
      OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
      pkey_sm2_cleanup(dst);
      return 0;
    }
    memcpy(dctx->id, sctx->id, sctx->id_len);
  }
  dctx->id_len = sctx->id_len;
  dctx->id_set = sctx->id_set;

  dctx->md = sctx->md;
  dctx->gen_group = sctx->gen_group;

  return 1;
}

static int pkey_sm2_sign(EVP_PKEY_CTX *ctx, uint8_t *sig, size_t *siglen,
                         const uint8_t *tbs, size_t tbslen) {
  const EC_KEY *ec = reinterpret_cast<EC_KEY *>(ctx->pkey->pkey);

  if (!sig) {
    *siglen = ECDSA_size(ec);
    return 1;
  }else if (*siglen < ECDSA_size(ec)) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_BUFFER_TOO_SMALL);
    return 0;
  }

  unsigned int sltmp;
  if(!ossl_sm2_internal_sign(tbs, tbslen, sig, &sltmp, ec)) {
    return 0;
  }

  *siglen = (size_t)sltmp;
  return 1;
}

static int pkey_sm2_verify(EVP_PKEY_CTX *ctx, const uint8_t *sig, size_t siglen,
                           const uint8_t *tbs, size_t tbslen) {
  const EC_KEY *ec_key = reinterpret_cast<EC_KEY *>(ctx->pkey->pkey);

  return ossl_sm2_internal_verify(tbs, tbslen, sig, siglen, ec_key);
}

static int pkey_sm2_encrypt(EVP_PKEY_CTX *ctx, uint8_t *out, size_t *outlen,
                            const uint8_t *in, size_t inlen) {
  const EC_KEY *ec_key = reinterpret_cast<EC_KEY *>(ctx->pkey->pkey);
  SM2_PKEY_CTX *dctx = reinterpret_cast<SM2_PKEY_CTX *>(ctx->data);
  const EVP_MD *md = (dctx->md == NULL) ? EVP_sm3() : dctx->md;

  if (!out) {
    if (!ossl_sm2_ciphertext_size(ec_key, md, inlen, outlen)) {
      return -1;
    } else {
      return 1;
    }
  }

  return ossl_sm2_encrypt(ec_key, md, in, inlen, out, outlen);
}

static int pkey_sm2_decrypt(EVP_PKEY_CTX *ctx, uint8_t *out, size_t *outlen,
                            const uint8_t *in, size_t inlen) {
  const EC_KEY *ec_key = reinterpret_cast<EC_KEY *>(ctx->pkey->pkey);
  SM2_PKEY_CTX *dctx = reinterpret_cast<SM2_PKEY_CTX *>(ctx->data);
  const EVP_MD *md = (dctx->md == NULL) ? EVP_sm3() : dctx->md;

  if (!out) {
    if (!ossl_sm2_ciphertext_size(ec_key, md, inlen, outlen)) {
      return -1;
    } else {
      return 1;
    }
  }

  return ossl_sm2_decrypt(ec_key, md, in, inlen, out, outlen);
}

static int pkey_sm2_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
  SM2_PKEY_CTX *dctx = reinterpret_cast<SM2_PKEY_CTX *>(ctx->data);

  EC_GROUP *group;

  switch (type) {
    case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
      group = EC_GROUP_new_by_curve_name(p1);
      if (group == NULL) {
        OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_CURVE);
        return 0;
      }
      dctx->gen_group = group;
      return 1;
    case EVP_PKEY_CTRL_MD: {
      const EVP_MD *md = reinterpret_cast<const EVP_MD *>(p2);
      int md_type = EVP_MD_type(md);
      if (md_type != NID_sm3 && md_type != NID_sha256) {
        OPENSSL_PUT_ERROR(EVP, EVP_R_INVALID_DIGEST_TYPE);
        return 0;
      }
      dctx->md = md;
      return 1;
    }

    case EVP_PKEY_CTRL_GET_MD:
      *(const EVP_MD **)p2 = dctx->md;
      return 1;
    case EVP_PKEY_CTRL_SET1_ID: {
      uint8_t *tmp_id;
      if (p1 > 0) {
        tmp_id = reinterpret_cast<uint8_t *>(OPENSSL_malloc((size_t)p1));
        if (tmp_id == NULL) {
          OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
          return 0;
        }
        memcpy(tmp_id, p2, p1);
        OPENSSL_free(dctx->id);
        dctx->id = tmp_id;
      } else {
        /* set null-ID */
        OPENSSL_free(dctx->id);
        dctx->id = NULL;
      }
      dctx->id_len = (size_t)p1;
      dctx->id_set = 1;
      return 1;
    }
    case EVP_PKEY_CTRL_GET1_ID:
      memcpy(p2, dctx->id, dctx->id_len);
      return 1;
    case EVP_PKEY_CTRL_GET1_ID_LEN:
      *(size_t *)p2 = dctx->id_len;
      return 1;

    default:
      return -2;
  }
}

static int pkey_ec_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {
  SM2_PKEY_CTX *dctx = reinterpret_cast<SM2_PKEY_CTX *>(ctx->data);
  const EC_GROUP *group = dctx->gen_group;
  if (!group) {
    if (ctx->pkey == NULL) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_NO_PARAMETERS_SET);
      return 0;
    }
    group = EC_KEY_get0_group(reinterpret_cast<EC_KEY *>(ctx->pkey->pkey));
  }
  EC_KEY *ec = EC_KEY_new();
  if (ec == NULL || !EC_KEY_set_group(ec, group) || !EC_KEY_generate_key(ec)) {
    EC_KEY_free(ec);
    return 0;
  }
  EVP_PKEY_assign_SM2_KEY(pkey, ec);
  return 1;
}

static int pkey_ec_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {
  SM2_PKEY_CTX *dctx = reinterpret_cast<SM2_PKEY_CTX *>(ctx->data);
  if (dctx->gen_group == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_NO_PARAMETERS_SET);
    return 0;
  }
  EC_KEY *ec = EC_KEY_new();
  if (ec == NULL || !EC_KEY_set_group(ec, dctx->gen_group)) {
    EC_KEY_free(ec);
    return 0;
  }
  EVP_PKEY_assign_SM2_KEY(pkey, ec);
  return 1;
}

static int pkey_sm2_digest_custom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {
  uint8_t z[EVP_MAX_MD_SIZE];
  SM2_PKEY_CTX *smctx = reinterpret_cast<SM2_PKEY_CTX *>(ctx->data);
  EC_KEY *ec = reinterpret_cast<EC_KEY *>(ctx->pkey->pkey);
  const EVP_MD *md = EVP_MD_CTX_md(mctx);
  int mdlen = EVP_MD_size(md);

  if (!smctx->id_set) {
    /*
     * An ID value must be set. The specifications are not clear whether a
     * NULL is allowed. We only allow it if set explicitly for maximum
     * flexibility.
     */
    OPENSSL_PUT_ERROR(EVP, SM2_R_ID_NOT_SET);
    return 0;
  }

  if (mdlen < 0) {
    OPENSSL_PUT_ERROR(EVP, SM2_R_INVALID_DIGEST);
    return 0;
  }

  /* get hashed prefix 'z' of tbs message */
  if (!ossl_sm2_compute_z_digest(z, md, smctx->id, smctx->id_len, ec)) {
    return 0;
  }

  return EVP_DigestUpdate(mctx, z, (size_t)mdlen);
}

const EVP_PKEY_METHOD sm2_pkey_meth = {
    EVP_PKEY_SM2,
    pkey_sm2_init,
    pkey_sm2_copy,
    pkey_sm2_cleanup,
    pkey_ec_keygen,  // keygen not supported
    pkey_sm2_sign,
    NULL,  // sign_message not supported
    pkey_sm2_verify,
    NULL,  // verify_message not supported
    NULL,  // verify_recover not supported
    pkey_sm2_encrypt,
    pkey_sm2_decrypt,
    NULL,              // derive not supported
    pkey_ec_paramgen,  // paramgen not supported
    pkey_sm2_ctrl,
    pkey_sm2_digest_custom,
};

int EVP_PKEY_CTX_set_sm2_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid) {
  return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM2, EVP_PKEY_OP_TYPE_GEN,
                           EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, nid, NULL);
}
