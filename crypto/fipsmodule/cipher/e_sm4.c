#include <assert.h>
#include <limits.h>
#include <string.h>

#include <openssl/aead.h>
#include <openssl/cipher.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/rand.h>
#include <openssl/sm4.h>


#include "../delocate.h"
#include "../modes/internal.h"
#include "internal.h"


typedef struct {
  union {
    double align;
    SM4_KEY ks;
  } ks;
  block128_f block;
  union {
    // ecb128_f ecb;
    cbc128_f cbc;
    ctr128_f ctr;
  } stream;
} EVP_SM4_KEY;

static int sm4_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                        const uint8_t *iv, int enc) {
  int ret = 1;
  EVP_SM4_KEY *dat = (EVP_SM4_KEY*)ctx->cipher_data;
  const int mode = ctx->cipher->flags & EVP_CIPH_MODE_MASK;

  if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE) && !enc) {
    SM4_set_key(key, &dat->ks.ks);
    dat->block = (block128_f)SM4_decrypt;
    dat->stream.cbc = NULL;
  } else {
    SM4_set_key(key, &dat->ks.ks);
    dat->block = (block128_f)SM4_encrypt;
    dat->stream.cbc = NULL;
  }
  return ret;
}

static int sm4_cbc_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                          const uint8_t *in, size_t len) {
  EVP_SM4_KEY *dat = (EVP_SM4_KEY *)ctx->cipher_data;

  if (dat->stream.cbc) {
    (*dat->stream.cbc)(in, out, len, &dat->ks.ks, ctx->iv, ctx->encrypt);
  } else if (ctx->encrypt) {
    CRYPTO_cbc128_encrypt(in, out, len, &dat->ks, ctx->iv, dat->block);
  } else {
    CRYPTO_cbc128_decrypt(in, out, len, &dat->ks, ctx->iv, dat->block);
  }
  return 1;
}

static int sm4_ecb_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in,
                          size_t len) {
  size_t bl = ctx->cipher->block_size;
  EVP_SM4_KEY *dat = (EVP_SM4_KEY *)ctx->cipher_data;

  if (len < bl) {
    return 1;
  }

  len -= bl;
  for (size_t i = 0; i <= len; i += bl) {
    (*dat->block)(in + i, out + i, &dat->ks.ks);
  }

  return 1;
}

static int sm4_ctr_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                          const uint8_t *in, size_t len)
{
    EVP_SM4_KEY *dat = (EVP_SM4_KEY *)ctx->cipher_data;

    if (dat->stream.ctr)
        CRYPTO_ctr128_encrypt_ctr32(in, out, len, &dat->ks,
                                    ctx->iv,
                                    ctx->buf,
                                    &ctx->num, dat->stream.ctr);
    else
        CRYPTO_ctr128_encrypt(in, out, len, &dat->ks,
                              ctx->iv,
                              ctx->buf, &ctx->num,
                              dat->block);
    return 1;
}

DEFINE_METHOD_FUNCTION(EVP_CIPHER, EVP_sm4_cbc) {
  memset(out, 0, sizeof(EVP_CIPHER));

  out->nid = NID_sm4_cbc;
  out->block_size = 16;
  out->key_len = 128/8;
  out->iv_len = 16;
  out->ctx_size = sizeof(EVP_SM4_KEY);
  out->flags = EVP_CIPH_CBC_MODE;
  out->init = sm4_init_key;
  out->cipher = sm4_cbc_cipher;
}

DEFINE_METHOD_FUNCTION(EVP_CIPHER, EVP_sm4_ecb) {
  memset(out, 0, sizeof(EVP_CIPHER));

  out->nid = NID_sm4_ecb;
  out->block_size = 16;
  out->key_len = 128/8;
  out->iv_len = 0;
  out->ctx_size = sizeof(EVP_SM4_KEY);
  out->flags = EVP_CIPH_ECB_MODE;
  out->init = sm4_init_key;
  out->cipher = sm4_ecb_cipher;
}

DEFINE_METHOD_FUNCTION(EVP_CIPHER, EVP_sm4_ctr) {
  memset(out, 0, sizeof(EVP_CIPHER));

  out->nid = NID_sm4_ctr;
  out->block_size = 1;
  out->key_len = 128/8;
  out->iv_len = 16;
  out->ctx_size = sizeof(EVP_SM4_KEY);
  out->flags = EVP_CIPH_CTR_MODE;
  out->init = sm4_init_key;
  out->cipher = sm4_ctr_cipher;
}

#if 0
typedef struct {
    SM4_KEY ks;                 /* SM4 key schedule to use */
    int key_set;                /* Set if key initialized */
    int iv_set;                 /* Set if an iv is set */
    GCM128_CONTEXT gcm;
    uint8_t *iv;          /* Temporary IV store */
    int ivlen;                  /* IV length */
    int taglen;
    int iv_gen;                 /* It is OK to generate IVs */
    int tls_aad_len;            /* TLS AAD length */
    ctr128_f ctr;
} EVP_SM4_GCM_CTX;

#if defined(OPENSSL_32_BIT)
#define EVP_SM4_GCM_CTX_PADDING (4+8)
#else
#define EVP_SM4_GCM_CTX_PADDING 8
#endif

static EVP_SM4_GCM_CTX *sm4_gcm_from_cipher_ctx(EVP_CIPHER_CTX *ctx) 
{
  static_assert(
      alignof(EVP_SM4_GCM_CTX) <= 16,
      "EVP_AES_GCM_CTX needs more alignment than this function provides");

  // |malloc| guarantees up to 4-byte alignment on 32-bit and 8-byte alignment
  // on 64-bit systems, so we need to adjust to reach 16-byte alignment.
  assert(ctx->cipher->ctx_size ==
         sizeof(EVP_SM4_GCM_CTX) + EVP_SM4_GCM_CTX_PADDING);

  char *ptr = ctx->cipher_data;
#if defined(OPENSSL_32_BIT)
  assert((uintptr_t)ptr % 4 == 0);
  ptr += (uintptr_t)ptr & 4;
#endif
  assert((uintptr_t)ptr % 8 == 0);
  ptr += (uintptr_t)ptr & 8;
  return (EVP_SM4_GCM_CTX *)ptr;
}

/* increment counter (64-bit int) by 1 */
static void ctr64_inc(uint8_t *counter)
{
    int n = 8;
    uint8_t c;

    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c)
            return;
    } while (n);
}

static int sm4_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
    EVP_SM4_GCM_CTX *gctx = sm4_gcm_from_cipher_ctx(c);

    switch (type) {
    case EVP_CTRL_INIT:
        gctx->key_set = 0;
        gctx->iv_set = 0;
        gctx->ivlen = EVP_CIPHER_iv_length(c->cipher);
        gctx->iv = c->iv;
        gctx->taglen = -1;
        gctx->iv_gen = 0;
        gctx->tls_aad_len = -1;
        return 1;

    case EVP_CTRL_GET_IVLEN:
        *(int *)ptr = gctx->ivlen;
        return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
        if (arg <= 0)
            return 0;
        /* Allocate memory for IV if needed */
        if ((arg > EVP_MAX_IV_LENGTH) && (arg > gctx->ivlen)) {
            if (gctx->iv != c->iv)
                OPENSSL_free(gctx->iv);
            if ((gctx->iv = OPENSSL_malloc(arg)) == NULL)
                return 0;
        }
        gctx->ivlen = arg;
        return 1;

    case EVP_CTRL_AEAD_SET_TAG:
        if (arg <= 0 || arg > 16 || c->encrypt)
            return 0;
        OPENSSL_memcpy(c->buf, ptr, arg);
        gctx->taglen = arg;
        return 1;

    case EVP_CTRL_AEAD_GET_TAG:
        if (arg <= 0 || arg > 16 || !c->encrypt || gctx->taglen < 0)
            return 0;
        OPENSSL_memcpy(ptr, c->buf, arg);
        return 1;

    case EVP_CTRL_GCM_SET_IV_FIXED:
        /* Special case: -1 length restores whole IV */
        if (arg == -1) {
            memcpy(gctx->iv, ptr, gctx->ivlen);
            gctx->iv_gen = 1;
            return 1;
        }
        /*
         * Fixed field must be at least 4 bytes and invocation field at least
         * 8.
         */
        if ((arg < 4) || (gctx->ivlen - arg) < 8)
            return 0;
        if (arg)
            memcpy(gctx->iv, ptr, arg);
        if (c->encrypt && RAND_bytes(gctx->iv + arg, gctx->ivlen - arg) <= 0)
            return 0;
        gctx->iv_gen = 1;
        return 1;

    case EVP_CTRL_GCM_IV_GEN:
        if (gctx->iv_gen == 0 || gctx->key_set == 0)
            return 0;
        CRYPTO_gcm128_setiv(&gctx->gcm, gctx->iv, gctx->ivlen);
        if (arg <= 0 || arg > gctx->ivlen)
            arg = gctx->ivlen;
        OPENSSL_memcpy(ptr, gctx->iv + gctx->ivlen - arg, arg);
        // Invocation field will be at least 8 bytes in size, so no need to check
        // wrap around or increment more than last 8 bytes.
        uint8_t *ctr = gctx->iv + gctx->ivlen - 8;
        CRYPTO_store_u64_be(ctr, CRYPTO_load_u64_be(ctr) + 1);
        gctx->iv_set = 1;
        return 1;

    case EVP_CTRL_GCM_SET_IV_INV:
        if (gctx->iv_gen == 0 || gctx->key_set == 0 || c->encrypt)
            return 0;
        memcpy(gctx->iv + gctx->ivlen - arg, ptr, arg);
        CRYPTO_gcm128_setiv(&gctx->gcm, gctx->iv, gctx->ivlen);
        gctx->iv_set = 1;
        return 1;
    case EVP_CTRL_COPY:
        {
            EVP_CIPHER_CTX *out = ptr;
            EVP_SM4_GCM_CTX *gctx_out = sm4_gcm_from_cipher_ctx(c);
            // |EVP_CIPHER_CTX_copy| copies this generically, but we must redo it in
            // case |out->cipher_data| and |in->cipher_data| are differently aligned.
            OPENSSL_memcpy(gctx_out, gctx, sizeof(EVP_SM4_GCM_CTX));
            if (gctx->iv == c->iv) {
                gctx_out->iv = out->iv;
            } else {
                gctx_out->iv = OPENSSL_memdup(gctx->iv, gctx->ivlen);
                if (!gctx_out->iv) {
                return 0;
                }
            }
            return 1;

        }
    case EVP_CTRL_AEAD_SET_MAC_KEY:
        /* no-op */
        return 1;
    default:
        return -1;
    }
    return 1;
}
static int sm4_gcm_init(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                        const uint8_t *iv, int enc)
{
    EVP_SM4_GCM_CTX *gctx = sm4_gcm_from_cipher_ctx(ctx);

    if (!iv && !key) {
        return 1;

    if (key) {
        OPENSSL_memset(&gctx->gcm, 0, sizeof(gctx->gcm));
        SM4_set_key(key, &gctx->ks);
        CRYPTO_gcm128_init(&gctx->gcm, &gctx->ks, (block128_f)SM4_encrypt);
        gctx->ctr = NULL;
        /*
         * If we have an iv can set it directly, otherwise use saved IV.
         */
        if (iv == NULL && gctx->iv_set)
            iv = gctx->iv;
        if (iv) {
            CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
            gctx->iv_set = 1;
        }
        gctx->key_set = 1;
    } else {
        /* If key set use IV, otherwise copy */
        if (gctx->key_set)
            CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
        else
            memcpy(gctx->iv, iv, gctx->ivlen);
        gctx->iv_set = 1;
        gctx->iv_gen = 0;
    }
    return 1;
}

/*
 * Handle TLS GCM packet format. This consists of the last portion of the IV
 * followed by the payload and finally the tag. On encrypt generate IV,
 * encrypt payload and write the tag. On verify retrieve IV, decrypt payload
 * and verify tag.
 */

static int sm4_gcm_tls_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                              const uint8_t *in, size_t len)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX,ctx);
    int rv = -1;
    /* Encrypt/decrypt must be performed in place */
    if (out != in
        || len < (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN))
        return -1;
    /*
     * Set IV from start of buffer or generate IV and write to start of
     * buffer.
     */
    if (EVP_CIPHER_CTX_ctrl(ctx, ctx->encrypt ? EVP_CTRL_GCM_IV_GEN
                                              : EVP_CTRL_GCM_SET_IV_INV,
                            EVP_GCM_TLS_EXPLICIT_IV_LEN, out) <= 0)
        goto err;
    /* Use saved AAD */
    if (CRYPTO_gcm128_aad(&gctx->gcm, ctx->buf, gctx->tls_aad_len))
        goto err;
    /* Fix buffer and length to point to payload */
    in += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    out += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    len -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    if (ctx->encrypt) {
        /* Encrypt payload */
        if (gctx->ctr) {
            size_t bulk = 0;
            if (CRYPTO_gcm128_encrypt_ctr32(&gctx->gcm,
                                            in + bulk,
                                            out + bulk,
                                            len - bulk, gctx->ctr))
                goto err;
        } else {
            size_t bulk = 0;
            if (CRYPTO_gcm128_encrypt(&gctx->gcm,
                                      in + bulk, out + bulk, len - bulk))
                goto err;
        }
        out += len;
        /* Finally write tag */
        CRYPTO_gcm128_tag(&gctx->gcm, out, EVP_GCM_TLS_TAG_LEN);
        rv = len + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    } else {
        /* Decrypt */
        if (gctx->ctr) {
            size_t bulk = 0;
            if (CRYPTO_gcm128_decrypt_ctr32(&gctx->gcm,
                                            in + bulk,
                                            out + bulk,
                                            len - bulk, gctx->ctr))
                goto err;
        } else {
            size_t bulk = 0;
            if (CRYPTO_gcm128_decrypt(&gctx->gcm,
                                      in + bulk, out + bulk, len - bulk))
                goto err;
        }
        /* Retrieve tag */
        CRYPTO_gcm128_tag(&gctx->gcm, ctx->buf, EVP_GCM_TLS_TAG_LEN);
        /* If tag mismatch wipe buffer */
        if (CRYPTO_memcmp(ctx->buf, in + len, EVP_GCM_TLS_TAG_LEN)) {
            OPENSSL_cleanse(out, len);
            goto err;
        }
        rv = len;
    }

 err:
    gctx->iv_set = 0;
    gctx->tls_aad_len = -1;
    return rv;
}

static int sm4_gcm_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                          const uint8_t *in, size_t len)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX,ctx);

    /* If not set up, return error */
    if (!gctx->key_set)
        return -1;

    if (gctx->tls_aad_len >= 0)
        return sm4_gcm_tls_cipher(ctx, out, in, len);

    if (!gctx->iv_set)
        return -1;

    if (in != NULL) {
        if (out == NULL) {
            if (CRYPTO_gcm128_aad(&gctx->gcm, in, len))
                return -1;
        } else if (ctx->encrypt) {
            if (gctx->ctr != NULL) {
                if (CRYPTO_gcm128_encrypt_ctr32(&gctx->gcm, in, out, len, gctx->ctr))
                    return -1;
            } else {
                if (CRYPTO_gcm128_encrypt(&gctx->gcm, in, out, len))
                    return -1;
            }
        } else {
            if (gctx->ctr != NULL) {
                if (CRYPTO_gcm128_decrypt_ctr32(&gctx->gcm, in, out, len, gctx->ctr))
                    return -1;
            } else {
                if (CRYPTO_gcm128_decrypt(&gctx->gcm, in, out, len))
                    return -1;
            }
        }
        return len;
    } else {
        if (!ctx->encrypt) {
            if (gctx->taglen < 0)
                return -1;
            if (CRYPTO_gcm128_finish(&gctx->gcm, ctx->buf, gctx->taglen) != 0)
                return -1;
            gctx->iv_set = 0;
            return 0;
        }
        CRYPTO_gcm128_tag(&gctx->gcm, ctx->buf, 16);
        gctx->taglen = 16;
        /* Don't reuse the IV */
        gctx->iv_set = 0;
        return 0;
    }
}

static int sm4_gcm_cleanup(EVP_CIPHER_CTX *c)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX, c);
    const uint8_t *iv;

    if (gctx == NULL)
        return 0;

    iv = EVP_CIPHER_CTX_iv(c);
    if (iv != gctx->iv)
        OPENSSL_free(gctx->iv);

    OPENSSL_cleanse(gctx, sizeof(*gctx));
    return 1;
}

#define SM4_GCM_NONCE_LENGTH 12
DEFINE_METHOD_FUNCTION(EVP_CIPHER, EVP_sm4_gcm) {
  memset(out, 0, sizeof(EVP_CIPHER));

  out->nid = NID_sm4_gcm;
  out->block_size = 1;
  out->key_len = 16;
  out->iv_len = SM4_GCM_NONCE_LENGTH;
  out->ctx_size = sizeof(EVP_SM4_GCM_CTX) + EVP_SM4_GCM_CTX_PADDING;
  out->flags = EVP_CIPH_GCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_CUSTOM_COPY |
               EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_ALWAYS_CALL_INIT |
               EVP_CIPH_CTRL_INIT | EVP_CIPH_FLAG_AEAD_CIPHER;
  out->init = sm4_gcm_init;
  out->cipher = sm4_gcm_cipher;
  out->cleanup = sm4_gcm_cleanup;
  out->ctrl = sm4_gcm_ctrl;
}

#endif // sm4_gcm