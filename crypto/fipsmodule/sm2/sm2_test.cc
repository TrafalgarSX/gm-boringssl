#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <openssl/sm2.h>
#include <openssl/evp.h>
#include <openssl/mem.h>

/*
Title = SM2 tests

PrivateKey=SM2_key1
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg0JFWczAXva2An9m7
2MaT9gIwWTFptvlKrxyO4TjMmbWhRANCAAQ5OirZ4n5DrKqrhaGdO4VZHhRAYVcX
Wt3Te/d/8Mr57Tf886i09VwDhSMmH8pmNq/mp6+ioUgqYG9cs6GLLioe
-----END PRIVATE KEY-----

Verify = SM2_key1
Ctrl = digest:SM3
Input = D7AD397F6FFA5D4F7F11E7217F241607DC30618C236D2C09C1B9EA8FDADEE2E8
Output = 3046022100AB1DB64DE7C40EDBDE6651C9B8EBDB804673DB836E5D5C7FE15DCF9ED2725037022100EBA714451FF69B0BB930B379E192E7CD5FA6E3C41C7FBD8303B799AB54A54621

Verify = SM2_key1
Ctrl = digest:SM3
Input = B1139602C6ECC9E15E2F3F9C635A1AFE737058BC15387479C1EA0D0B3D90E9E5
Output = 3045022100E6E0414EBD3A656C35602AF14AB20287DBF30D57AF75C49A188ED4B42391F22402202F54F277C606F4605E1CE9514947FFDDF94C67A539804A4ED17F852288BDBE2E

Verify = SM2_key1
Ctrl = digest:SHA512
Input = 40AA1B203C9D8EE150B21C3C7CDA8261492E5420C5F2B9F7380700E094C303B48E62F319C1DA0E32EB40D113C5F1749CC61AEB499167890AB82F2CC9BB706971
Output = 3046022100AE018933B9BA041784380069F2DDF609694DCD299FDBF23D09F4B711FBC103EC0221008440BB1A48C132DE4FB91BE9F43B958142FDD29FB9DABE01B17514023A2F638C

Decrypt = SM2_key1
Input = 30818A0220466BE2EF5C11782EC77864A0055417F407A5AFC11D653C6BCE69E417BB1D05B6022062B572E21FF0DDF5C726BD3F9FF2EAE56E6294713A607E9B9525628965F62CC804203C1B5713B5DB2728EB7BF775E44F4689FC32668BDC564F52EA45B09E8DF2A5F40422084A9D0CC2997092B7D3C404FCE95956EB604D732B2307A8E5B8900ED6608CA5B197
Output = "The floofy bunnies hop at midnight"

# This is a "fake" test as it does only verify that the SM2 EVP_PKEY interface
# is capable of creating a signature without failing, but it does not say
# anything about the generated signature being valid, nor does it test the
# correct implementation of the cryptosystem.
Sign = SM2_key1
Ctrl = digest:SM3
Input = D7AD397F6FFA5D4F7F11E7217F241607DC30618C236D2C09C1B9EA8FDADEE2E8
Output = 3045022100f11bf36e75bb304f094fb42a4ca22377d0cc768637c5011cd59fb9ed4b130c98022035545ffe2c2efb3abee4fee661468946d886004fae8ea5311593e48f7fe21b91
Result = KEYOP_MISMATCH
*/

static const unsigned char kMsg[] = { 1, 2, 3, 4 };

TEST(SM2Test, test_sm2) {
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    size_t sig_len = 0;
    unsigned char *sig = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_MD_CTX *md_ctx_verify = NULL;
    EVP_PKEY_CTX *cctx = NULL;

    uint8_t ciphertext[128];
    size_t ctext_len = sizeof(ciphertext);

    uint8_t plaintext[8];
    size_t ptext_len = sizeof(plaintext);

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
    ASSERT_TRUE(pctx != NULL);

    if (!EVP_PKEY_paramgen_init(pctx))
        goto done;

    if (!EVP_PKEY_CTX_set_sm2_paramgen_curve_nid(pctx, NID_sm2))
        goto done;

    if (!EVP_PKEY_paramgen(pctx, &params))
        goto done;

    kctx = EVP_PKEY_CTX_new(params, NULL);
    if (!kctx)
        goto done;

    if (!EVP_PKEY_keygen_init(kctx))
        goto done;

    if (!EVP_PKEY_keygen(kctx, &pkey))
        goto done;

    if (!EVP_PKEY_set_type(pkey, EVP_PKEY_SM2))
        goto done;

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
        goto done;
    md_ctx_verify = EVP_MD_CTX_new();
    if (!md_ctx_verify)
        goto done;

    if (!EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), NULL, pkey))
        goto done;

    if(!EVP_DigestSignUpdate(md_ctx, kMsg, sizeof(kMsg)))
        goto done;

    /* Determine the size of the signature. */
    if (!EVP_DigestSignFinal(md_ctx, NULL, &sig_len))
        goto done;

    if (!(sig_len == (size_t)EVP_PKEY_size(pkey)))
        goto done;

    sig = (uint8_t *)OPENSSL_malloc(sig_len);
    if (!sig)
        goto done;

    if (!EVP_DigestSignFinal(md_ctx, sig, &sig_len))
        goto done;

    /* Ensure that the signature round-trips. */

    if (!EVP_DigestVerifyInit(md_ctx_verify, NULL, EVP_sm3(), NULL, pkey))
        goto done;

    if (!EVP_DigestVerifyUpdate(md_ctx_verify, kMsg, sizeof(kMsg)))
        goto done;

    if (!EVP_DigestVerifyFinal(md_ctx_verify, sig, sig_len))
        goto done;

    /* now check encryption/decryption */
    cctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!cctx)
        goto done;

    if (!EVP_PKEY_encrypt_init(cctx))
        goto done;

    if (!EVP_PKEY_encrypt(cctx, ciphertext, &ctext_len, kMsg, sizeof(kMsg)))
        goto done;

    if (!EVP_PKEY_decrypt_init(cctx))
        goto done;

    if (!EVP_PKEY_decrypt(cctx, plaintext, &ptext_len, ciphertext, ctext_len))
        goto done;

    if (!(ptext_len == sizeof(kMsg)))
        goto done;

    if (!(memcmp(plaintext, kMsg, sizeof(kMsg)) == 0))
        goto done;

    ret = 1;
done:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(cctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(params);
    EVP_MD_CTX_free(md_ctx);
    EVP_MD_CTX_free(md_ctx_verify);
    OPENSSL_free(sig);
    std::cout << "SM2 test result: " << (ret ? "PASS" : "FAIL") << std::endl;
}

TEST(SM2Test, test_sm2_vector) {
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    size_t sig_len = 0;
    unsigned char *sig = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_MD_CTX *md_ctx_verify = NULL;
    EVP_PKEY_CTX *cctx = NULL;

    uint8_t ciphertext[128];
    size_t ctext_len = sizeof(ciphertext);

    uint8_t plaintext[8];
    size_t ptext_len = sizeof(plaintext);

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    ASSERT_TRUE(pctx != NULL);

    if (!EVP_PKEY_paramgen_init(pctx))
        goto done;

    if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_sm2))
        goto done;

    if (!EVP_PKEY_paramgen(pctx, &params))
        goto done;

    kctx = EVP_PKEY_CTX_new(params, NULL);
    if (!kctx)
        goto done;

    if (!EVP_PKEY_keygen_init(kctx))
        goto done;

    if (!EVP_PKEY_keygen(kctx, &pkey))
        goto done;

    if (!EVP_PKEY_set_type(pkey, EVP_PKEY_SM2))
        goto done;

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
        goto done;
    md_ctx_verify = EVP_MD_CTX_new();
    if (!md_ctx_verify)
        goto done;

    if (!EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), NULL, pkey))
        goto done;

    if(!EVP_DigestSignUpdate(md_ctx, kMsg, sizeof(kMsg)))
        goto done;

    /* Determine the size of the signature. */
    if (!EVP_DigestSignFinal(md_ctx, NULL, &sig_len))
        goto done;

    if (!(sig_len == (size_t)EVP_PKEY_size(pkey)))
        goto done;

    sig = (uint8_t *)OPENSSL_malloc(sig_len);
    if (!sig)
        goto done;

    if (!EVP_DigestSignFinal(md_ctx, sig, &sig_len))
        goto done;

    /* Ensure that the signature round-trips. */

    if (!EVP_DigestVerifyInit(md_ctx_verify, NULL, EVP_sm3(), NULL, pkey))
        goto done;

    if (!EVP_DigestVerifyUpdate(md_ctx_verify, kMsg, sizeof(kMsg)))
        goto done;

    if (!EVP_DigestVerifyFinal(md_ctx_verify, sig, sig_len))
        goto done;

    /* now check encryption/decryption */
    cctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!cctx)
        goto done;

    if (!EVP_PKEY_encrypt_init(cctx))
        goto done;

    if (!EVP_PKEY_encrypt(cctx, ciphertext, &ctext_len, kMsg, sizeof(kMsg)))
        goto done;

    if (!EVP_PKEY_decrypt_init(cctx))
        goto done;

    if (!EVP_PKEY_decrypt(cctx, plaintext, &ptext_len, ciphertext, ctext_len))
        goto done;

    if (!(ptext_len == sizeof(kMsg)))
        goto done;

    if (!(memcmp(plaintext, kMsg, sizeof(kMsg)) == 0))
        goto done;

    ret = 1;
done:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(cctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(params);
    EVP_MD_CTX_free(md_ctx);
    EVP_MD_CTX_free(md_ctx_verify);
    OPENSSL_free(sig);
    std::cout << "SM2 test result: " << (ret ? "PASS" : "FAIL") << std::endl;
}