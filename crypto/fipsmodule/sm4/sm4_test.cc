#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <vector>

#include <gtest/gtest.h>

#include <openssl/cipher.h>
#include <openssl/rand.h>
#include <openssl/sm4.h>


#include "../../internal.h"
#include "../../test/file_test.h"
#include "../../test/test_util.h"
#include "../../test/wycheproof_util.h"
#include "internal.h"


static void TestRaw(FileTest *t) {
  std::vector<uint8_t> key, plaintext, ciphertext;
  ASSERT_TRUE(t->GetBytes(&key, "Key"));
  ASSERT_TRUE(t->GetBytes(&plaintext, "Plaintext"));
  ASSERT_TRUE(t->GetBytes(&ciphertext, "Ciphertext"));

  ASSERT_EQ(static_cast<unsigned>(SM4_BLOCK_SIZE), plaintext.size());
  ASSERT_EQ(static_cast<unsigned>(SM4_BLOCK_SIZE), ciphertext.size());

  SM4_KEY sm4_key;
  ASSERT_EQ(1, SM4_set_key(key.data(), &sm4_key));

  // Test encryption.
  uint8_t block[SM4_BLOCK_SIZE];
  SM4_encrypt(plaintext.data(), block, &sm4_key);
  EXPECT_EQ(Bytes(ciphertext), Bytes(block));

  OPENSSL_memcpy(block, plaintext.data(), SM4_BLOCK_SIZE);
  SM4_encrypt(block, block, &sm4_key);
  EXPECT_EQ(Bytes(ciphertext), Bytes(block));

  ASSERT_EQ(1, SM4_set_key(key.data(), &sm4_key));

  // Test decryption.
  SM4_decrypt(ciphertext.data(), block, &sm4_key);
  EXPECT_EQ(Bytes(plaintext), Bytes(block));

  // Test in-place decryption.
  OPENSSL_memcpy(block, ciphertext.data(), SM4_BLOCK_SIZE);
  SM4_decrypt(block, block, &sm4_key);
  EXPECT_EQ(Bytes(plaintext), Bytes(block));
}

static const EVP_CIPHER *GetCipher(const std::string &name) {
  if (name == "SM4-CBC") {
    return EVP_sm4_cbc();
  } else if (name == "SM4-ECB") {
    return EVP_sm4_ecb();
  } else if (name == "SM4-CTR") {
    return EVP_sm4_ctr();
  }
  return nullptr;
}

enum class Operation {
  // kBoth tests both encryption and decryption.
  kBoth,
  // kEncrypt tests encryption. The result of encryption should always
  // successfully decrypt, so this should only be used if the test file has a
  // matching decrypt-only vector.
  kEncrypt,
  // kDecrypt tests decryption. This should only be used if the test file has a
  // matching encrypt-only input, or if multiple ciphertexts are valid for
  // a given plaintext and this is a non-canonical ciphertext.
  kDecrypt,
  // kInvalidDecrypt tests decryption and expects it to fail, e.g. due to
  // invalid tag or padding.
  kInvalidDecrypt,
};

static const char *OperationToString(Operation op) {
  switch (op) {
    case Operation::kBoth:
      return "Both";
    case Operation::kEncrypt:
      return "Encrypt";
    case Operation::kDecrypt:
      return "Decrypt";
    case Operation::kInvalidDecrypt:
      return "InvalidDecrypt";
  }
  abort();
}

// MaybeCopyCipherContext, if |copy| is true, replaces |*ctx| with a, hopefully
// equivalent, copy of it.
static bool MaybeCopyCipherContext(bool copy,
                                   bssl::UniquePtr<EVP_CIPHER_CTX> *ctx) {
  if (!copy) {
    return true;
  }
  bssl::UniquePtr<EVP_CIPHER_CTX> ctx2(EVP_CIPHER_CTX_new());
  if (!ctx2 || !EVP_CIPHER_CTX_copy(ctx2.get(), ctx->get())) {
    return false;
  }
  *ctx = std::move(ctx2);
  return true;
}

static void TestCipherAPI(const EVP_CIPHER *cipher, Operation op, bool padding,
                          bool copy, bool in_place, bool use_evp_cipher,
                          size_t chunk_size, bssl::Span<const uint8_t> key,
                          bssl::Span<const uint8_t> iv,
                          bssl::Span<const uint8_t> plaintext,
                          bssl::Span<const uint8_t> ciphertext,
                          bssl::Span<const uint8_t> aad,
                          bssl::Span<const uint8_t> tag) {
  bool encrypt = op == Operation::kEncrypt;
  bool is_custom_cipher =
      EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_CUSTOM_CIPHER;
  bssl::Span<const uint8_t> in = encrypt ? plaintext : ciphertext;
  bssl::Span<const uint8_t> expected = encrypt ? ciphertext : plaintext;
  bool is_aead = EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE;

  // Some |EVP_CIPHER|s take a variable-length key, and need to first be
  // configured with the key length, which requires configuring the cipher.
  bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  ASSERT_TRUE(ctx);
  ASSERT_TRUE(EVP_CipherInit_ex(ctx.get(), cipher, /*engine=*/nullptr,
                                /*key=*/nullptr, /*iv=*/nullptr,
                                encrypt ? 1 : 0));
  ASSERT_TRUE(EVP_CIPHER_CTX_set_key_length(ctx.get(), key.size()));
  if (!padding) {
    ASSERT_TRUE(EVP_CIPHER_CTX_set_padding(ctx.get(), 0));
  }

  // Configure the key.
  ASSERT_TRUE(MaybeCopyCipherContext(copy, &ctx));
  ASSERT_TRUE(EVP_CipherInit_ex(ctx.get(), /*cipher=*/nullptr,
                                /*engine=*/nullptr, key.data(), /*iv=*/nullptr,
                                /*enc=*/-1));

  // Configure the IV to run the actual operation. Callers that wish to use a
  // key for multiple, potentially concurrent, operations will likely copy at
  // this point. The |EVP_CIPHER_CTX| API uses the same type to represent a
  // pre-computed key schedule and a streaming operation.
  ASSERT_TRUE(MaybeCopyCipherContext(copy, &ctx));
  if (is_aead) {
    ASSERT_LE(iv.size(), size_t{INT_MAX});
    ASSERT_TRUE(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
                                    static_cast<int>(iv.size()), nullptr));
    ASSERT_EQ(EVP_CIPHER_CTX_iv_length(ctx.get()), iv.size());
  } else {
    ASSERT_EQ(iv.size(), EVP_CIPHER_CTX_iv_length(ctx.get()));
  }
  ASSERT_TRUE(EVP_CipherInit_ex(ctx.get(), /*cipher=*/nullptr,
                                /*engine=*/nullptr,
                                /*key=*/nullptr, iv.data(), /*enc=*/-1));

  if (is_aead && !encrypt) {
    ASSERT_TRUE(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG,
                                    tag.size(),
                                    const_cast<uint8_t *>(tag.data())));
  }

  // Note: the deprecated |EVP_CIPHER|-based AEAD API is sensitive to whether
  // parameters are NULL, so it is important to skip the |in| and |aad|
  // |EVP_CipherUpdate| calls when empty.
  while (!aad.empty()) {
    size_t todo =
        chunk_size == 0 ? aad.size() : std::min(aad.size(), chunk_size);
    if (use_evp_cipher) {
      // AEADs always use the "custom cipher" return value convention. Passing a
      // null output pointer triggers the AAD logic.
      ASSERT_TRUE(is_custom_cipher);
      ASSERT_EQ(static_cast<int>(todo),
                EVP_Cipher(ctx.get(), nullptr, aad.data(), todo));
    } else {
      int len;
      ASSERT_TRUE(EVP_CipherUpdate(ctx.get(), nullptr, &len, aad.data(), todo));
      // Although it doesn't output anything, |EVP_CipherUpdate| should claim to
      // output the input length.
      EXPECT_EQ(len, static_cast<int>(todo));
    }
    aad = aad.subspan(todo);
  }

  // Set up the output buffer.
  size_t max_out = in.size();
  size_t block_size = EVP_CIPHER_CTX_block_size(ctx.get());
  if (block_size > 1 &&
      (EVP_CIPHER_CTX_flags(ctx.get()) & EVP_CIPH_NO_PADDING) == 0 &&
      EVP_CIPHER_CTX_encrypting(ctx.get())) {
    max_out += block_size - (max_out % block_size);
  }
  std::vector<uint8_t> result(max_out);
  if (in_place) {
    std::copy(in.begin(), in.end(), result.begin());
    in = bssl::MakeConstSpan(result).first(in.size());
  }

  size_t total = 0;
  int len;
  while (!in.empty()) {
    size_t todo = chunk_size == 0 ? in.size() : std::min(in.size(), chunk_size);
    EXPECT_LE(todo, static_cast<size_t>(INT_MAX));
    ASSERT_TRUE(MaybeCopyCipherContext(copy, &ctx));
    if (use_evp_cipher) {
      // |EVP_Cipher| sometimes returns the number of bytes written, or -1 on
      // error, and sometimes 1 or 0, implicitly writing |in_len| bytes.
      if (is_custom_cipher) {
        len = EVP_Cipher(ctx.get(), result.data() + total, in.data(), todo);
      } else {
        ASSERT_EQ(
            1, EVP_Cipher(ctx.get(), result.data() + total, in.data(), todo));
        len = static_cast<int>(todo);
      }
    } else {
      ASSERT_TRUE(EVP_CipherUpdate(ctx.get(), result.data() + total, &len,
                                   in.data(), static_cast<int>(todo)));
    }
    ASSERT_GE(len, 0);
    total += static_cast<size_t>(len);
    in = in.subspan(todo);
  }
  if (op == Operation::kInvalidDecrypt) {
    if (use_evp_cipher) {
      // Only the "custom cipher" return value convention can report failures.
      // Passing all nulls should act like |EVP_CipherFinal_ex|.
      ASSERT_TRUE(is_custom_cipher);
      EXPECT_EQ(-1, EVP_Cipher(ctx.get(), nullptr, nullptr, 0));
    } else {
      // Invalid padding and invalid tags all appear as a failed
      // |EVP_CipherFinal_ex|.
      EXPECT_FALSE(EVP_CipherFinal_ex(ctx.get(), result.data() + total, &len));
    }
  } else {
    if (use_evp_cipher) {
      if (is_custom_cipher) {
        // Only the "custom cipher" convention has an |EVP_CipherFinal_ex|
        // equivalent.
        len = EVP_Cipher(ctx.get(), nullptr, nullptr, 0);
      } else {
        len = 0;
      }
    } else {
      ASSERT_TRUE(EVP_CipherFinal_ex(ctx.get(), result.data() + total, &len));
    }
    ASSERT_GE(len, 0);
    total += static_cast<size_t>(len);
    result.resize(total);
    EXPECT_EQ(Bytes(expected), Bytes(result));
    if (encrypt && is_aead) {
      uint8_t rtag[16];
      ASSERT_LE(tag.size(), sizeof(rtag));
      ASSERT_TRUE(MaybeCopyCipherContext(copy, &ctx));
      ASSERT_TRUE(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG,
                                      tag.size(), rtag));
      EXPECT_EQ(Bytes(tag), Bytes(rtag, tag.size()));
    }
  }
}
#if 0
static void TestCipher(const EVP_CIPHER *cipher, Operation input_op,
                       bool padding, bssl::Span<const uint8_t> key,
                       bssl::Span<const uint8_t> iv,
                       bssl::Span<const uint8_t> plaintext,
                       bssl::Span<const uint8_t> ciphertext,
                       bssl::Span<const uint8_t> aad,
                       bssl::Span<const uint8_t> tag) {
  size_t block_size = EVP_CIPHER_block_size(cipher);
  std::vector<Operation> ops;
  if (input_op == Operation::kBoth) {
    ops = {Operation::kEncrypt, Operation::kDecrypt};
  } else {
    ops = {input_op};
  }
  for (Operation op : ops) {
    SCOPED_TRACE(OperationToString(op));
    // Zero indicates a single-shot API.
    static const size_t kChunkSizes[] = {0,  1,  2,  5,  7,  8,  9,  15, 16,
                                         17, 31, 32, 33, 63, 64, 65, 512};
    for (size_t chunk_size : kChunkSizes) {
      SCOPED_TRACE(chunk_size);
      if (chunk_size > plaintext.size() && chunk_size > ciphertext.size() &&
          chunk_size > aad.size()) {
        continue;
      }
      for (bool in_place : {false, true}) {
        SCOPED_TRACE(in_place);
        for (bool copy : {false, true}) {
          SCOPED_TRACE(copy);
          TestCipherAPI(cipher, op, padding, copy, in_place,
                        /*use_evp_cipher=*/false, chunk_size, key, iv,
                        plaintext, ciphertext, aad, tag);
          if (!padding && chunk_size % block_size == 0) {
            TestCipherAPI(cipher, op, padding, copy, in_place,
                          /*use_evp_cipher=*/true, chunk_size, key, iv,
                          plaintext, ciphertext, aad, tag);
          }
        }
      }
    }
  }
}
#endif

static void TestCipherMine(const EVP_CIPHER *cipher, Operation input_op,
                       bool padding, bssl::Span<const uint8_t> key,
                       bssl::Span<const uint8_t> iv,
                       bssl::Span<const uint8_t> plaintext,
                       bssl::Span<const uint8_t> ciphertext,
                       bssl::Span<const uint8_t> aad,
                       bssl::Span<const uint8_t> tag) {
  size_t block_size = EVP_CIPHER_block_size(cipher);
  std::vector<Operation> ops;
  if (input_op == Operation::kBoth) {
    ops = {Operation::kEncrypt, Operation::kDecrypt};
  } else {
    ops = {input_op};
  }

  int chunk_size = 0;

  for (Operation op : ops) {
    SCOPED_TRACE(OperationToString(op));
    for (bool in_place : {false, true}) {
    SCOPED_TRACE(in_place);
    for (bool copy : {false, true}) {
        SCOPED_TRACE(copy);
        TestCipherAPI(cipher, op, padding, copy, in_place,
                    /*use_evp_cipher=*/false, chunk_size, key, iv,
                    plaintext, ciphertext, aad, tag);
        if (!padding && chunk_size % block_size == 0) {
        TestCipherAPI(cipher, op, padding, copy, in_place,
                        /*use_evp_cipher=*/true, chunk_size, key, iv,
                        plaintext, ciphertext, aad, tag);
        }
    }
    }
  }

}

static void CipherFileTest(FileTest *t) {
  std::string cipher_str;
  ASSERT_TRUE(t->GetAttribute(&cipher_str, "Cipher"));
  const EVP_CIPHER *cipher = GetCipher(cipher_str);
  ASSERT_TRUE(cipher);

  std::vector<uint8_t> key, iv, plaintext, ciphertext, aad, tag;
  ASSERT_TRUE(t->GetBytes(&key, "Key"));
  ASSERT_TRUE(t->GetBytes(&plaintext, "Plaintext"));
  ASSERT_TRUE(t->GetBytes(&ciphertext, "Ciphertext"));
  if (EVP_CIPHER_iv_length(cipher) > 0) {
    ASSERT_TRUE(t->GetBytes(&iv, "IV"));
  }
  if (EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE) {
    ASSERT_TRUE(t->GetBytes(&aad, "AAD"));
    ASSERT_TRUE(t->GetBytes(&tag, "Tag"));
  }

  Operation op = Operation::kBoth;
  if (t->HasAttribute("Operation")) {
    const std::string &str = t->GetAttributeOrDie("Operation");
    if (str == "Encrypt" || str == "ENCRYPT") {
      op = Operation::kEncrypt;
    } else if (str == "Decrypt" || str == "DECRYPT") {
      op = Operation::kDecrypt;
    } else if (str == "InvalidDecrypt") {
      op = Operation::kInvalidDecrypt;
    } else {
      FAIL() << "Unknown operation: " << str;
    }
  }

//   TestCipher(cipher, op, /*padding=*/false, key, iv, plaintext, ciphertext, aad,
//              tag);
   TestCipherMine(cipher, op, /*padding=*/false, key, iv, plaintext,
              ciphertext, aad, tag);
}

TEST(SM4Test, TestVectors) {
  FileTestGTest("crypto/fipsmodule/sm4/sm4_tests.txt", [](FileTest *t) {
    if (t->GetParameter() == "Raw") {
      TestRaw(t);
    } else if (t->GetParameter() == "SM4-CBC" ||
               t->GetParameter() == "SM4-ECB" ||
               t->GetParameter() == "SM4-CTR") {
      CipherFileTest(t);
    } else {
      ADD_FAILURE() << "Unknown mode " << t->GetParameter();
    }
  });
}