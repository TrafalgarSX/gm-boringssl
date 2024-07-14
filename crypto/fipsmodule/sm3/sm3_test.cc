/* Copyright (c) 2014, Google Inc.
 * Copyright (c) 2024 guoyawen98@gmail.com.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <openssl/sm3.h>

#include "../../test/test_util.h"

TEST(SM3Test, sm3) {
  std::string s = "abc";
  std::vector<uint8_t> s_byte(s.begin(), s.end());

  unsigned char digest[SM3_DIGEST_LENGTH];
  std::string s_digest = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
  std::vector<uint8_t> b_digest;
  ASSERT_TRUE(DecodeHex(&b_digest, s_digest));

  SM3(s_byte.data(), s_byte.size(), digest);

  EXPECT_EQ(Bytes(b_digest.data(), b_digest.size()), Bytes(digest, sizeof(digest)));


  uint8_t block[SM3_CBLOCK] = {0};
  std::fill_n(block, SM3_CBLOCK, 0x11);
  SM3_CTX ctx;
  SM3_Init(&ctx);
  SM3_Transform(&ctx, block);

  for(int i = 0; i < 8; i++) {
    std::cout << ctx.A[i] << " ";
  }
  std::cout << std::endl;



  s = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
  std::vector<uint8_t> s_byte2(s.begin(), s.end());
  s_digest = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732";
  ASSERT_TRUE(DecodeHex(&b_digest, s_digest));

  SM3(s_byte2.data(), s_byte2.size(), digest);

  EXPECT_EQ(Bytes(b_digest.data(), b_digest.size()), Bytes(digest, sizeof(digest)));
}