// Copyright 2024 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <openssl/sm3.h>

#include <openssl/mem.h>

#include "../fipsmodule/bcm_interface.h"


int SM3_Init(SM3_CTX *sm3) {
  BCM_sm3_Init(sm3);
  return 1;
}

int SM3_Update(SM3_CTX *sm3, const void *data, size_t len) {
  BCM_sm3_Update(sm3, data, len);
  return 1;
}

int SM3_Final(uint8_t out[SM3_DIGEST_LENGTH], SM3_CTX *sm3) {
  BCM_sm3_Final(out, sm3);
  return 1;
}


void SM3_Transform(SM3_CTX *c, const uint8_t *data) {
    BCM_sm3_Transform(c, data);
}

uint8_t *SM3(const uint8_t *data, size_t len, uint8_t out[SM3_DIGEST_LENGTH]) {
  SM3_CTX ctx;
  BCM_sm3_Init(&ctx);
  BCM_sm3_Update(&ctx, data, len);
  BCM_sm3_Final(out, &ctx);
  OPENSSL_cleanse(&ctx, sizeof(ctx));
  return out;
}
