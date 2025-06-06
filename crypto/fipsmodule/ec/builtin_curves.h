// Copyright 2023 The BoringSSL Authors
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

// This file is generated by make_tables.go.

// P-224
[[maybe_unused]] static const uint64_t kP224FieldN0 = 0xffffffffffffffff;
[[maybe_unused]] static const uint64_t kP224OrderN0 = 0xd6e242706a1fc2eb;
#if defined(OPENSSL_64_BIT)
[[maybe_unused]] static const uint64_t kP224Field[] = {
    0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff,
    0x00000000ffffffff};
[[maybe_unused]] static const uint64_t kP224Order[] = {
    0x13dd29455c5c2a3d, 0xffff16a2e0b8f03e, 0xffffffffffffffff,
    0x00000000ffffffff};
[[maybe_unused]] static const uint64_t kP224B[] = {
    0x270b39432355ffb4, 0x5044b0b7d7bfd8ba, 0x0c04b3abf5413256,
    0x00000000b4050a85};
[[maybe_unused]] static const uint64_t kP224GX[] = {
    0x343280d6115c1d21, 0x4a03c1d356c21122, 0x6bb4bf7f321390b9,
    0x00000000b70e0cbd};
[[maybe_unused]] static const uint64_t kP224GY[] = {
    0x44d5819985007e34, 0xcd4375a05a074764, 0xb5f723fb4c22dfe6,
    0x00000000bd376388};
[[maybe_unused]] static const uint64_t kP224FieldR[] = {
    0xffffffff00000000, 0xffffffffffffffff, 0x0000000000000000,
    0x0000000000000000};
[[maybe_unused]] static const uint64_t kP224FieldRR[] = {
    0xffffffff00000001, 0xffffffff00000000, 0xfffffffe00000000,
    0x00000000ffffffff};
[[maybe_unused]] static const uint64_t kP224OrderRR[] = {
    0x29947a695f517d15, 0xabc8ff5931d63f4b, 0x6ad15f7cd9714856,
    0x00000000b1e97961};
[[maybe_unused]] static const uint64_t kP224MontB[] = {
    0xe768cdf663c059cd, 0x107ac2f3ccf01310, 0x3dceba98c8528151,
    0x000000007fc02f93};
[[maybe_unused]] static const uint64_t kP224MontGX[] = {
    0xbc9052266d0a4aea, 0x852597366018bfaa, 0x6dd3af9bf96bec05,
    0x00000000a21b5e60};
[[maybe_unused]] static const uint64_t kP224MontGY[] = {
    0x2edca1e5eff3ede8, 0xf8cd672b05335a6b, 0xaea9c5ae03dfe878,
    0x00000000614786f1};
#elif defined(OPENSSL_32_BIT)
[[maybe_unused]] static const uint32_t kP224Field[] = {
    0x00000001, 0x00000000, 0x00000000, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff};
[[maybe_unused]] static const uint32_t kP224Order[] = {
    0x5c5c2a3d, 0x13dd2945, 0xe0b8f03e, 0xffff16a2,
    0xffffffff, 0xffffffff, 0xffffffff};
[[maybe_unused]] static const uint32_t kP224B[] = {
    0x2355ffb4, 0x270b3943, 0xd7bfd8ba, 0x5044b0b7,
    0xf5413256, 0x0c04b3ab, 0xb4050a85};
[[maybe_unused]] static const uint32_t kP224GX[] = {
    0x115c1d21, 0x343280d6, 0x56c21122, 0x4a03c1d3,
    0x321390b9, 0x6bb4bf7f, 0xb70e0cbd};
[[maybe_unused]] static const uint32_t kP224GY[] = {
    0x85007e34, 0x44d58199, 0x5a074764, 0xcd4375a0,
    0x4c22dfe6, 0xb5f723fb, 0xbd376388};
[[maybe_unused]] static const uint32_t kP224FieldR[] = {
    0xffffffff, 0xffffffff, 0xffffffff, 0x00000000,
    0x00000000, 0x00000000, 0x00000000};
[[maybe_unused]] static const uint32_t kP224FieldRR[] = {
    0x00000001, 0x00000000, 0x00000000, 0xfffffffe,
    0xffffffff, 0xffffffff, 0x00000000};
[[maybe_unused]] static const uint32_t kP224OrderRR[] = {
    0x3ad01289, 0x6bdaae6c, 0x97a54552, 0x6ad09d91,
    0xb1e97961, 0x1822bc47, 0xd4baa4cf};
[[maybe_unused]] static const uint32_t kP224MontB[] = {
    0xe768cdf7, 0xccf01310, 0x743b1cc0, 0xc8528150,
    0x3dceba98, 0x7fc02f93, 0x9c3fa633};
[[maybe_unused]] static const uint32_t kP224MontGX[] = {
    0xbc905227, 0x6018bfaa, 0xf22fe220, 0xf96bec04,
    0x6dd3af9b, 0xa21b5e60, 0x92f5b516};
[[maybe_unused]] static const uint32_t kP224MontGY[] = {
    0x2edca1e6, 0x05335a6b, 0xe8c15513, 0x03dfe878,
    0xaea9c5ae, 0x614786f1, 0x100c1218};
#else
#error "unknown word size"
#endif

// sm2-p256v1
[[maybe_unused]] static const uint64_t kSM2_256FieldN0 = 0x0000000000000001;
[[maybe_unused]] static const uint64_t kSM2_256OrderN0 = 0x327f9e8872350975;
#if defined(OPENSSL_64_BIT)
// P
[[maybe_unused]] static const uint64_t kSM2_256Field[] = {
    0xffffffffffffffff, 0xffffffff00000000, 0xffffffffffffffff,
    0xfffffffeffffffff};
// Order
[[maybe_unused]] static const uint64_t kSM2_256Order[] = {
    0x53bbf40939d54123, 0x7203df6b21c6052b, 0xffffffffffffffff,
    0xfffffffeffffffff};
[[maybe_unused]] static const uint64_t kSM2_256FieldR[] = {
    0x0000000000000001, 0x00000000ffffffff, 0x0000000000000000,
    0x0000000100000000};
[[maybe_unused]] static const uint64_t kSM2_256FieldRR[] = {
    0x0000000200000003, 0x00000002ffffffff, 0x0000000100000001,
    0x0000000400000002};
[[maybe_unused]] static const uint64_t kSM2_256OrderRR[] = {
    0x901192af7c114f20, 0x3464504ade6fa2fa, 0x620fc84c3affe0d4,
    0x1eb5e412a22b3d3b};
[[maybe_unused]] static const uint64_t kSM2_256MontB[] = {
    0x90d230632bc0dd42, 0x71cf379ae9b537ab, 0x527981505ea51c3c,
    0x240fe188ba20e2c8};
[[maybe_unused]] static const uint64_t kSM2_256MontGX[] = {
    0x61328990f418029e, 0x3e7981eddca6c050, 0xd6a1ed99ac24c3c3,
    0x91167a5ee1c13b05};
[[maybe_unused]] static const uint64_t kSM2_256MontGY[] = {
    0xc1354e593c2d0ddd, 0xc1f5e5788d3295fa, 0x8d4cfb066e2a48f8,
    0x63cd65d481d735bd};
#elif defined(OPENSSL_32_BIT)
// P
[[maybe_unused]] static const uint32_t kSM2_256Field[] = {
    0xffffffff, 0xffffffff, 0x00000000, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe};
// Order
[[maybe_unused]] static const uint32_t kSM2_256Order[] = {
    0x39d54123, 0x53bbf409, 0x21c6052b, 0x7203df6b,
    0xffffffff, 0xffffffff, 0xfffffffe, 0xffffffff};
[[maybe_unused]] static const uint32_t kSM2_256FieldR[] = {
    0x00000001, 0x00000000, 0xffffffff, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000001};
[[maybe_unused]] static const uint32_t kSM2_256FieldRR[] = {
    0x00000003, 0x00000002, 0xffffffff, 0x00000002,
    0x00000001, 0x00000001, 0x00000002, 0x00000004};
[[maybe_unused]] static const uint32_t kSM2_256OrderRR[] = {
    0x7c114f20, 0x901192af, 0xde6fa2fa, 0x3464504a,
    0x3affe0d4, 0x620fc84c, 0xa22b3d3b, 0x1eb5e412};
[[maybe_unused]] static const uint32_t kSM2_256MontB[] = {
    0x2bc0dd42, 0x90d23063, 0xe9b537ab, 0x71cf379a,
    0x5ea51c3c, 0x52798150, 0xba20e2c8, 0x240fe188};
[[maybe_unused]] static const uint32_t kSM2_256MontGX[] = {
    0xf418029e, 0x61328990, 0xdca6c050, 0x3e7981ed,
    0xac24c3c3, 0xd6a1ed99, 0xe1c13b05, 0x91167a5e};
[[maybe_unused]] static const uint32_t kSM2_256MontGY[] = {
    0x3c2d0ddd, 0xc1354e59, 0x8d3295fa, 0xc1f5e578
    0x6e2a48f8, 0x8d4cfb06, 0x81d735bd, 0x63cd65d4};
#else
#error "unknown word size"
#endif

// P-256
[[maybe_unused]] static const uint64_t kP256FieldN0 = 0x0000000000000001;
[[maybe_unused]] static const uint64_t kP256OrderN0 = 0xccd1c8aaee00bc4f;
#if defined(OPENSSL_64_BIT)
[[maybe_unused]] static const uint64_t kP256Field[] = {
    0xffffffffffffffff, 0x00000000ffffffff, 0x0000000000000000,
    0xffffffff00000001};
[[maybe_unused]] static const uint64_t kP256Order[] = {
    0xf3b9cac2fc632551, 0xbce6faada7179e84, 0xffffffffffffffff,
    0xffffffff00000000};
[[maybe_unused]] static const uint64_t kP256FieldR[] = {
    0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff,
    0x00000000fffffffe};
[[maybe_unused]] static const uint64_t kP256FieldRR[] = {
    0x0000000000000003, 0xfffffffbffffffff, 0xfffffffffffffffe,
    0x00000004fffffffd};
[[maybe_unused]] static const uint64_t kP256OrderRR[] = {
    0x83244c95be79eea2, 0x4699799c49bd6fa6, 0x2845b2392b6bec59,
    0x66e12d94f3d95620};
[[maybe_unused]] static const uint64_t kP256MontB[] = {
    0xd89cdf6229c4bddf, 0xacf005cd78843090, 0xe5a220abf7212ed6,
    0xdc30061d04874834};
[[maybe_unused]] static const uint64_t kP256MontGX[] = {
    0x79e730d418a9143c, 0x75ba95fc5fedb601, 0x79fb732b77622510,
    0x18905f76a53755c6};
[[maybe_unused]] static const uint64_t kP256MontGY[] = {
    0xddf25357ce95560a, 0x8b4ab8e4ba19e45c, 0xd2e88688dd21f325,
    0x8571ff1825885d85};
#elif defined(OPENSSL_32_BIT)
[[maybe_unused]] static const uint32_t kP256Field[] = {
    0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 0x00000000, 0x00000000,
    0x00000001, 0xffffffff};
[[maybe_unused]] static const uint32_t kP256Order[] = {
    0xfc632551, 0xf3b9cac2, 0xa7179e84, 0xbce6faad, 0xffffffff, 0xffffffff,
    0x00000000, 0xffffffff};
[[maybe_unused]] static const uint32_t kP256FieldR[] = {
    0x00000001, 0x00000000, 0x00000000, 0xffffffff, 0xffffffff, 0xffffffff,
    0xfffffffe, 0x00000000};
[[maybe_unused]] static const uint32_t kP256FieldRR[] = {
    0x00000003, 0x00000000, 0xffffffff, 0xfffffffb, 0xfffffffe, 0xffffffff,
    0xfffffffd, 0x00000004};
[[maybe_unused]] static const uint32_t kP256OrderRR[] = {
    0xbe79eea2, 0x83244c95, 0x49bd6fa6, 0x4699799c, 0x2b6bec59, 0x2845b239,
    0xf3d95620, 0x66e12d94};
[[maybe_unused]] static const uint32_t kP256MontB[] = {
    0x29c4bddf, 0xd89cdf62, 0x78843090, 0xacf005cd, 0xf7212ed6, 0xe5a220ab,
    0x04874834, 0xdc30061d};
[[maybe_unused]] static const uint32_t kP256MontGX[] = {
    0x18a9143c, 0x79e730d4, 0x5fedb601, 0x75ba95fc, 0x77622510, 0x79fb732b,
    0xa53755c6, 0x18905f76};
[[maybe_unused]] static const uint32_t kP256MontGY[] = {
    0xce95560a, 0xddf25357, 0xba19e45c, 0x8b4ab8e4, 0xdd21f325, 0xd2e88688,
    0x25885d85, 0x8571ff18};
#else
#error "unknown word size"
#endif

// P-384
[[maybe_unused]] static const uint64_t kP384FieldN0 = 0x0000000100000001;
[[maybe_unused]] static const uint64_t kP384OrderN0 = 0x6ed46089e88fdc45;
#if defined(OPENSSL_64_BIT)
[[maybe_unused]] static const uint64_t kP384Field[] = {
    0x00000000ffffffff, 0xffffffff00000000, 0xfffffffffffffffe,
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};
[[maybe_unused]] static const uint64_t kP384Order[] = {
    0xecec196accc52973, 0x581a0db248b0a77a, 0xc7634d81f4372ddf,
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};
[[maybe_unused]] static const uint64_t kP384FieldR[] = {
    0xffffffff00000001, 0x00000000ffffffff, 0x0000000000000001,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000};
[[maybe_unused]] static const uint64_t kP384FieldRR[] = {
    0xfffffffe00000001, 0x0000000200000000, 0xfffffffe00000000,
    0x0000000200000000, 0x0000000000000001, 0x0000000000000000};
[[maybe_unused]] static const uint64_t kP384OrderRR[] = {
    0x2d319b2419b409a9, 0xff3d81e5df1aa419, 0xbc3e483afcb82947,
    0xd40d49174aab1cc5, 0x3fb05b7a28266895, 0x0c84ee012b39bf21};
[[maybe_unused]] static const uint64_t kP384MontB[] = {
    0x081188719d412dcc, 0xf729add87a4c32ec, 0x77f2209b1920022e,
    0xe3374bee94938ae2, 0xb62b21f41f022094, 0xcd08114b604fbff9};
[[maybe_unused]] static const uint64_t kP384MontGX[] = {
    0x3dd0756649c0b528, 0x20e378e2a0d6ce38, 0x879c3afc541b4d6e,
    0x6454868459a30eff, 0x812ff723614ede2b, 0x4d3aadc2299e1513};
[[maybe_unused]] static const uint64_t kP384MontGY[] = {
    0x23043dad4b03a4fe, 0xa1bfa8bf7bb4a9ac, 0x8bade7562e83b050,
    0xc6c3521968f4ffd9, 0xdd8002263969a840, 0x2b78abc25a15c5e9};
#elif defined(OPENSSL_32_BIT)
[[maybe_unused]] static const uint32_t kP384Field[] = {
    0xffffffff, 0x00000000, 0x00000000, 0xffffffff, 0xfffffffe, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
[[maybe_unused]] static const uint32_t kP384Order[] = {
    0xccc52973, 0xecec196a, 0x48b0a77a, 0x581a0db2, 0xf4372ddf, 0xc7634d81,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
[[maybe_unused]] static const uint32_t kP384FieldR[] = {
    0x00000001, 0xffffffff, 0xffffffff, 0x00000000, 0x00000001, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
[[maybe_unused]] static const uint32_t kP384FieldRR[] = {
    0x00000001, 0xfffffffe, 0x00000000, 0x00000002, 0x00000000, 0xfffffffe,
    0x00000000, 0x00000002, 0x00000001, 0x00000000, 0x00000000, 0x00000000};
[[maybe_unused]] static const uint32_t kP384OrderRR[] = {
    0x19b409a9, 0x2d319b24, 0xdf1aa419, 0xff3d81e5, 0xfcb82947, 0xbc3e483a,
    0x4aab1cc5, 0xd40d4917, 0x28266895, 0x3fb05b7a, 0x2b39bf21, 0x0c84ee01};
[[maybe_unused]] static const uint32_t kP384MontB[] = {
    0x9d412dcc, 0x08118871, 0x7a4c32ec, 0xf729add8, 0x1920022e, 0x77f2209b,
    0x94938ae2, 0xe3374bee, 0x1f022094, 0xb62b21f4, 0x604fbff9, 0xcd08114b};
[[maybe_unused]] static const uint32_t kP384MontGX[] = {
    0x49c0b528, 0x3dd07566, 0xa0d6ce38, 0x20e378e2, 0x541b4d6e, 0x879c3afc,
    0x59a30eff, 0x64548684, 0x614ede2b, 0x812ff723, 0x299e1513, 0x4d3aadc2};
[[maybe_unused]] static const uint32_t kP384MontGY[] = {
    0x4b03a4fe, 0x23043dad, 0x7bb4a9ac, 0xa1bfa8bf, 0x2e83b050, 0x8bade756,
    0x68f4ffd9, 0xc6c35219, 0x3969a840, 0xdd800226, 0x5a15c5e9, 0x2b78abc2};
#else
#error "unknown word size"
#endif

// P-521
[[maybe_unused]] static const uint64_t kP521FieldN0 = 0x0000000000000001;
[[maybe_unused]] static const uint64_t kP521OrderN0 = 0x1d2f5ccd79a995c7;
#if defined(OPENSSL_64_BIT)
[[maybe_unused]] static const uint64_t kP521Field[] = {
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff, 0x00000000000001ff};
[[maybe_unused]] static const uint64_t kP521Order[] = {
    0xbb6fb71e91386409, 0x3bb5c9b8899c47ae, 0x7fcc0148f709a5d0,
    0x51868783bf2f966b, 0xfffffffffffffffa, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff, 0x00000000000001ff};
[[maybe_unused]] static const uint64_t kP521FieldR[] = {
    0x0080000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000};
[[maybe_unused]] static const uint64_t kP521FieldRR[] = {
    0x0000000000000000, 0x0000400000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000};
[[maybe_unused]] static const uint64_t kP521OrderRR[] = {
    0x137cd04dcf15dd04, 0xf707badce5547ea3, 0x12a78d38794573ff,
    0xd3721ef557f75e06, 0xdd6e23d82e49c7db, 0xcff3d142b7756e3e,
    0x5bcc6d61a8e567bc, 0x2d8e03d1492d0d45, 0x000000000000003d};
[[maybe_unused]] static const uint64_t kP521MontB[] = {
    0x8014654fae586387, 0x78f7a28fea35a81f, 0x839ab9efc41e961a,
    0xbd8b29605e9dd8df, 0xf0ab0c9ca8f63f49, 0xf9dc5a44c8c77884,
    0x77516d392dccd98a, 0x0fc94d10d05b42a0, 0x000000000000004d};
[[maybe_unused]] static const uint64_t kP521MontGX[] = {
    0xb331a16381adc101, 0x4dfcbf3f18e172de, 0x6f19a459e0c2b521,
    0x947f0ee093d17fd4, 0xdd50a5af3bf7f3ac, 0x90fc1457b035a69e,
    0x214e32409c829fda, 0xe6cf1f65b311cada, 0x0000000000000074};
[[maybe_unused]] static const uint64_t kP521MontGY[] = {
    0x28460e4a5a9e268e, 0x20445f4a3b4fe8b3, 0xb09a9e3843513961,
    0x2062a85c809fd683, 0x164bf7394caf7a13, 0x340bd7de8b939f33,
    0xeccc7aa224abcda2, 0x022e452fda163e8d, 0x00000000000001e0};
#elif defined(OPENSSL_32_BIT)
[[maybe_unused]] static const uint32_t kP521Field[] = {
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x000001ff};
[[maybe_unused]] static const uint32_t kP521Order[] = {
    0x91386409, 0xbb6fb71e, 0x899c47ae, 0x3bb5c9b8, 0xf709a5d0, 0x7fcc0148,
    0xbf2f966b, 0x51868783, 0xfffffffa, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x000001ff};
[[maybe_unused]] static const uint32_t kP521FieldR[] = {
    0x00800000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
[[maybe_unused]] static const uint32_t kP521FieldRR[] = {
    0x00000000, 0x00004000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
[[maybe_unused]] static const uint32_t kP521OrderRR[] = {
    0x61c64ca7, 0x1163115a, 0x4374a642, 0x18354a56, 0x0791d9dc, 0x5d4dd6d3,
    0xd3402705, 0x4fb35b72, 0xb7756e3a, 0xcff3d142, 0xa8e567bc, 0x5bcc6d61,
    0x492d0d45, 0x2d8e03d1, 0x8c44383d, 0x5b5a3afe, 0x0000019a};
[[maybe_unused]] static const uint32_t kP521MontB[] = {
    0x8014654f, 0xea35a81f, 0x78f7a28f, 0xc41e961a, 0x839ab9ef, 0x5e9dd8df,
    0xbd8b2960, 0xa8f63f49, 0xf0ab0c9c, 0xc8c77884, 0xf9dc5a44, 0x2dccd98a,
    0x77516d39, 0xd05b42a0, 0x0fc94d10, 0xb0c70e4d, 0x0000015c};
[[maybe_unused]] static const uint32_t kP521MontGX[] = {
    0xb331a163, 0x18e172de, 0x4dfcbf3f, 0xe0c2b521, 0x6f19a459, 0x93d17fd4,
    0x947f0ee0, 0x3bf7f3ac, 0xdd50a5af, 0xb035a69e, 0x90fc1457, 0x9c829fda,
    0x214e3240, 0xb311cada, 0xe6cf1f65, 0x5b820274, 0x00000103};
[[maybe_unused]] static const uint32_t kP521MontGY[] = {
    0x28460e4a, 0x3b4fe8b3, 0x20445f4a, 0x43513961, 0xb09a9e38, 0x809fd683,
    0x2062a85c, 0x4caf7a13, 0x164bf739, 0x8b939f33, 0x340bd7de, 0x24abcda2,
    0xeccc7aa2, 0xda163e8d, 0x022e452f, 0x3c4d1de0, 0x000000b5};
#else
#error "unknown word size"
#endif
