/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/**
   @brief       SM4 block cipher algorithm
   @date        Oct 2018
   @author      Chao Wei

   SM4 (formerly SMS4) is a block cipher used in the Chinese National
   Standard for Wireless LAN WAPI (Wired Authentication and Privacy
   Infrastructure).
   --from wikipedia:
    https://en.wikipedia.org/wiki/SM4_(cipher)

   This implimentation follows Chinese National Standard
        GM/T 0002-2012
 */
#include "tomcrypt_private.h"

#ifdef LTC_SM4

/*porting to libtomcrypt*/
/*char always 8bits long*/
typedef unsigned char sm4_u8_t;
typedef ulong32 sm4_u32_t;

/*
 * S-box defined in section 6.2
 * (1) Nonlinear transformation
 */
static const sm4_u8_t sm4_sbox_table[16][16] = {
    {0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
        0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05},
    {0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
        0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99},
    {0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
        0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62},
    {0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
        0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6},
    {0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
        0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8},
    {0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
        0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35},
    {0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
        0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87},
    {0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
        0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e},
    {0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
        0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1},
    {0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
        0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3},
    {0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
        0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f},
    {0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
        0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51},
    {0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
        0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8},
    {0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
        0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0},
    {0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
        0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84},
    {0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
        0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48},
};

/*
 * S-box
 * defined in section 2.6 S-box
 */
LTC_INLINE static sm4_u8_t s_sm4_sbox(sm4_u8_t a)
{
    return sm4_sbox_table[(a >> 4) & 0x0f][a & 0x0f];
}

/*
 * Nonlinear transformation t
 * defined in section 6.2 (1) Nonelinear transformation t
 *
 * Here should be big endian.
 * But we just convert a 32bit word byte by byte.
 * So it's OK if we don't convert the endian order
 */
LTC_INLINE static sm4_u32_t s_sm4_t(sm4_u32_t A)
{
    sm4_u8_t  a[4];
    sm4_u8_t  b[4];
    sm4_u32_t B;

    STORE32H(A, a);
    b[0] = s_sm4_sbox(a[0]);
    b[1] = s_sm4_sbox(a[1]);
    b[2] = s_sm4_sbox(a[2]);
    b[3] = s_sm4_sbox(a[3]);
    LOAD32H(B, b);
    return B;
}

/*
 * defined in section 6.2 (2) Linear transformation L
 */
LTC_INLINE static sm4_u32_t s_sm4_L62(sm4_u32_t B)
{
    return B ^ ROLc(B, 2) ^ ROLc(B, 10) ^ ROLc(B, 18) ^ ROLc(B, 24);
}

/*
 * defined in section 6.2 Permutation T
 */
LTC_INLINE static sm4_u32_t s_sm4_T62(sm4_u32_t Z)
{
    return s_sm4_L62(s_sm4_t(Z));
}

/*
 * defined in section 7.3 (2) The system parameter FK
 */
static const sm4_u32_t sm4_FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

/*
 * defined in section 7.3 (3) The fixed parameter CK
 * The fixed parameter CK is used in the key expansion algorithm
 */
static const sm4_u32_t sm4_CK[32] =
{
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
};

/*
 * defined in section 7.3 (1) L'
 */
LTC_INLINE static sm4_u32_t s_sm4_L73(sm4_u32_t B)
{
    return B ^ ROLc(B, 13) ^ ROLc(B, 23);
}

/*
 * defined in section 7.3 (1) T'
 */
LTC_INLINE static sm4_u32_t s_sm4_T73(sm4_u32_t Z)
{
    return s_sm4_L73(s_sm4_t(Z));
}

/*
 * defined in section 7.3 Key Expansion
 */
LTC_INLINE static void s_sm4_mk2rk(sm4_u32_t rk[32], sm4_u8_t mk[16])
{
    sm4_u32_t MK[4] = { 0 };
    sm4_u32_t K[4+32] = { 0 };
    int i;

    LOAD32H(MK[0], mk     );
    LOAD32H(MK[1], mk +  4);
    LOAD32H(MK[2], mk +  8);
    LOAD32H(MK[3], mk + 12);

    for (i = 0; i < 4; ++i)
        K[i] = MK[i] ^ sm4_FK[i];
    for (i = 0; i < 32; ++i)
        K[i+4] = K[i] ^ s_sm4_T73(K[i+1] ^ K[i+2] ^ K[i+3] ^ sm4_CK[i]);
    for (i = 0; i < 32; ++i)
        rk[i] = K[i+4];
}

/*
 * defined in section 6 Round Function F
 */
LTC_INLINE static sm4_u32_t s_sm4_F(sm4_u32_t X[4], sm4_u32_t rk)
{
    return X[0] ^ s_sm4_T62(X[1] ^ X[2] ^ X[3] ^ rk);
}

/*
 * defined in section 7.1 (2) The reverse transformation
 */
LTC_INLINE static void s_sm4_R(sm4_u32_t Y[4], sm4_u32_t X[32+4])
{
    Y[0] = X[35];
    Y[1] = X[34];
    Y[2] = X[33];
    Y[3] = X[32];
}

/*
 * defined in section 7.1 (En)cryption
 */
LTC_INLINE static void s_sm4_crypt(sm4_u32_t Y[4], sm4_u32_t X[4+32], const sm4_u32_t rk[32])
{
    int i;

    for (i = 0; i < 32; ++i)
        X[i+4] = s_sm4_F(X+i, rk[i]);
    s_sm4_R(Y, X);
}

LTC_INLINE static void s_sm4_setkey(struct sm4_key *sm4, const unsigned char *key)
{
    int i;

    s_sm4_mk2rk(sm4->ek,(void*)key);
    /*swap key sequence when decrypt cipher*/
    for (i = 0; i < 32; ++i)
        sm4->dk[i] = sm4->ek[32 - 1 - i];
}

int sm4_setup(const unsigned char *key, int keylen,
              int num_rounds, symmetric_key *skey)
{
    LTC_ARGCHK(key != NULL);
    LTC_ARGCHK(skey != NULL);
    if (num_rounds != 0 && num_rounds != 32)
        return CRYPT_INVALID_ROUNDS;
    if (keylen != 16)
        return CRYPT_INVALID_KEYSIZE;
    s_sm4_setkey(&(skey->sm4), key);
    return CRYPT_OK;
}

/*
 * SM4 encryption.
 */
LTC_INLINE static void s_sm4_do(void *output, const void *input, const sm4_u32_t rk[32])
{
    sm4_u32_t Y[4];
    sm4_u32_t X[32+4];

    LOAD32H(X[0], (sm4_u8_t *)input     );
    LOAD32H(X[1], (sm4_u8_t *)input +  4);
    LOAD32H(X[2], (sm4_u8_t *)input +  8);
    LOAD32H(X[3], (sm4_u8_t *)input + 12);

    s_sm4_crypt(Y, X, rk);

    STORE32H(Y[0], (sm4_u8_t *)output     );
    STORE32H(Y[1], (sm4_u8_t *)output +  4);
    STORE32H(Y[2], (sm4_u8_t *)output +  8);
    STORE32H(Y[3], (sm4_u8_t *)output + 12);
}

int sm4_ecb_encrypt(const unsigned char *pt, unsigned char *ct,
                    const symmetric_key *skey)
{
    LTC_ARGCHK(pt   != NULL);
    LTC_ARGCHK(ct   != NULL);
    LTC_ARGCHK(skey != NULL);
    s_sm4_do(ct, pt, skey->sm4.ek);
    return CRYPT_OK;
}
int sm4_ecb_decrypt(const unsigned char *ct, unsigned char *pt,
                    const symmetric_key *skey)
{
    LTC_ARGCHK(pt   != NULL);
    LTC_ARGCHK(ct   != NULL);
    LTC_ARGCHK(skey != NULL);
    s_sm4_do(pt, ct, skey->sm4.dk);
    return CRYPT_OK;
}

void sm4_done(symmetric_key *skey)
{
    LTC_UNUSED_PARAM(skey);
}
int sm4_keysize(int *keysize)
{
    LTC_ARGCHK(keysize != NULL);
    if(*keysize < 16) {
        return CRYPT_INVALID_KEYSIZE;
    }
    *keysize = 16;
    return CRYPT_OK;
}

/*
 * libtomcrypt interface is used
 */

#ifdef LTC_TEST
static int sm4_self_test_ltc(void)
{
    int result;
    int i;
    int keysize;
    symmetric_key skey;

    sm4_u8_t output[16];
    sm4_u8_t plaintext[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    sm4_u8_t key[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    sm4_u8_t ciphertext[] = {
        0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E,
        0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46,
    };
    sm4_u8_t ciphertext_1000000t[] = {
        0x59, 0x52, 0x98, 0xC7, 0xC6, 0xFD, 0x27, 0x1F,
        0x04, 0x02, 0xF8, 0x04, 0xC3, 0x3D, 0x3F, 0x66,
    };

    result = CRYPT_OK;          /* Assume the best */

    sm4_setup(key, sizeof(key), 32, &skey);

    /*A.1 example 1*/
    sm4_ecb_encrypt(plaintext, output, &skey);
    if (compare_testvector(output, 16, ciphertext, 16, "SM4 single encryption", 0) != 0)
        result = CRYPT_ERROR;

    sm4_ecb_decrypt(ciphertext, output, &skey);
    if (compare_testvector(output, 16, plaintext, 16, "SM4 single decryption", 0) != 0)
        result = CRYPT_ERROR;

    /*A.2 example 2*/
    XMEMCPY(output, plaintext, 16);
    for (i = 0; i < 1000000; ++i)
        sm4_ecb_encrypt(output, output, &skey);
    if (compare_testvector(output, 16, ciphertext_1000000t, 16, "SM4 1000000 times encryption", 0) != 0)
        result = CRYPT_ERROR;

    XMEMCPY(output, ciphertext_1000000t, 16);
    for (i = 0; i < 1000000; ++i)
        sm4_ecb_decrypt(output, output, &skey);
    if (compare_testvector(output, 16, plaintext, 16, "SM4 1000000 times encryption", 0) != 0)
        result = CRYPT_ERROR;

    keysize = 128;
    if (sm4_keysize(&keysize) != CRYPT_OK) {
        fprintf(stderr, "Getting the max SM4 keysize failed\n");
        result = CRYPT_ERROR;
    } else if (keysize != 16) {
        fprintf(stderr, "SM4 maximum key size is faulty:\nSHOULD be 16\nIS %d\n", keysize);
        result = CRYPT_ERROR;
    }

    sm4_done(&skey);

    return result;
}
#endif

int sm4_test(void)
{
#ifndef LTC_TEST
    return CRYPT_NOP;
#else
    return sm4_self_test_ltc();
#endif
}

const struct ltc_cipher_descriptor sm4_desc = {
    "sm4",
    28,
    16, 16, 16, 32,        /* min_key_len, max_key_len, block_len, default_rounds */
    &sm4_setup,
    &sm4_ecb_encrypt,
    &sm4_ecb_decrypt,
    &sm4_test,
    &sm4_done,
    &sm4_keysize,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
};

#endif      /*LTC_SM4*/
