
/**
  @file sm4.c
  Implementation of SMS4
*/

#include "tomcrypt.h"
#include "sms4_lcl.h"

#ifdef LTC_SM4

const struct ltc_cipher_descriptor sm4_desc =
{
    "sm4",  /* name */
    24,     /* ID */
    SMS4_KEY_LENGTH,     /* min_key_length */
    SMS4_KEY_LENGTH,     /* max_key_length */
    SMS4_BLOCK_SIZE,     /* block_length */
    SMS4_NUM_ROUNDS,     /* default_rounds */
    sm4_setup, sm4_ecb_encrypt, sm4_ecb_decrypt, sm4_test, sm4_done, sm4_keysize,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

 /**
    Initialize the SMS4 block cipher
    @param key The symmetric key you wish to pass
    @param keylen The key length in bytes
    @param num_rounds The number of rounds desired (0 for default)
    @param skey The key in as scheduled by this function.
    @return CRYPT_OK if successful
 */
int sm4_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
    LTC_UNUSED_PARAM(num_rounds);

    LTC_ARGCHK(key  != NULL);
    LTC_ARGCHK(skey != NULL);

    if (keylen != 16) {
        return CRYPT_INVALID_KEYSIZE;
    }

    sms4_set_encrypt_key(&(skey->sm4), key);
    sms4_set_decrypt_key(&(skey->sm4), key);

    return CRYPT_OK;
}

/**
  Encrypts a block of text with SMS4
  @param pt The input plaintext (16 bytes)
  @param ct The output ciphertext (16 bytes)
  @param skey The key as scheduled
  @return CRYPT_OK if successful
*/
int sm4_ecb_encrypt(const unsigned char *pt, unsigned char *ct, const symmetric_key *skey)
{
	sms4_encrypt(pt, ct, &(skey->sm4));

    return CRYPT_OK;
}

/**
  Decrypts a block of text with SMS4
  @param ct The input ciphertext (16 bytes)
  @param pt The output plaintext (16 bytes)
  @param skey The key as scheduled
  @return CRYPT_OK if successful
*/
int sm4_ecb_decrypt(const unsigned char *ct, unsigned char *pt, const symmetric_key *skey)
{
    sms4_decrypt(ct, pt, &(skey->sm4));

    return CRYPT_OK;
}

/**
  Performs a self-test of the SMS4 block cipher
  @return CRYPT_OK if functional, CRYPT_NOP if self-test has been disabled
*/
int sm4_test(void)
{
#ifndef LTC_TEST
    return CRYPT_NOP;
#else
    int err;
    static const struct {
        int keylen;
        unsigned char key[32], pt[16], ct[16];
    } tests[] = {
        { 16,
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
        { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
        { 0x74, 0xc0, 0x46, 0x04, 0x81, 0x61, 0xbb, 0xf3,
            0xd4, 0xce, 0xff, 0x33, 0xd3, 0xf4, 0x29, 0xbe }
        }
    };

    symmetric_key key;
    unsigned char tmp[2][16];
    int i, y;

    for (i = 0; i < (int)(sizeof(tests)/sizeof(tests[0])); i++) {
        zeromem(&key, sizeof(key));
        if ((err = sm4_setup(tests[i].key, tests[i].keylen, 0, &key)) != CRYPT_OK) {
            return err;
        }

        sm4_ecb_encrypt(tests[i].pt, tmp[0], &key);
        sm4_ecb_decrypt(tmp[0], tmp[1], &key);
        if (compare_testvector(tmp[0], 16, tests[i].ct, 16, "SM4 Encrypt", i) ||
            compare_testvector(tmp[1], 16, tests[i].pt, 16, "SM4 Decrypt", i)) {
            return CRYPT_FAIL_TESTVECTOR;
        }

        /* now see if we can encrypt all zero bytes 1000 times, decrypt and come back where we started */
        for (y = 0; y < 16; y++) tmp[0][y] = 0;
        for (y = 0; y < 1000; y++) sm4_ecb_encrypt(tmp[0], tmp[0], &key);
        for (y = 0; y < 1000; y++) sm4_ecb_decrypt(tmp[0], tmp[0], &key);
        for (y = 0; y < 16; y++) if (tmp[0][y] != 0) return CRYPT_FAIL_TESTVECTOR;
    }
    return CRYPT_OK;
#endif
}

/** Terminate the context
   @param skey    The scheduled key
*/
void sm4_done(symmetric_key *skey)
{
    LTC_UNUSED_PARAM(skey);
}

/**
  Gets suitable key size
  @param keysize [in/out] The length of the recommended key (in bytes).  This function will store the suitable size back in this variable.
  @return CRYPT_OK if the input key size is acceptable.
*/
int sm4_keysize(int *keysize)
{
    LTC_ARGCHK(keysize != NULL);

    *keysize = SMS4_KEY_LENGTH;

    return CRYPT_OK;
}

#endif  /* LTC_SM4 */
