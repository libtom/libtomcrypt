/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@iahu.ca, http://libtomcrypt.org
 */
#include "tomcrypt.h"

/**
   @file cbc_encrypt.c
   CBC implementation, encrypt block, Tom St Denis
*/


#ifdef CBC

/**
  CBC encrypt
  @param pt     Plaintext
  @param ct     [out] Ciphertext
  @param cbc    CBC state
  @return CRYPT_OK if successful
*/
int cbc_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_CBC *cbc)
{
   int x, err;
   unsigned char tmp[MAXBLOCKSIZE];

   LTC_ARGCHK(pt != NULL);
   LTC_ARGCHK(ct != NULL);
   LTC_ARGCHK(cbc != NULL);

   if ((err = cipher_is_valid(cbc->cipher)) != CRYPT_OK) {
       return err;
   }
   
   /* is blocklen valid? */
   if (cbc->blocklen < 0 || cbc->blocklen > (int)sizeof(cbc->IV)) {
      return CRYPT_INVALID_ARG;
   }    

   /* xor IV against plaintext */
   for (x = 0; x < cbc->blocklen; x++) {
       tmp[x] = pt[x] ^ cbc->IV[x];
   }

   /* encrypt */
   cipher_descriptor[cbc->cipher].ecb_encrypt(tmp, ct, &cbc->key);

   /* store IV [ciphertext] for a future block */
   for (x = 0; x < cbc->blocklen; x++) {
       cbc->IV[x] = ct[x];
   }

   #ifdef LTC_CLEAN_STACK
      zeromem(tmp, sizeof(tmp));
   #endif
   return CRYPT_OK;
}

#endif
