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
  @file ecb_encrypt.c
  ECB implementation, encrypt a block, Tom St Denis
*/

#ifdef ECB

/**
  ECB encrypt
  @param pt     Plaintext
  @param ct     [out] Ciphertext
  @param ecb    ECB state
  @return CRYPT_OK if successful
*/
int ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_ECB *ecb)
{
   int err;
   LTC_ARGCHK(pt != NULL);
   LTC_ARGCHK(ct != NULL);
   LTC_ARGCHK(ecb != NULL);

   if ((err = cipher_is_valid(ecb->cipher)) != CRYPT_OK) {
       return err;
   }
   cipher_descriptor[ecb->cipher].ecb_encrypt(pt, ct, &ecb->key);
   return CRYPT_OK;
}

#endif
