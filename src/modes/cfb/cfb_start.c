/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file cfb_start.c
   CFB implementation, start chain, Tom St Denis
*/


#ifdef LTC_CFB_MODE


/**
   Extended initialization of a CFB context
   @param cipher      The index of the cipher desired
   @param IV          The initialization vector
   @param key         The secret key
   @param keylen      The length of the secret key (octets)
   @param num_rounds  Number of rounds in the cipher desired (0 for default)
   @param width       The width of the mode in bits (0 for default)
   @param cfb         The CFB state to initialize
   @return CRYPT_OK if successful
*/
int cfb_start_ex(int cipher, const unsigned char *IV, const unsigned char *key,
                 int keylen, int num_rounds, int width, symmetric_CFB *cfb)
{
   int x, err;

   LTC_ARGCHK(IV != NULL);
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(cfb != NULL);

   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }

   switch (width) {
      case 0:
         width = cipher_descriptor[cipher].block_length * 8;
         break;
      case 1:
      case 8:
         LTC_ARGCHK(cipher_descriptor[cipher].block_length == 8
                    || cipher_descriptor[cipher].block_length == 16);
         break;
      case 64:
      case 128:
         LTC_ARGCHK(width == cipher_descriptor[cipher].block_length * 8);
         break;
      default:
         return CRYPT_INVALID_ARG;
   }


   /* copy data */
   cfb->cipher = cipher;
   cfb->width = width;
   cfb->blocklen = cipher_descriptor[cipher].block_length;
   for (x = 0; x < cfb->blocklen; x++) {
       cfb->pad[x] = IV[x];
   }

   /* init the cipher */
   if ((err = cipher_descriptor[cipher].setup(key, keylen, num_rounds, &cfb->key)) != CRYPT_OK) {
      return err;
   }

   /* encrypt the IV */
   cfb->padlen = 0;
   return cipher_descriptor[cfb->cipher].ecb_encrypt(cfb->pad, cfb->IV, &cfb->key);
}

/**
   Initialize a CFB context
   @param cipher      The index of the cipher desired
   @param IV          The initialization vector
   @param key         The secret key
   @param keylen      The length of the secret key (octets)
   @param num_rounds  Number of rounds in the cipher desired (0 for default)
   @param cfb         The CFB state to initialize
   @return CRYPT_OK if successful
*/
int cfb_start(int cipher, const unsigned char *IV, const unsigned char *key,
              int keylen, int num_rounds, symmetric_CFB *cfb)
{
   return cfb_start_ex(cipher, IV, key, keylen, num_rounds, 0, cfb);
}

#endif
