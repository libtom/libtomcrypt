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
   @file pmac_process.c
   PMAC implementation, process data, by Tom St Denis 
*/


#ifdef PMAC

/**
  Process data in a PMAC stream
  @param pmac     The PMAC state
  @param in       The data to send through PMAC
  @param inlen    The length of the data to send through PMAC
  @return CRYPT_OK if successful
*/
int pmac_process(pmac_state *pmac, const unsigned char *in, unsigned long inlen)
{
   int err, n, x;
   unsigned char Z[MAXBLOCKSIZE];

   LTC_ARGCHK(pmac != NULL);
   LTC_ARGCHK(in   != NULL);
   if ((err = cipher_is_valid(pmac->cipher_idx)) != CRYPT_OK) {
      return err;
   }

   if ((pmac->buflen > (int)sizeof(pmac->block)) || (pmac->buflen < 0) ||
       (pmac->block_len > (int)sizeof(pmac->block)) || (pmac->buflen > pmac->block_len)) {
      return CRYPT_INVALID_ARG;
   }

   while (inlen != 0) { 
       /* ok if the block is full we xor in prev, encrypt and replace prev */
       if (pmac->buflen == pmac->block_len) {
          pmac_shift_xor(pmac);
          for (x = 0; x < pmac->block_len; x++) {
              Z[x] = pmac->Li[x] ^ pmac->block[x];
          }
          cipher_descriptor[pmac->cipher_idx].ecb_encrypt(Z, Z, &pmac->key);
          for (x = 0; x < pmac->block_len; x++) {
              pmac->checksum[x] ^= Z[x];
          }
          pmac->buflen = 0;
       }

       /* add bytes */
       n = MIN(inlen, (unsigned long)(pmac->block_len - pmac->buflen));
       XMEMCPY(pmac->block + pmac->buflen, in, n);
       pmac->buflen  += n;
       inlen         -= n;
       in            += n;
   }

#ifdef LTC_CLEAN_STACK
   zeromem(Z, sizeof(Z));
#endif

   return CRYPT_OK;
}

#endif
