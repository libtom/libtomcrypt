/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file omac_process.c
  OMAC1 support, process data, Tom St Denis
*/


#ifdef LTC_OMAC

/**
   Process data through OMAC
   @param omac     The OMAC state
   @param in       The input data to send through OMAC
   @param inlen    The length of the input (octets)
   @return CRYPT_OK if successful
*/
int omac_process(omac_state *omac, const unsigned char *in, unsigned long inlen)
{
   unsigned long n, x;
   int           err;

   LTC_ARGCHK(omac  != NULL);
   LTC_ARGCHK(in    != NULL);

   if ((omac->buflen > (int)sizeof(omac->block)) || (omac->buflen < 0) ||
       (omac->blklen > (int)sizeof(omac->block)) || (omac->buflen > omac->blklen)) {
      return CRYPT_INVALID_ARG;
   }

#ifdef LTC_FAST
   if (omac->buflen == 0 && inlen > (unsigned long)omac->blklen) {
      for (x = 0; x < (inlen - omac->blklen); x += omac->blklen) {
          for (n = 0; n < (unsigned long)omac->blklen; n += sizeof(LTC_FAST_TYPE)) {
              *(LTC_FAST_TYPE_PTR_CAST(&omac->prev[n])) ^= *(LTC_FAST_TYPE_PTR_CAST(&in[n]));
          }
          in += omac->blklen;
          if ((err = ecb_encrypt_block(omac->prev, omac->prev, &omac->key)) != CRYPT_OK) {
             return err;
          }
      }
      inlen -= x;
   }
#endif

   while (inlen != 0) {
       /* ok if the block is full we xor in prev, encrypt and replace prev */
       if (omac->buflen == omac->blklen) {
          for (x = 0; x < (unsigned long)omac->blklen; x++) {
              omac->block[x] ^= omac->prev[x];
          }
          if ((err = ecb_encrypt_block(omac->block, omac->prev, &omac->key)) != CRYPT_OK) {
             return err;
          }
          omac->buflen = 0;
       }

       /* add bytes */
       n = MIN(inlen, (unsigned long)(omac->blklen - omac->buflen));
       XMEMCPY(omac->block + omac->buflen, in, n);
       omac->buflen  += n;
       inlen         -= n;
       in            += n;
   }

   return CRYPT_OK;
}

#endif

