/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file ctr_encrypt.c
  CTR implementation, encrypt data, Tom St Denis
*/


#ifdef LTC_CTR_MODE

/**
  CTR encrypt software implementation
  @param pt     Plaintext
  @param ct     [out] Ciphertext
  @param len    Length of plaintext (octets)
  @param ctr    CTR state
  @return CRYPT_OK if successful
*/
static int s_ctr_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_CTR *ctr)
{
   int x, err;

   while (len) {
      /* is the pad empty? */
      if (ctr->padlen == ctr->ecb.blocklen) {
         /* increment counter */
         if (ctr->mode == CTR_COUNTER_LITTLE_ENDIAN) {
            /* little-endian */
            for (x = 0; x < ctr->ctrlen; x++) {
               ctr->ctr[x] = (ctr->ctr[x] + (unsigned char)1) & (unsigned char)255;
               if (ctr->ctr[x] != (unsigned char)0) {
                  break;
               }
            }
         } else {
            /* big-endian */
            for (x = ctr->ecb.blocklen-1; x >= ctr->ctrlen; x--) {
               ctr->ctr[x] = (ctr->ctr[x] + (unsigned char)1) & (unsigned char)255;
               if (ctr->ctr[x] != (unsigned char)0) {
                  break;
               }
            }
         }

         /* encrypt it */
         if ((err = ecb_encrypt_block(ctr->ctr, ctr->pad, &ctr->ecb)) != CRYPT_OK) {
            return err;
         }
         ctr->padlen = 0;
      }
#ifdef LTC_FAST
      if ((ctr->padlen == 0) && (len >= (unsigned long)ctr->ecb.blocklen)) {
         for (x = 0; x < ctr->ecb.blocklen; x += sizeof(LTC_FAST_TYPE)) {
            *(LTC_FAST_TYPE_PTR_CAST((unsigned char *)ct + x)) = *(LTC_FAST_TYPE_PTR_CAST((unsigned char *)pt + x)) ^
                                                           *(LTC_FAST_TYPE_PTR_CAST((unsigned char *)ctr->pad + x));
         }
       pt         += ctr->ecb.blocklen;
       ct         += ctr->ecb.blocklen;
       len        -= ctr->ecb.blocklen;
       ctr->padlen = ctr->ecb.blocklen;
       continue;
      }
#endif
      *ct++ = *pt++ ^ ctr->pad[ctr->padlen++];
      --len;
   }
   return CRYPT_OK;
}

/**
  CTR encrypt
  @param pt     Plaintext
  @param ct     [out] Ciphertext
  @param len    Length of plaintext (octets)
  @param ctr    CTR state
  @return CRYPT_OK if successful
*/
int ctr_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_CTR *ctr)
{
   int err, fr;

   LTC_ARGCHK(pt != NULL);
   LTC_ARGCHK(ct != NULL);
   LTC_ARGCHK(ctr != NULL);

   if ((err = cipher_is_valid(ctr->ecb.cipher)) != CRYPT_OK) {
       return err;
   }

   /* is blocklen/padlen valid? */
   if ((ctr->ecb.blocklen < 1) || (ctr->ecb.blocklen > (int)sizeof(ctr->ctr)) ||
       (ctr->padlen   < 0) || (ctr->padlen   > (int)sizeof(ctr->pad))) {
      return CRYPT_INVALID_ARG;
   }

#ifdef LTC_FAST
   if (ctr->ecb.blocklen % sizeof(LTC_FAST_TYPE)) {
      return CRYPT_INVALID_ARG;
   }
#endif

   /* handle acceleration only if pad is empty, accelerator is present and length is >= a block size */
   if ((cipher_descriptor[ctr->ecb.cipher].accel_ctr_encrypt != NULL) && (len >= (unsigned long)ctr->ecb.blocklen)) {
     if (ctr->padlen < ctr->ecb.blocklen) {
       fr = ctr->ecb.blocklen - ctr->padlen;
       if ((err = s_ctr_encrypt(pt, ct, fr, ctr)) != CRYPT_OK) {
          return err;
       }
       pt += fr;
       ct += fr;
       len -= fr;
     }

     if (len >= (unsigned long)ctr->ecb.blocklen) {
       if ((err = cipher_descriptor[ctr->ecb.cipher].accel_ctr_encrypt(pt, ct, len/ctr->ecb.blocklen, ctr->ctr, ctr->mode, &ctr->ecb.key)) != CRYPT_OK) {
          return err;
       }
       pt += (len / ctr->ecb.blocklen) * ctr->ecb.blocklen;
       ct += (len / ctr->ecb.blocklen) * ctr->ecb.blocklen;
       len %= ctr->ecb.blocklen;
     }
   }

   return s_ctr_encrypt(pt, ct, len, ctr);
}

#endif
