/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file cfb_decrypt.c
  CFB implementation, decrypt data, Tom St Denis
*/

#ifdef LTC_CFB_MODE

static LTC_INLINE void s_shift1left_64(unsigned char *b, unsigned char v)
{
   ulong64 bval;
   LOAD64H(bval, b);
   bval <<= 1;
   bval |= v & 0x01u;
   STORE64H(bval, b);
}

static LTC_INLINE void s_shift1left_128(unsigned char *b, unsigned char v)
{
   ulong64 bval[2];
   LOAD64H(bval[0], b);
   LOAD64H(bval[1], b + 8);
   bval[0] <<= 1;
   bval[0] |= (bval[1] >> 63) & 0x01u;
   bval[1] <<= 1;
   bval[1] |= v & 0x01u;
   STORE64H(bval[0], b);
   STORE64H(bval[1], b + 8);
}

/**
   CFB decrypt
   @param ct      Ciphertext
   @param pt      [out] Plaintext
   @param len     Length of ciphertext (octets)
   @param cfb     CFB state
   @return CRYPT_OK if successful
*/
int cfb_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_CFB *cfb)
{
   int err;
   ulong64 bitlen = len * 8, bits_per_round;
   unsigned int cur_bit = 0;
   unsigned char pt_ = 0, ct_ = 0;

   LTC_ARGCHK(pt != NULL);
   LTC_ARGCHK(ct != NULL);
   LTC_ARGCHK(cfb != NULL);

   if (bitlen < len) {
      return CRYPT_OVERFLOW;
   }

   if ((err = cipher_is_valid(cfb->cipher)) != CRYPT_OK) {
       return err;
   }

   /* is blocklen/padlen valid? */
   if (cfb->blocklen < 0 || cfb->blocklen > (int)sizeof(cfb->IV) ||
       cfb->padlen   < 0 || cfb->padlen   > (int)sizeof(cfb->pad)) {
      return CRYPT_INVALID_ARG;
   }

   bits_per_round = cfb->width == 1 ? 1 : 8;

   while (bitlen > 0) {
       if (cfb->padlen == cfb->blocklen) {
          if ((err = cipher_descriptor[cfb->cipher].ecb_encrypt(cfb->pad, cfb->IV, &cfb->key)) != CRYPT_OK) {
             return err;
          }
          cfb->padlen = 0;
       }
       switch (cfb->width) {
         case 1:
            if (cur_bit++ % 8 == 0) {
               ct_ = *ct++;
               pt_ = 0;
            } else {
               ct_ <<= 1;
               pt_ <<= 1;
            }
            if (cfb->blocklen == 16)
               s_shift1left_128(cfb->pad, ct_ >> 7);
            else
               s_shift1left_64(cfb->pad, ct_ >> 7);
            pt_ |= ((ct_ ^ cfb->IV[0]) >> 7) & 0x01u;
            cfb->padlen = cfb->blocklen;
            if (cur_bit % 8 == 0) {
               *pt++ = pt_;
               cur_bit = 0;
            }
            break;
         case 8:
            XMEMMOVE(cfb->pad, cfb->pad + 1, cfb->blocklen - 1);
            cfb->pad[cfb->blocklen - 1] = *ct;
            *pt++ = *ct++ ^ cfb->IV[0];
            cfb->padlen = cfb->blocklen;
            break;
         case 64:
         case 128:
            cfb->pad[cfb->padlen] = *ct;
            *pt++ = *ct++ ^ cfb->IV[cfb->padlen];
            ++(cfb->padlen);
            break;
         default:
            return CRYPT_INVALID_ARG;
      }
      bitlen -= bits_per_round;
   }
   return CRYPT_OK;
}

#endif

