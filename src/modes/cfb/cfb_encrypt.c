/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file cfb_encrypt.c
  CFB implementation, encrypt data, Tom St Denis
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
  CFB encrypt
  @param pt     Plaintext
  @param ct     [out] Ciphertext
  @param len    Length of plaintext (octets)
  @param cfb    CFB state
  @return CRYPT_OK if successful
*/
int cfb_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_CFB *cfb)
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
               pt_ = *pt++;
               ct_ = 0;
            } else {
               pt_ <<= 1;
               ct_ <<= 1;
            }
            ct_ |= ((pt_ ^ cfb->IV[0]) >> 7) & 0x01u;
            if (cfb->blocklen == 16)
               s_shift1left_128(cfb->pad, ct_);
            else
               s_shift1left_64(cfb->pad, ct_);
            cfb->padlen = cfb->blocklen;
            if (cur_bit % 8 == 0) {
               *ct++ = ct_;
               cur_bit = 0;
            }
            break;
         case 8:
            XMEMMOVE(cfb->pad, cfb->pad + 1, cfb->blocklen - 1);
            cfb->pad[cfb->blocklen - 1] = (*ct = *pt ^ cfb->IV[0]);
            ++pt;
            ++ct;
            cfb->padlen = cfb->blocklen;
            break;
         case 64:
         case 128:
             cfb->pad[cfb->padlen] = (*ct = *pt ^ cfb->IV[cfb->padlen]);
             ++pt;
             ++ct;
             ++(cfb->padlen);
            break;
      }
      bitlen -= bits_per_round;
   }
   return CRYPT_OK;
}

#endif
