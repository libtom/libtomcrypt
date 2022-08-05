/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file der_encode_integer.c
  ASN.1 DER, encode an integer, Tom St Denis
*/


#ifdef LTC_DER

/* Exports a positive bignum as DER format (upto 2^32 bytes in size) */
/**
  Store a mp_int integer
  @param num      The first mp_int to encode
  @param out      [out] The destination for the DER encoded integers
  @param outlen   [in/out] The max size and resulting size of the DER encoded integers
  @return CRYPT_OK if successful
*/
int der_encode_integer(void *num, unsigned char *out, unsigned long *outlen)
{
   unsigned long tmplen, y, len;
   int           err, leading_zero;

   LTC_ARGCHK(num    != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* find out how big this will be */
   if ((err = der_length_integer(num, &tmplen)) != CRYPT_OK) {
      return err;
   }

   if (*outlen < tmplen) {
      *outlen = tmplen;
      return CRYPT_BUFFER_OVERFLOW;
   }

   if (ltc_mp_cmp_d(num, 0) != LTC_MP_LT) {
      /* we only need a leading zero if the msb of the first byte is one */
      if ((ltc_mp_count_bits(num) & 7) == 0 || ltc_mp_iszero(num) == LTC_MP_YES) {
         leading_zero = 1;
      } else {
         leading_zero = 0;
      }

      /* get length of num in bytes (plus 1 since we force the msbyte to zero) */
      y = ltc_mp_unsigned_bin_size(num) + leading_zero;
   } else {
      leading_zero = 0;
      y            = ltc_mp_count_bits(num);
      y            = y + (8 - (y & 7));
      y            = y >> 3;
      if (((ltc_mp_cnt_lsb(num)+1)==ltc_mp_count_bits(num)) && ((ltc_mp_count_bits(num)&7)==0)) --y;
   }

   /* now store initial data */
   *out++ = 0x02;
   len = *outlen - 1;
   if ((err = der_encode_asn1_length(y, out, &len)) != CRYPT_OK) {
      return err;
   }
   out += len;

   /* now store msbyte of zero if num is non-zero */
   if (leading_zero) {
      *out++ = 0x00;
   }

   /* if it's not zero store it as big endian */
   if (ltc_mp_cmp_d(num, 0) == LTC_MP_GT) {
      /* now store the mpint */
      if ((err = ltc_mp_to_unsigned_bin(num, out)) != CRYPT_OK) {
          return err;
      }
   } else if (ltc_mp_iszero(num) != LTC_MP_YES) {
      void *tmp;

      /* negative */
      if (ltc_mp_init(&tmp) != CRYPT_OK) {
         return CRYPT_MEM;
      }

      /* 2^roundup and subtract */
      y = ltc_mp_count_bits(num);
      y = y + (8 - (y & 7));
      if (((ltc_mp_cnt_lsb(num)+1)==ltc_mp_count_bits(num)) && ((ltc_mp_count_bits(num)&7)==0)) y -= 8;
      if (ltc_mp_2expt(tmp, y) != CRYPT_OK || ltc_mp_add(tmp, num, tmp) != CRYPT_OK) {
         ltc_mp_clear(tmp);
         return CRYPT_MEM;
      }
      if ((err = ltc_mp_to_unsigned_bin(tmp, out)) != CRYPT_OK) {
         ltc_mp_clear(tmp);
         return err;
      }
      ltc_mp_clear(tmp);
   }

   /* we good */
   *outlen = tmplen;
   return CRYPT_OK;
}

#endif
