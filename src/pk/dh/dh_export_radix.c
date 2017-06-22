/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

#ifdef LTC_MDH

static unsigned long _count_digits(int radix, void *num)
{
   void *r, *t;
   unsigned long digits = 0;

   if (mp_iszero(num) == LTC_MP_YES) return 1;
   if (mp_init_multi(&t, &r, NULL) != CRYPT_OK) return 0;
   mp_copy(num, t);
   mp_set_int(r, radix);
   while (mp_iszero(t) == LTC_MP_NO) {
      if (mp_div(t, r, t, NULL) != CRYPT_OK) {
         mp_clear_multi(t, r, NULL);
         return 0;
      }
      digits++;
   }
   mp_clear_multi(t, r, NULL);
   return digits;
}

/**
  Export a DH key to a binary packet
  @param out    [out] The destination for the key
  @param outlen [in/out] The max size and resulting size of the DH key
  @param type   Which type of key (PK_PRIVATE or PK_PUBLIC)
  @param key    The key you wish to export
  @return CRYPT_OK if successful
*/
int dh_export_radix(int radix, void *out, unsigned long *outlen, int type, dh_key *key)
{
   unsigned long len;
   void *k;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);
   LTC_ARGCHK((radix >= 2 && radix <= 64) || radix == 256);

   k = (type == PK_PRIVATE) ? key->x : key->y;
   len = (radix == 256) ? mp_unsigned_bin_size(k) : _count_digits(radix, k) + 1;

   if (*outlen < len) {
      *outlen = len;
      return CRYPT_BUFFER_OVERFLOW;
   }
   *outlen = len;

   return (radix == 256) ? mp_to_unsigned_bin(k, out) : mp_toradix(k, out, radix);
}

#endif /* LTC_MDH */

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
