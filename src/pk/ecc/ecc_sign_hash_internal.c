/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt_private.h"

#ifdef LTC_MECC

int ecc_sign_hash_internal(const unsigned char *in,  unsigned long inlen,
                           void *r, void *s, prng_state *prng, int wprng,
                           int *recid, const ecc_key *key)
{
   ecc_key       pubkey;
   void          *e, *p, *b;
   int           v = 0;
   int           err, max_iterations = LTC_PK_MAX_RETRIES;
   unsigned long pbits, pbytes, i, shift_right;
   unsigned char ch, buf[MAXBLOCKSIZE];

   LTC_ARGCHK(r      != NULL);
   LTC_ARGCHK(s      != NULL);
   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(key    != NULL);

   /* is this a private key? */
   if (key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* init the bignums */
   if ((err = mp_init_multi(&e, &b, NULL)) != CRYPT_OK) {
      return err;
   }

   /* get the hash and load it as a bignum into 'e' */
   p = key->dp.order;
   pbits = mp_count_bits(p);
   pbytes = (pbits+7) >> 3;
   if (pbits > inlen*8) {
      if ((err = mp_read_unsigned_bin(e, (unsigned char *)in, inlen)) != CRYPT_OK)    { goto errnokey; }
   }
   else if (pbits % 8 == 0) {
      if ((err = mp_read_unsigned_bin(e, (unsigned char *)in, pbytes)) != CRYPT_OK)   { goto errnokey; }
   }
   else {
      shift_right = 8 - pbits % 8;
      for (i=0, ch=0; i<pbytes; i++) {
        buf[i] = ch;
        ch = (in[i] << (8-shift_right));
        buf[i] = buf[i] ^ (in[i] >> shift_right);
      }
      if ((err = mp_read_unsigned_bin(e, (unsigned char *)buf, pbytes)) != CRYPT_OK)  { goto errnokey; }
   }

   /* make up a key and export the public copy */
   do {
      if ((err = ecc_copy_curve(key, &pubkey)) != CRYPT_OK)                { goto errnokey; }
      if ((err = ecc_generate_key(prng, wprng, &pubkey)) != CRYPT_OK)      { goto errnokey; }

      /* find r = x1 mod n */
      if ((err = mp_mod(pubkey.pubkey.x, p, r)) != CRYPT_OK)               { goto error; }

      if (recid) {
         /* find recovery ID (if needed) */
         v = 0;
         if (mp_copy(pubkey.pubkey.x, s) != CRYPT_OK)                      { goto error; }
         while (mp_cmp_d(s, 0) == LTC_MP_GT && mp_cmp(s, p) != LTC_MP_LT) {
            /* Compute x1 div n... this will almost never be reached for curves with order 1 */
            v += 2;
            if ((err = mp_sub(s, p, s)) != CRYPT_OK)                       { goto error; }
         }
         if (mp_isodd(pubkey.pubkey.y)) v += 1;
      }

      if (mp_iszero(r) == LTC_MP_YES) {
         ecc_free(&pubkey);
      } else {
         if ((err = rand_bn_upto(b, p, prng, wprng)) != CRYPT_OK)          { goto error; } /* b = blinding value */
         /* find s = (e + xr)/k */
         if ((err = mp_mulmod(pubkey.k, b, p, pubkey.k)) != CRYPT_OK)      { goto error; } /* k = kb */
         if ((err = mp_invmod(pubkey.k, p, pubkey.k)) != CRYPT_OK)         { goto error; } /* k = 1/kb */
         if ((err = mp_mulmod(key->k, r, p, s)) != CRYPT_OK)               { goto error; } /* s = xr */
         if ((err = mp_mulmod(pubkey.k, s, p, s)) != CRYPT_OK)             { goto error; } /* s = xr/kb */
         if ((err = mp_mulmod(pubkey.k, e, p, e)) != CRYPT_OK)             { goto error; } /* e = e/kb */
         if ((err = mp_add(e, s, s)) != CRYPT_OK)                          { goto error; } /* s = e/kb + xr/kb */
         if ((err = mp_mulmod(s, b, p, s)) != CRYPT_OK)                    { goto error; } /* s = b(e/kb + xr/kb) = (e + xr)/k */
         ecc_free(&pubkey);
         if (mp_iszero(s) == LTC_MP_NO) {
            break;
         }
      }
   } while (--max_iterations > 0);

   if (max_iterations == 0) {
      goto errnokey;
   }

   if (recid) *recid = v;

   goto errnokey;
error:
   ecc_free(&pubkey);
errnokey:
   mp_clear_multi(e, b, NULL);
   return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
