/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_MECC

int ecc_sign_hash_internal(const unsigned char *in,  unsigned long inlen,
                           void *r, void *s, ltc_ecc_sig_opts *opts, const ecc_key *key)
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
   LTC_ARGCHK(opts   != NULL);
   LTC_ARGCHK(key    != NULL);

   /* is this a private key? */
   if (key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* init the bignums */
   if ((err = ltc_mp_init_multi(&e, &b, LTC_NULL)) != CRYPT_OK) {
      return err;
   }

   /* get the hash and load it as a bignum into 'e' */
   p = key->dp.order;
   pbits = ltc_mp_count_bits(p);
   pbytes = (pbits+7) >> 3;
   if (pbits > inlen*8) {
      if ((err = ltc_mp_read_unsigned_bin(e, (unsigned char *)in, inlen)) != CRYPT_OK)    { goto errnokey; }
   }
   else if (pbits % 8 == 0) {
      if ((err = ltc_mp_read_unsigned_bin(e, (unsigned char *)in, pbytes)) != CRYPT_OK)   { goto errnokey; }
   }
   else {
      if (pbytes >= MAXBLOCKSIZE) {
         err = CRYPT_BUFFER_OVERFLOW;
         goto errnokey;
      }
      shift_right = 8 - pbits % 8;
      for (i=0, ch=0; i<pbytes; i++) {
        buf[i] = ch;
        ch = (in[i] << (8-shift_right));
        buf[i] = buf[i] ^ (in[i] >> shift_right);
      }
      if ((err = ltc_mp_read_unsigned_bin(e, (unsigned char *)buf, pbytes)) != CRYPT_OK)  { goto errnokey; }
   }

   /* make up a key and export the public copy */
   do {
      if ((err = ecc_copy_curve(key, &pubkey)) != CRYPT_OK)                    { goto errnokey; }
      if (opts->rfc6979_hash_alg != NULL) {
         if ((err = ecc_rfc6979_key(key, in, inlen, opts->rfc6979_hash_alg, &pubkey)) != CRYPT_OK)     { goto errnokey; }
      } else {
         if ((err = ecc_generate_key(opts->prng, opts->wprng, &pubkey)) != CRYPT_OK)       { goto errnokey; }
      }

      /* find r = x1 mod n */
      if ((err = ltc_mp_mod(pubkey.pubkey.x, p, r)) != CRYPT_OK)               { goto error; }

      if (opts->enable_recovery_id) {
         /* find recovery ID (if needed) */
         v = 0;
         if ((err = ltc_mp_copy(pubkey.pubkey.x, s)) != CRYPT_OK)              { goto error; }
         while (ltc_mp_cmp_d(s, 0) == LTC_MP_GT && ltc_mp_cmp(s, p) != LTC_MP_LT) {
            /* Compute x1 div n... this will almost never be reached for curves with order 1 */
            v += 2;
            if ((err = ltc_mp_sub(s, p, s)) != CRYPT_OK)                       { goto error; }
         }
         if (ltc_mp_isodd(pubkey.pubkey.y)) v += 1;
      }

      if (ltc_mp_iszero(r) == LTC_MP_YES) {
         ecc_free(&pubkey);
      } else {
         if ((err = rand_bn_upto(b, p, opts->prng, opts->wprng)) != CRYPT_OK)              { goto error; } /* b = blinding value */
         /* find s = (e + xr)/k */
         if ((err = ltc_mp_mulmod(pubkey.k, b, p, pubkey.k)) != CRYPT_OK)      { goto error; } /* k = kb */
         if ((err = ltc_mp_invmod(pubkey.k, p, pubkey.k)) != CRYPT_OK)         { goto error; } /* k = 1/kb */
         if ((err = ltc_mp_mulmod(key->k, r, p, s)) != CRYPT_OK)               { goto error; } /* s = xr */
         if ((err = ltc_mp_mulmod(pubkey.k, s, p, s)) != CRYPT_OK)             { goto error; } /* s = xr/kb */
         if ((err = ltc_mp_mulmod(pubkey.k, e, p, e)) != CRYPT_OK)             { goto error; } /* e = e/kb */
         if ((err = ltc_mp_add(e, s, s)) != CRYPT_OK)                          { goto error; } /* s = e/kb + xr/kb */
         if ((err = ltc_mp_mulmod(s, b, p, s)) != CRYPT_OK)                    { goto error; } /* s = b(e/kb + xr/kb) = (e + xr)/k */
         ecc_free(&pubkey);
         if (ltc_mp_iszero(s) == LTC_MP_NO) {
            break;
         }
      }
   } while (--max_iterations > 0);

   if (max_iterations == 0) {
      err = CRYPT_ERROR;
      goto errnokey;
   }

   if (opts->enable_recovery_id) opts->recovery_id = v;

   goto errnokey;
error:
   ecc_free(&pubkey);
errnokey:
   ltc_mp_deinit_multi(e, b, LTC_NULL);
   return err;
}

#endif
