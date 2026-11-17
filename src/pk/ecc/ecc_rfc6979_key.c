/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

/**
  @file ecc_rfc6979_key.c
  ECC Crypto, Russ Williams
*/

#ifdef LTC_MECC
#ifdef LTC_SHA256

/**
  Make deterministic ECC key using the RFC6979 method
  @param priv         [in] Private key for HMAC
  @param in           Message to sign for HMAC
  @param inlen        Length of the message
  @param key          [out] Newly created deterministic key
  @return CRYPT_OK if successful, upon error all allocated memory will be freed
*/
int ecc_rfc6979_key(const ecc_key *priv, const unsigned char *in, unsigned long inlen, const char *rfc6979_hash_alg, ecc_key *key)
{
   int            err, hash = -1;
   unsigned char  v[MAXBLOCKSIZE], k[MAXBLOCKSIZE];
   unsigned char  buffer[256], sep[1], privkey[128];
   unsigned long  order_bits, len_diff, pk_len, zero_extend, outlen, klen, vlen, buflen, qlen, hashsize;
   void *r, *d;

   LTC_ARGCHK(ltc_mp.name != NULL);
   LTC_ARGCHK(priv        != NULL);
   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(key->dp.size > 0);

   if (rfc6979_hash_alg == NULL) {
      return CRYPT_INVALID_ARG;
   }
   hash = find_hash(rfc6979_hash_alg);
   if ((err = hash_is_valid(hash)) != CRYPT_OK) {
      return err;
   }

   hashsize = hash_descriptor[hash].hashsize;

   if ((err = ltc_mp_init_multi(&r, &d, NULL)) != CRYPT_OK) {
      return err;
   }

   /* Length, in bytes, of key */
   order_bits = ltc_mp_count_bits(key->dp.order);
   qlen = (order_bits+7) >> 3;
   len_diff = qlen > inlen ? qlen - inlen : 0;
   pk_len = (ltc_mp_count_bits(priv->k)+7) >> 3;
   zero_extend = qlen - pk_len;
   XMEMSET(buffer, 0x00, len_diff + zero_extend);

   /* RFC6979 3.2b, set V */
   XMEMSET(v, 0x01, hashsize);

   /* RFC6979 3.2c, set K */
   XMEMSET(k, 0x00, hashsize);

   if ((err = ltc_mp_to_unsigned_bin(priv->k, privkey) != CRYPT_OK))                                     { goto error; }
   /* RFC6979 3.2d, set K to HMAC_K(V::0x00::priv::in) */
   sep[0] = 0;
   klen = sizeof(k);
   if((err = hmac_memory_multi(hash,
                               k, hashsize,
                               k, &klen,
                               v, hashsize,
                               sep, 1uL,
                               buffer, zero_extend,
                               privkey, qlen - zero_extend,
                               buffer, len_diff,
                               in, qlen - len_diff,
                               LTC_NULL)) != CRYPT_OK)                                                   { goto error; }

   /* RFC6979 3.2e, set V = HMAC_K(V) */
   vlen = sizeof(v);
   if((err = hmac_memory(hash, k, klen, v, hashsize, v, &vlen)) != CRYPT_OK)                             { goto error; }

   /* RFC6979 3.2f, set K to HMAC_K(V::0x01::priv::in) */
   sep[0] = 0x01;
   outlen = sizeof(k);
   if((err = hmac_memory_multi(hash,
                               k, klen,
                               k, &klen,
                               v, hashsize,
                               sep, 1uL,
                               buffer, zero_extend,
                               privkey, qlen - zero_extend,
                               buffer, len_diff,
                               in, qlen - len_diff,
                               LTC_NULL)) != CRYPT_OK)                                                   { goto error; }

   /* RFC6979 3.2g, set V = HMAC_K(V) */
   outlen = sizeof(v);
   if((err = hmac_memory(hash, k, klen, v, hashsize, v, &outlen)) != CRYPT_OK)                           { goto error; }

   /* RFC6979 3.2h, generate and check key */
   do {
      /* concatenate hash bits into T */
      buflen = 0;
      while (buflen < qlen) {
         if (buflen + hashsize >= sizeof(buffer) || buflen + hashsize < buflen) {
            err = CRYPT_BUFFER_OVERFLOW;
            goto error;
         }
         outlen = sizeof(v);
         if((err = hmac_memory(hash, k, klen, v, hashsize, v, &outlen)) != CRYPT_OK)                     { goto error; }
         XMEMCPY(&buffer[buflen], v, hashsize);
         buflen += hashsize;
      }

      /* key->k = bits2int(T) */
      if ((err = ltc_mp_read_unsigned_bin(r, buffer, qlen)) != CRYPT_OK)                                 { goto error; }
      if ((qlen * 8) > order_bits) {
         if ((err = ltc_mp_2expt(d, (qlen * 8) - order_bits)) != CRYPT_OK)                               { goto error; }
         if ((err = ltc_mp_div(r, d, r, NULL)) != CRYPT_OK)                                              { goto error; }
         if ((err = ltc_mp_to_unsigned_bin(r, buffer)) != CRYPT_OK)                                      { goto error; }
         qlen = ltc_mp_unsigned_bin_size(r);
      }

      if ((err = ecc_set_key(buffer, qlen, PK_PRIVATE, key))!= CRYPT_OK)                                 { goto error; }

      /* check that k is in range [1,q-1] */
      if (ltc_mp_cmp_d(key->k, 0) == LTC_MP_GT && ltc_mp_cmp(key->k, key->dp.order) == LTC_MP_LT) {
         /* Check that pubkey.x != 0 (mod p) */
         if ((err = ltc_mp_mod(key->pubkey.x, key->dp.order, r)) != CRYPT_OK)                            { goto error; }

         /* if we have a valid key, exit loop */
         if (ltc_mp_iszero(r) == LTC_MP_NO)
            break;
      } else {
         /* K = HMAC_K(V::0x00) */
         buffer[0] = 0x0;
         outlen = sizeof(k);
         if((err = hmac_memory_multi(hash, k, klen, k, &klen, v, hashsize, buffer, 1uL, LTC_NULL)) != CRYPT_OK)  { goto error; }

         /* V = HMAC_K(V) */
         outlen = sizeof(v);
         if((err = hmac_memory(hash, k, klen, v, hashsize, v, &outlen)) != CRYPT_OK)                           { goto error; }

         /* ... and try again! */
      }
   } while (1);

   key->type = PK_PRIVATE;

   /* success */
   err = CRYPT_OK;
   goto cleanup;

error:
   ecc_free(key);
cleanup:
   ltc_mp_cleanup_multi(&d, &r, NULL);
   return err;
}

#endif
#endif
