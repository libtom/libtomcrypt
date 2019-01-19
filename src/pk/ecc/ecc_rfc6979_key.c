/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

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
int ecc_rfc6979_key(const ecc_key *priv, const unsigned char *in, int inlen, ecc_key *key)
{
   int            err, hash, i;
   unsigned char  v[32], k[32], digest[32]; /* No way to determine hash so always use SHA256 */
   unsigned char  buffer[256];
   unsigned long  outlen, buflen, qlen;

   LTC_ARGCHK(ltc_mp.name != NULL);
   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(key->dp.size > 0);

   hash = find_hash("sha256");
   if (hash == -1) {err = CRYPT_ERROR; goto error;}

   /* Length, in bytes, of key */
   i = mp_count_bits(key->dp.order);
   qlen = (i+7) >> 3;

   /* RFC6979 3.2b, set V */
   for (i=0; i<32; i++) v[i] = 0x01;

   /* RFC6979 3.2c, set K */
   for (i=0; i<32; i++) k[i] = 0x00;

   /* RFC6979 3.2d, set K to HMAC_K(V::0x00::priv::in) */
   XMEMCPY(&buffer[0], v, 32);
   buffer[32] = 0x00;
   if ((err = mp_to_unsigned_bin(priv->k, &buffer[33]) != CRYPT_OK))                                   { goto error; }
   XMEMCPY(&buffer[33+qlen], in, inlen);
   buflen = 32 + 1 + qlen + inlen;
   outlen = sizeof(digest);
   if((err = hmac_memory(hash, k, 32, buffer, buflen, digest, &outlen)) != CRYPT_OK)                   { goto error; }
   XMEMCPY(k, digest, 32);

   /* RFC6979 3.2e, set V = HMAC_K(V) */
   outlen = sizeof(digest);
   if((err = hmac_memory(hash, k, 32, v, 32, digest, &outlen)) != CRYPT_OK)                            { goto error; }
   XMEMCPY(v, digest, 32);

   /* RFC6979 3.2f, set K to HMAC_K(V::0x01::priv::in) */
   XMEMCPY(&buffer[0], v, 32);
   buffer[32] = 0x01;
   if ((err = mp_to_unsigned_bin(priv->k, &buffer[33]) != CRYPT_OK))                                   { goto error; }
   XMEMCPY(&buffer[33+qlen], in, inlen);
   buflen = 32 + 1 + qlen + inlen;
   outlen = sizeof(digest);
   if((err = hmac_memory(hash, k, 32, buffer, buflen, digest, &outlen)) != CRYPT_OK)                   { goto error; }
   XMEMCPY(k, digest, 32);

   /* RFC6979 3.2g, set V = HMAC_K(V) */
   outlen = sizeof(digest);
   if((err = hmac_memory(hash, k, 32, v, 32, digest, &outlen)) != CRYPT_OK)                            { goto error; }
   XMEMCPY(v, digest, 32);

   /* RFC6979 3.2h, generate and check key */
   do {
      /* concatenate hash bits into T */
      buflen = 0;
      while (buflen < qlen) {
         outlen = sizeof(digest);
         if((err = hmac_memory(hash, k, 32, v, 32, digest, &outlen)) != CRYPT_OK)                      { goto error; }
         XMEMCPY(v, digest, 32);
         XMEMCPY(&buffer[buflen], v, 32);
         buflen += 32;
      }

      /* key->k = bits2int(T) */
      if ((err = mp_read_unsigned_bin(key->k, (unsigned char *)buffer, qlen)) != CRYPT_OK)             { goto error; }

      /* make the public key */
      if ((err = ltc_mp.ecc_ptmul(key->k, &key->dp.base, &key->pubkey, key->dp.A, key->dp.prime, 1)) != CRYPT_OK) {
         goto error;
      }

      /* check that k is in range [1,q-1] */
      if (mp_cmp_d(key->k, 0) == LTC_MP_GT && mp_cmp(key->k, key->dp.order) == LTC_MP_LT) {
         /* TODO: Check that pubkey.x != 0 (mod p) */

         /* if we have a valid key, exit loop */
         break;
      } else {
         /* K = HMAC_K(V::0x00) */
         XMEMCPY(&buffer[0], v, 32);
         buffer[32] = 0x00;
         buflen = 32 + 1;
         outlen = sizeof(digest);
         if((err = hmac_memory(hash, k, 32, buffer, buflen, digest, &outlen)) != CRYPT_OK)             { goto error; }
         XMEMCPY(k, digest, 32);

         /* V = HMAC_K(V) */
         outlen = sizeof(digest);
         if((err = hmac_memory(hash, k, 32, v, 32, digest, &outlen)) != CRYPT_OK)                      { goto error; }
         XMEMCPY(v, digest, 32);

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
   return err;
}

#endif
#endif
/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */

