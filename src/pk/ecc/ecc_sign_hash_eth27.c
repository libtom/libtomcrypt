/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_MECC

/**
  Sign a message digest (Ethereum format with recovery_id+27)
  @param in        The message digest to sign
  @param inlen     The length of the digest
  @param out       [out] The destination for the signature
  @param outlen    [in/out] The max size and resulting size of the signature
  @param prng      An active PRNG state
  @param wprng     The index of the PRNG you wish to use
  @param key       A private ECC key
  @return CRYPT_OK if successful
*/
int ecc_sign_hash_eth27(const unsigned char *in,  unsigned long inlen,
                        unsigned char *out, unsigned long *outlen,
                        prng_state *prng, int wprng, const ecc_key *key)
{
   int err, recid;
   void *r, *s;
   unsigned long i;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   /* Only valid for secp256k1 - OID 1.3.132.0.10 */
   if (pk_oid_cmp_with_ulong("1.3.132.0.10", key->dp.oid, key->dp.oidlen) != CRYPT_OK) {
      return CRYPT_ERROR;
   }
   if (*outlen < 65) {
      *outlen = 65;
      return CRYPT_BUFFER_OVERFLOW;
   }

   if ((err = mp_init_multi(&r, &s, NULL)) != CRYPT_OK) return err;
   if ((err = ecc_sign_hash_internal(in, inlen, r, s, prng, wprng, &recid, key)) != CRYPT_OK) goto error;

   zeromem(out, 65);
   *outlen = 65;
   i = mp_unsigned_bin_size(r);
   if ((err = mp_to_unsigned_bin(r, out + 32 - i)) != CRYPT_OK) goto error;
   i = mp_unsigned_bin_size(s);
   if ((err = mp_to_unsigned_bin(s, out + 64 - i)) != CRYPT_OK) goto error;
   out[64] = (unsigned char)(recid + 27); /* Recovery ID is 27/28 for Ethereum */
   err = CRYPT_OK;

error:
   mp_clear_multi(r, s, NULL);
   return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
