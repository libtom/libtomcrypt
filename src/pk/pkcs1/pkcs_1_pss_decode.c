/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file pkcs_1_pss_decode.c
  PKCS #1 PSS Signature Padding, Tom St Denis
*/

#ifdef LTC_MRSA

/**
   PKCS #1 v2.00 Signature Verification
   @param  msghash         The hash to verify
   @param  msghashlen      The length of the hash (octets)
   @param  sig             The signature data (encoded data)
   @param  siglen          The length of the signature data (octets)
   @param  params          The PKCS#1 operation's parameters
   @param  modulus_bitlen  The bit length of the RSA modulus
   @param  res             [out] The result of the comparison, 1==valid, 0==invalid
   @return CRYPT_OK if successful (even if the comparison failed)
*/
int ltc_pkcs_1_pss_decode_mgf1(const unsigned char *msghash, unsigned long  msghashlen,
                               const unsigned char *sig,     unsigned long  siglen,
                               ltc_rsa_op_parameters *params,
                                     unsigned long  modulus_bitlen,    int *res)
{
   unsigned char *DB, *mask, *hash;
   unsigned long x, y, hLen, modulus_len, saltlen;
   int           err;
   hash_state    md;
   ltc_rsa_op_checked op_checked = ltc_pkcs1_op_checked_init(params);

   /* res is cleared before anything else can return, it stays 0 unless the signature is good */
   LTC_ARGCHK(res     != NULL);
   *res = 0;

   LTC_ARGCHK(msghash != NULL);
   LTC_ARGCHK(sig     != NULL);
   LTC_ARGCHK(params  != NULL);

   if ((err = rsa_key_valid_op(LTC_PKCS1_VERIFY, &op_checked)) != CRYPT_OK) {
      return err;
   }

   hLen        = hash_descriptor[op_checked.hash_alg].hashsize;
   saltlen     = params->params.saltlen;
   modulus_bitlen--;
   modulus_len = (modulus_bitlen>>3) + (modulus_bitlen & 7 ? 1 : 0);

   /* check sizes */
   if ((saltlen > modulus_len) ||
       (modulus_len < hLen + saltlen + 2) ||
       (siglen != modulus_len)) {
      return CRYPT_PK_INVALID_SIZE;
   }

   /* allocate ram for DB/mask/hash of size modulus_len */
   DB   = XMALLOC(modulus_len);
   mask = XMALLOC(modulus_len);
   hash = XMALLOC(modulus_len);
   if (DB == NULL || mask == NULL || hash == NULL) {
      if (DB != NULL) {
         XFREE(DB);
      }
      if (mask != NULL) {
         XFREE(mask);
      }
      if (hash != NULL) {
         XFREE(hash);
      }
      return CRYPT_MEM;
   }

   /* ensure the 0xBC byte */
   if (sig[siglen-1] != 0xBC) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   }

   /* copy out the DB */
   x = 0;
   XMEMCPY(DB, sig + x, modulus_len - hLen - 1);
   x += modulus_len - hLen - 1;

   /* copy out the hash */
   XMEMCPY(hash, sig + x, hLen);
   /* x += hLen; */

   /* check the MSB */
   if ((sig[0] & ~(0xFF >> ((modulus_len<<3) - (modulus_bitlen)))) != 0) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   }

   /* generate mask of length modulus_len - hLen - 1 from hash */
   if ((err = ltc_pkcs_1_mgf1(op_checked.mgf1_hash_alg, hash, hLen, mask, modulus_len - hLen - 1)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* xor against DB */
   for (y = 0; y < (modulus_len - hLen - 1); y++) {
      DB[y] ^= mask[y];
   }

   /* now clear the first byte [make sure smaller than modulus] */
   DB[0] &= 0xFF >> ((modulus_len<<3) - (modulus_bitlen));

   /* DB = PS || 0x01 || salt, PS == modulus_len - saltlen - hLen - 2 zero bytes */

   /* check for zeroes and 0x01 */
   for (x = 0; x < modulus_len - saltlen - hLen - 2; x++) {
       if (DB[x] != 0x00) {
          err = CRYPT_INVALID_PACKET;
          goto LBL_ERR;
       }
   }

   /* check for the 0x01 */
   if (DB[x++] != 0x01) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   }

   /* M = (eight) 0x00 || msghash || salt, mask = H(M) */
   if ((err = hash_descriptor[op_checked.hash_alg].init(&md)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   zeromem(mask, 8);
   if ((err = hash_descriptor[op_checked.hash_alg].process(&md, mask, 8)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   if ((err = hash_descriptor[op_checked.hash_alg].process(&md, msghash, msghashlen)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   if ((err = hash_descriptor[op_checked.hash_alg].process(&md, DB+x, saltlen)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   if ((err = hash_descriptor[op_checked.hash_alg].done(&md, mask)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* mask == hash means valid signature */
   if (XMEM_NEQ(mask, hash, hLen) == 0) {
      *res = 1;
   }

   err = CRYPT_OK;
LBL_ERR:
#ifdef LTC_CLEAN_STACK
   zeromem(DB,   modulus_len);
   zeromem(mask, modulus_len);
   zeromem(hash, modulus_len);
#endif

   XFREE(hash);
   XFREE(mask);
   XFREE(DB);

   return err;
}

#endif /* LTC_MRSA */
