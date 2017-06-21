/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

/**
  @file ecc_import.c
  ECC Crypto, Tom St Denis
*/

#ifdef LTC_MECC

/**
  Import an ECC key from a binary packet
  @param in      The packet to import
  @param inlen   The length of the packet
  @param key     [out] The destination of the import
  @return CRYPT_OK if successful, upon error all allocated memory will be freed
*/
int ecc_import(const unsigned char *in, unsigned long inlen, ecc_key *key)
{
   return ecc_import_ex(in, inlen, key, NULL);
}

/**
  Import an ECC key from a binary packet, using user supplied domain params rather than one of the NIST ones
  @param in      The packet to import
  @param inlen   The length of the packet
  @param key     [out] The destination of the import
  @param dp      pointer to user supplied params; must be the same as the params used when exporting
  @return CRYPT_OK if successful, upon error all allocated memory will be freed
*/
int ecc_import_ex(const unsigned char *in, unsigned long inlen, ecc_key *key, const ltc_ecc_set_type *dp)
{
   unsigned long key_size;
   unsigned char flags[1];
   int           err;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   /* init key */
   if (mp_init_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k, NULL) != CRYPT_OK) {
      return CRYPT_MEM;
   }

   /* find out what type of key it is */
   if ((err = der_decode_sequence_multi(in, inlen,
                                  LTC_ASN1_BIT_STRING, 1UL, flags,
                                  LTC_ASN1_EOL,        0UL, NULL)) != CRYPT_OK) {
      goto done;
   }


   if (flags[0] == 1) {
      /* private key */
      key->type = PK_PRIVATE;
      if ((err = der_decode_sequence_multi(in, inlen,
                                     LTC_ASN1_BIT_STRING,      1UL, flags,
                                     LTC_ASN1_SHORT_INTEGER,   1UL, &key_size,
                                     LTC_ASN1_INTEGER,         1UL, key->pubkey.x,
                                     LTC_ASN1_INTEGER,         1UL, key->pubkey.y,
                                     LTC_ASN1_INTEGER,         1UL, key->k,
                                     LTC_ASN1_EOL,             0UL, NULL)) != CRYPT_OK) {
         goto done;
      }
   } else {
      /* public key */
      key->type = PK_PUBLIC;
      if ((err = der_decode_sequence_multi(in, inlen,
                                     LTC_ASN1_BIT_STRING,      1UL, flags,
                                     LTC_ASN1_SHORT_INTEGER,   1UL, &key_size,
                                     LTC_ASN1_INTEGER,         1UL, key->pubkey.x,
                                     LTC_ASN1_INTEGER,         1UL, key->pubkey.y,
                                     LTC_ASN1_EOL,             0UL, NULL)) != CRYPT_OK) {
         goto done;
      }
   }

   if (dp == NULL) {
     /* BEWARE: Here we are looking up the curve params by keysize (neither curve name nor curve oid),
      *         which might be ambiguous (there can more than one curve for given keysize).
      *         Thus the chosen curve depends on order of items in ltc_ecc_sets[] - see ecc.c file.
      */
     /* find the idx */
     for (key->idx = 0; ltc_ecc_sets[key->idx].size && (unsigned long)ltc_ecc_sets[key->idx].size != key_size; ++key->idx);
     if (ltc_ecc_sets[key->idx].size == 0) {
       err = CRYPT_INVALID_PACKET;
       goto done;
     }
     key->dp = &ltc_ecc_sets[key->idx];
   } else {
     key->idx = -1;
     key->dp = dp;
   }
   /* set z */
   if ((err = mp_set(key->pubkey.z, 1)) != CRYPT_OK) { goto done; }

   /* is it a point on the curve?  */
   if ((err = ltc_ecc_is_point(key->dp, key->pubkey.x, key->pubkey.y)) != CRYPT_OK) {
      goto done;
   }

   /* we're good */
   return CRYPT_OK;
done:
   mp_clear_multi(key->pubkey.x, key->pubkey.y, key->pubkey.z, key->k, NULL);
   return err;
}
#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
