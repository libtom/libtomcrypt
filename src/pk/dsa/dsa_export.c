/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */
#include "tomcrypt.h"

/**
   @file dsa_export.c
   DSA implementation, export key, Tom St Denis
*/

#ifdef LTC_MDSA

/**
  Export a DSA key to a binary packet
  @param out    [out] Where to store the packet
  @param outlen [in/out] The max size and resulting size of the packet
  @param type   The type of key to export (PK_PRIVATE or PK_PUBLIC)
  @param key    The key to export
  @return CRYPT_OK if successful
*/
int dsa_export(unsigned char *out, unsigned long *outlen, int type, dsa_key *key)
{
   unsigned char flags[1];
   unsigned long zero=0;
   int err;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   /* can we store the static header?  */
   if (type == PK_PRIVATE && key->type != PK_PRIVATE) {
      return CRYPT_PK_TYPE_MISMATCH;
   }

   if (type != PK_PUBLIC && type != PK_PRIVATE) {
      return CRYPT_INVALID_ARG;
   }

   /* This encoding is different from the one in original
    * libtomcrypt. It uses a compatible encoding with gnutls
    * and openssl
    */

   if (type == PK_PRIVATE) {
      return der_encode_sequence_multi(out, outlen,
                                 LTC_ASN1_SHORT_INTEGER, 1UL, &zero,
                                 LTC_ASN1_INTEGER,      1UL, key->p,
                                 LTC_ASN1_INTEGER,      1UL, key->q,
                                 LTC_ASN1_INTEGER,      1UL, key->g,
                                 LTC_ASN1_INTEGER,      1UL, key->y,
                                 LTC_ASN1_INTEGER,      1UL, key->x,
                                 LTC_ASN1_EOL,          0UL, NULL);
   } else {
      unsigned long tmplen = (mp_count_bits(key->y)/8)+8;
      unsigned char* tmp = XMALLOC(tmplen);
      ltc_asn1_list int_list[3];

      if (tmp == NULL) {
	   return CRYPT_MEM;
      }

      err = der_encode_integer(key->y, tmp, &tmplen);
      if (err != CRYPT_OK) {
		  goto error;
      }

      int_list[0].data = key->p;
      int_list[0].size = 1UL;
      int_list[0].type = LTC_ASN1_INTEGER;
      int_list[1].data = key->q;
      int_list[1].size = 1UL;
      int_list[1].type = LTC_ASN1_INTEGER;
      int_list[2].data = key->g;
      int_list[2].size = 1UL;
      int_list[2].type = LTC_ASN1_INTEGER;

      err = der_encode_subject_public_key_info(out, outlen,
        PKA_DSA, tmp, tmplen,
        LTC_ASN1_SEQUENCE, int_list, sizeof(int_list)/sizeof(int_list[0]));

error:
      XFREE(tmp);
      return err;
   }
}

#endif


/* $Source$ */
/* $Revision$ */
/* $Date$ */
