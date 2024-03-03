/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

#ifdef LTC_MECC

static int s_ecc_import_x509_with_oid(const unsigned char *in, unsigned long inlen, ecc_key *key)
{
   unsigned char bin_xy[2*ECC_MAXSIZE+2];
   unsigned long curveoid[16];
   unsigned long len_xy, len_oid;
   int err;

   len_xy = sizeof(bin_xy);
   len_oid = 16;
   err = x509_decode_subject_public_key_info(in, inlen, LTC_OID_EC, bin_xy, &len_xy,
                                             LTC_ASN1_OBJECT_IDENTIFIER, (void *)curveoid, &len_oid);
   if (err != CRYPT_OK) { goto error; }
   err = ecc_import_with_oid(bin_xy, len_xy, curveoid, len_oid, PK_PUBLIC, key);
error:
   return err;
}

int ecc_import_subject_public_key_info(const unsigned char *in, unsigned long inlen, ecc_key *key)
{
   int err;

   if ((err = s_ecc_import_x509_with_oid(in, inlen, key)) == CRYPT_OK) {
      goto success;
   }

   err = ecc_import_with_curve(in, inlen, PK_PUBLIC, key);

success:
   return err;
}

/**
  Import an ECC key from a X.509 certificate
  @param in      The packet to import from
  @param inlen   It's length (octets)
  @param key     [out] Destination for newly imported key
  @return CRYPT_OK if successful, upon error allocated memory is freed
*/
int ecc_import_x509(const unsigned char *in, unsigned long inlen, ecc_key *key)
{
   return x509_decode_public_key_from_certificate(in, inlen,
                                                  LTC_OID_EC,
                                                  LTC_ASN1_EOL, NULL, NULL,
                                                  (public_key_decode_cb)ecc_import_subject_public_key_info, key);
}

#endif /* LTC_MECC */

