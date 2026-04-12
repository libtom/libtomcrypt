/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file pqc_export_privkey.c
  Encode an ML-KEM or ML-DSA private key as a OneAsymmetricKey (PKCS#8) structure
*/

#if (defined(LTC_MLKEM) || defined(LTC_MLDSA)) && defined(LTC_DER)

/**
   INTERNAL ONLY, declared in tomcrypt_private.h

   Encode a PKCS#8 OneAsymmetricKey holding the RFC 9881/RFC 9935 private-key CHOICE.

   The arguments select which alternative is written:
     seed only     -> seed [0] OCTET STRING
     key only      -> expandedKey OCTET STRING
     seed and key  -> both SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING }

   @param out      [out] Destination for the DER
   @param outlen   [in/out] Max size and resulting size of the DER
   @param oid_id   The OID of the parameter set
   @param seed     The generation seed, or NULL to omit it
   @param seedlen  Length of the seed
   @param sk       The expanded private key, or NULL to omit it
   @param sklen    Length of the expanded private key
   @return CRYPT_OK if successful
*/
int pqc_export_privkey(unsigned char *out, unsigned long *outlen,
                       enum ltc_oid_id oid_id,
                       const unsigned char *seed, unsigned long seedlen,
                       const unsigned char *sk,   unsigned long sklen)
{
   const char *OID;
   unsigned long version, oid[16], oidlen, inner_len, alloc_len;
   unsigned char *inner;
   ltc_asn1_list alg_id[1], choice[2];
   int err;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(seed   != NULL || sk != NULL);

   if ((err = pk_get_oid(oid_id, &OID)) != CRYPT_OK) {
      return err;
   }
   oidlen = LTC_ARRAY_SIZE(oid);
   if ((err = pk_oid_str_to_num(OID, oid, &oidlen)) != CRYPT_OK) {
      return err;
   }
   LTC_SET_ASN1(alg_id, 0, LTC_ASN1_OBJECT_IDENTIFIER, oid, oidlen);

   if (seed != NULL && sk != NULL) {
      LTC_SET_ASN1(choice, 0, LTC_ASN1_OCTET_STRING, seed, seedlen);
      LTC_SET_ASN1(choice, 1, LTC_ASN1_OCTET_STRING, sk,   sklen);
      err = der_length_sequence(choice, 2, &inner_len);
   } else if (seed != NULL) {
      LTC_SET_ASN1_CUSTOM_PRIMITIVE(choice, 0, LTC_ASN1_CL_CONTEXT_SPECIFIC, 0,
                                    LTC_ASN1_OCTET_STRING, seed, seedlen);
      err = der_length_custom_type(choice, &inner_len, NULL);
   } else {
      err = der_length_octet_string(sklen, &inner_len);
   }
   if (err != CRYPT_OK) {
      return err;
   }

   alloc_len = inner_len;
   inner = XMALLOC(alloc_len);
   if (inner == NULL) {
      return CRYPT_MEM;
   }

   if (seed != NULL && sk != NULL) {
      err = der_encode_sequence(choice, 2, inner, &inner_len);
   } else if (seed != NULL) {
      err = der_encode_custom_type(choice, inner, &inner_len);
   } else {
      err = der_encode_octet_string(sk, sklen, inner, &inner_len);
   }

   if (err == CRYPT_OK) {
      version = 0;
      err = der_encode_sequence_multi(out, outlen,
                                      LTC_ASN1_SHORT_INTEGER, 1uL, &version,
                                      LTC_ASN1_SEQUENCE,      1uL, alg_id,
                                      LTC_ASN1_OCTET_STRING,  inner_len, inner,
                                      LTC_ASN1_EOL,           0uL, NULL);
   }

   zeromem(inner, alloc_len);
   XFREE(inner);
   return err;
}

#endif
