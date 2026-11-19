/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file pkcs8_encode.c
  PKCS#8, encode a PrivateKeyInfo structure
*/

#ifdef LTC_PKCS_8

/**
   Encode a PrivateKeyInfo

   PrivateKeyInfo ::= SEQUENCE {
      version              INTEGER,
      privateKeyAlgorithm  AlgorithmIdentifier,
      privateKey           OCTET STRING }

   @param out              [out] The destination of the DER encoded PrivateKeyInfo
   @param outlen           [in/out] The max size and resulting size of the output
   @param algorithm        The OID of the key algorithm
   @param parameters_type  The ASN.1 type of the algorithm parameters, LTC_ASN1_EOL leaves them out
   @param parameters       The algorithm parameters
   @param parameters_len   The number of parameters
   @param private_key      The encoded private key, its format depends on the algorithm
   @param private_key_len  The length of the private key
   @return CRYPT_OK on success
*/
int pkcs8_encode(unsigned char *out, unsigned long *outlen, enum ltc_oid_id algorithm,
                 ltc_asn1_type parameters_type, const void *parameters, unsigned long parameters_len,
                 const unsigned char *private_key, unsigned long private_key_len)
{
   int err;
   ltc_asn1_list alg_id[2];
   const char *OID;
   unsigned long oid[16], oidlen, version = 0;

   LTC_ARGCHK(out         != NULL);
   LTC_ARGCHK(outlen      != NULL);
   LTC_ARGCHK(private_key != NULL);

   if ((err = pk_get_oid(algorithm, &OID)) != CRYPT_OK) {
      return err;
   }
   oidlen = LTC_ARRAY_SIZE(oid);
   if ((err = pk_oid_str_to_num(OID, oid, &oidlen)) != CRYPT_OK) {
      return err;
   }

   LTC_SET_ASN1(alg_id, 0, LTC_ASN1_OBJECT_IDENTIFIER, oid,        oidlen);
   LTC_SET_ASN1(alg_id, 1, parameters_type,            parameters, parameters_len);

   return der_encode_sequence_multi(out, outlen,
                                    LTC_ASN1_SHORT_INTEGER, 1UL,             &version,
                                    LTC_ASN1_SEQUENCE,      2UL,             alg_id,
                                    LTC_ASN1_OCTET_STRING,  private_key_len, private_key,
                                    LTC_ASN1_EOL,           0UL,             NULL);
}

#endif
