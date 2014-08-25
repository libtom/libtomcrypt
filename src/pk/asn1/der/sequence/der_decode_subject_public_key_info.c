/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 */
#include "tomcrypt.h"
/**
  @file der_encode_sequence_multi.c
  ASN.1 DER, encode a Subject Public Key structure --nmav
*/

#ifdef LTC_DER

/* AlgorithmIdentifier := SEQUENCE {
 *    algorithm OBJECT IDENTIFIER,
 *    parameters ANY DEFINED BY algorithm
 * }
 *
 * SubjectPublicKeyInfo := SEQUENCE {
 *    algorithm AlgorithmIdentifier,
 *    subjectPublicKey BIT STRING
 * }
 */
/**
  Encode a SEQUENCE type using a VA list
  @param out    [out] Destination for data
  @param outlen [in/out] Length of buffer and resulting length of output
  @remark <...> is of the form <type, size, data> (int, unsigned long, void*)
  @return CRYPT_OK on success
*/
int der_decode_subject_public_key_info(const unsigned char *in, unsigned long inlen,
        unsigned int algorithm, void* public_key, unsigned long* public_key_len,
        unsigned long parameters_type, ltc_asn1_list* parameters, unsigned long parameters_len)
{
   int err;
   unsigned long len;
   oid_st oid;
   unsigned char *tmpbuf;
   unsigned long  tmpoid[16];
   ltc_asn1_list alg_id[2];
   ltc_asn1_list subject_pubkey[2];

   LTC_ARGCHK(in    != NULL);
   LTC_ARGCHK(inlen != 0);
   LTC_ARGCHK(public_key_len != NULL);

   err = pk_get_oid(algorithm, &oid);
   if (err != CRYPT_OK) {
        return err;
   }

   /* see if the OpenSSL DER format RSA public key will work */
   tmpbuf = XCALLOC(1, MAX_RSA_SIZE*8);
   if (tmpbuf == NULL) {
       err = CRYPT_MEM;
       goto LBL_ERR;
   }

   /* this includes the internal hash ID and optional params (NULL in this case) */
   LTC_SET_ASN1(alg_id, 0, LTC_ASN1_OBJECT_IDENTIFIER, tmpoid, sizeof(tmpoid)/sizeof(tmpoid[0]));
   LTC_SET_ASN1(alg_id, 1, parameters_type, parameters, parameters_len);

   /* the actual format of the SSL DER key is odd, it stores a RSAPublicKey
    * in a **BIT** string ... so we have to extract it then proceed to convert bit to octet
    */
   LTC_SET_ASN1(subject_pubkey, 0, LTC_ASN1_SEQUENCE, alg_id, 2);
   LTC_SET_ASN1(subject_pubkey, 1, LTC_ASN1_RAW_BIT_STRING, tmpbuf, MAX_RSA_SIZE*8);

   err=der_decode_sequence(in, inlen, subject_pubkey, 2UL);
   if (err != CRYPT_OK) {
           goto LBL_ERR;
   }

   if ((alg_id[0].size != oid.OIDlen) ||
       memcmp(oid.OID, alg_id[0].data, oid.OIDlen * sizeof(oid.OID[0]))) {
        /* OID mismatch */
        err = CRYPT_PK_INVALID_TYPE;
        goto LBL_ERR;
   }

   len = subject_pubkey[1].size/8;
   if (*public_key_len > len) {
       memcpy(public_key, subject_pubkey[1].data, len);
       *public_key_len = len;
    } else {
        *public_key_len = len;
        err = CRYPT_BUFFER_OVERFLOW;
        goto LBL_ERR;
    }

    err = CRYPT_OK;

LBL_ERR:

    XFREE(tmpbuf);

    return err;
}

#endif
