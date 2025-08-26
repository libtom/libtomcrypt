/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file x509_decode_public_key_from_certificate.c
  ASN.1 DER/X.509, decode a certificate
*/

#ifdef LTC_DER

/**
  Process the public key from the SubjectPublicKeyInfo of a X.509 certificate
   @param in               The input buffer
   @param inlen            The length of the input buffer
   @param algorithm        One out of the enum #public_key_algorithms
   @param param_type       The parameters' type out of the enum ltc_asn1_type
   @param parameters       The parameters to include
   @param parameters_len   [in/out] The number of parameters to include
   @param callback         The callback
   @param ctx              The context passed to the callback
   @return CRYPT_OK on success
*/
int x509_process_public_key_from_spki(const unsigned char *in, unsigned long inlen,
                                      enum ltc_oid_id algorithm, ltc_asn1_type param_type,
                                      ltc_asn1_list* parameters, unsigned long *parameters_len,
                                      public_key_decode_cb callback, void *ctx)
{
   int err;
   unsigned char *tmpbuf = NULL;
   unsigned long tmpbuf_len;

   LTC_ARGCHK(in        != NULL);
   LTC_ARGCHK(callback  != NULL);

   if (algorithm == LTC_OID_EC) {
      err = callback(in, inlen, ctx);
   } else {

      tmpbuf_len = inlen;
      tmpbuf = XCALLOC(1, tmpbuf_len);
      if (tmpbuf == NULL) {
          return CRYPT_MEM;
      }

      err = x509_decode_subject_public_key_info(in, inlen,
                                                algorithm, tmpbuf, &tmpbuf_len,
                                                param_type, parameters, parameters_len);
      if (err == CRYPT_OK) {
         err = callback(tmpbuf, tmpbuf_len, ctx);
      }
   }

   if (tmpbuf != NULL) XFREE(tmpbuf);

   return err;
}

/**
  Try to decode the public key from a X.509 certificate
   @param in               The input buffer
   @param inlen            The length of the input buffer
   @param algorithm        One out of the enum #public_key_algorithms
   @param param_type       The parameters' type out of the enum ltc_asn1_type
   @param parameters       The parameters to include
   @param parameters_len   [in/out] The number of parameters to include
   @param callback         The callback
   @param ctx              The context passed to the callback
   @return CRYPT_OK on success,
            CRYPT_NOP if no SubjectPublicKeyInfo was found,
            another error if decoding or memory allocation failed
*/
int x509_decode_public_key_from_certificate(const unsigned char *in, unsigned long inlen,
                                            enum ltc_oid_id algorithm, ltc_asn1_type param_type,
                                            ltc_asn1_list* parameters, unsigned long *parameters_len,
                                            public_key_decode_cb callback, void *ctx)
{
   int err;
   ltc_asn1_list *decoded_list;
   const ltc_asn1_list *spki;

   LTC_ARGCHK(in       != NULL);
   LTC_ARGCHK(inlen    != 0);
   LTC_ARGCHK(callback != NULL);

   if ((err = x509_decode_spki(in, inlen, &decoded_list, &spki)) != CRYPT_OK) {
      return err;
   }

   err = x509_process_public_key_from_spki(spki->data, spki->size,
                                           algorithm, param_type,
                                           parameters, parameters_len,
                                           callback, ctx);

   if (decoded_list) der_free_sequence_flexi(decoded_list);

   return err;
}

#endif
