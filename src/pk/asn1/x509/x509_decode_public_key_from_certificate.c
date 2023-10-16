/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file x509_decode_public_key_from_certificate.c
  ASN.1 DER/X.509, decode a certificate
*/

#ifdef LTC_DER

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
   unsigned char *tmpbuf = NULL;
   unsigned long tmpbuf_len;
   ltc_asn1_list *decoded_list = NULL, *spki;

   LTC_ARGCHK(in       != NULL);
   LTC_ARGCHK(inlen    != 0);
   LTC_ARGCHK(callback != NULL);

   if ((err = x509_decode_spki(in, inlen, &decoded_list, &spki)) != CRYPT_OK) {
      return err;
   }

   if (algorithm == LTC_OID_EC) {
      err = callback(spki->data, spki->size, ctx);
   } else {

      tmpbuf_len = inlen;
      tmpbuf = XCALLOC(1, tmpbuf_len);
      if (tmpbuf == NULL) {
          err = CRYPT_MEM;
          goto LBL_OUT;
      }

      err = x509_decode_subject_public_key_info(spki->data, spki->size,
                                                algorithm, tmpbuf, &tmpbuf_len,
                                                param_type, parameters, parameters_len);
      if (err == CRYPT_OK) {
         err = callback(tmpbuf, tmpbuf_len, ctx);
         goto LBL_OUT;
      }
   }

LBL_OUT:
   if (decoded_list) der_free_sequence_flexi(decoded_list);
   if (tmpbuf != NULL) XFREE(tmpbuf);

   return err;
}

#endif
