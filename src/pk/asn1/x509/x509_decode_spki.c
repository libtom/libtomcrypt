/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file x509_decode_public_key_from_certificate.c
  ASN.1 DER/X.509, decode a SubjectPublicKeyInfo
*/

#ifdef LTC_DER

/* Check if it looks like a SubjectPublicKeyInfo */
#define LOOKS_LIKE_SPKI(l) ((l) != NULL)              \
&& ((l)->type == LTC_ASN1_SEQUENCE)                   \
&& ((l)->child != NULL)                               \
&& ((l)->child->type == LTC_ASN1_OBJECT_IDENTIFIER)   \
&& ((l)->next != NULL)                                \
&& ((l)->next->type == LTC_ASN1_BIT_STRING)

/**
  DER decode a X.509 certificate and return the SubjectPublicKeyInfo
   @param in               The input buffer
   @param inlen            The length of the input buffer
   @param out              [out] A pointer to the decoded linked list (you take ownership of this one and
                                 `der_free_sequence_flexi()` it when you're done)
   @param spki             [out] A pointer to the SubjectPublicKeyInfo
   @return CRYPT_OK on success, CRYPT_NOP if no SubjectPublicKeyInfo was found, another error if decoding failed
*/
int x509_decode_spki(const unsigned char *in, unsigned long inlen, ltc_asn1_list **out, ltc_asn1_list **spki)
{
   int err;
   unsigned long tmp_inlen;
   ltc_asn1_list *decoded_list = NULL, *l;

   LTC_ARGCHK(in       != NULL);
   LTC_ARGCHK(inlen    != 0);

   tmp_inlen = inlen;
   if ((err = der_decode_sequence_flexi(in, &tmp_inlen, &decoded_list)) == CRYPT_OK) {
      l = decoded_list;

      err = CRYPT_NOP;

      /* Move 2 levels up in the tree
         SEQUENCE
             SEQUENCE
                 ...
       */
      if ((l->type == LTC_ASN1_SEQUENCE) && (l->child != NULL)) {
         l = l->child;
         if ((l->type == LTC_ASN1_SEQUENCE) && (l->child != NULL)) {
            l = l->child;

            /* Move forward in the tree until we find this combination
                 ...
                 SEQUENCE
                     SEQUENCE
                         OBJECT IDENTIFIER <some PKA OID, e.g. 1.2.840.113549.1.1.1>
                         NULL
                     BIT STRING
             */
            do {
               /* The additional check for l->data is there to make sure
                * we won't try to decode a list that has been 'shrunk'
                */
               if ((l->type == LTC_ASN1_SEQUENCE)
                     && (l->data != NULL)
                     && LOOKS_LIKE_SPKI(l->child)) {
                  *out = decoded_list;
                  *spki = l;
                  return CRYPT_OK;
               }
               l = l->next;
            } while(l);
         }
      }
   }
   if (decoded_list) der_free_sequence_flexi(decoded_list);
   return err;
}

#endif
