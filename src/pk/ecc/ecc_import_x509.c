/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

#ifdef LTC_MECC

/**
  Import an ECC key from a X.509 certificate
  @param in      The packet to import from
  @param inlen   It's length (octets)
  @param key     [out] Destination for newly imported key
  @return CRYPT_OK if successful, upon error allocated memory is freed
*/
int ecc_import_x509(const unsigned char *in, unsigned long inlen, ecc_key *key)
{
   int           err;
   unsigned long len;
   ltc_asn1_list *decoded_list = NULL, *l;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);

   len = inlen;
   if ((err = der_decode_sequence_flexi(in, &len, &decoded_list)) == CRYPT_OK) {
      err = CRYPT_ERROR;
      l = decoded_list;
      if (l->type == LTC_ASN1_SEQUENCE &&
          l->child && l->child->type == LTC_ASN1_SEQUENCE) {
         l = l->child->child;
         while (l) {
            if (l->type == LTC_ASN1_SEQUENCE && l->data &&
                l->child && l->child->type == LTC_ASN1_SEQUENCE &&
                l->child->child && l->child->child->type == LTC_ASN1_OBJECT_IDENTIFIER &&
                l->child->next && l->child->next->type == LTC_ASN1_BIT_STRING) {
               err = ecc_import_openssl(l->data, l->size, key);
               goto LBL_DONE;
            }
            l = l->next;
         }
      }
   }

LBL_DONE:
   if (decoded_list) der_free_sequence_flexi(decoded_list);
   return err;
}

#endif /* LTC_MECC */


/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
