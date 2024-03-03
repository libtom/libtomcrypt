/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file der_length_sequence.c
  ASN.1 DER, length a SEQUENCE, Tom St Denis
*/

#ifdef LTC_DER

/**
   Get the length of a DER sequence
   @param list   The sequences of items in the SEQUENCE
   @param inlen  The number of items
   @param outlen [out] The length required in octets to store it
   @return CRYPT_OK on success
*/

int der_flexi_sequence_cmp(const ltc_asn1_list *flexi, der_flexi_check *check)
{
   ltc_asn1_list *cur;
   if (flexi->type != LTC_ASN1_SEQUENCE) {
      return CRYPT_INVALID_PACKET;
   }
   cur = flexi->child;
   while(check->t != LTC_ASN1_EOL) {
      if (!LTC_ASN1_IS_TYPE(cur, check->t)) {
         return CRYPT_INVALID_PACKET;
      }
      if (check->pp != NULL) *check->pp = cur;
      cur = cur->next;
      check++;
   }
   return CRYPT_OK;
}

#endif
