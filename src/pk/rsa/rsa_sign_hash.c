/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file rsa_sign_hash.c
  RSA PKCS #1 v1.5 and v2 PSS sign hash, Tom St Denis and Andreas Lange
*/

#ifdef LTC_MRSA
/**
  PKCS #1 pad then sign
  @param hash      The hash to sign
  @param hashlen   The length of the hash to sign (octets)
  @param sig       [out] The signature
  @param siglen    [in/out] The max size and resulting size of the signature
  @param params    The RSA operation parameters
  @param key       The private RSA key to use
  @return CRYPT_OK if successful
*/
int rsa_sign_hash_v2(const unsigned char   *hash,   unsigned long  hashlen,
                           unsigned char   *sig,    unsigned long *siglen,
                     ltc_rsa_op_parameters *params,
                     const rsa_key         *key)
{
   unsigned long modulus_bitlen, modulus_bytelen, x;
   int           err;
   ltc_rsa_op_checked op_checked = ltc_rsa_op_checked_init(key, params);

   LTC_ARGCHK(hash     != NULL);
   LTC_ARGCHK(sig      != NULL);
   LTC_ARGCHK(siglen   != NULL);
   LTC_ARGCHK(key      != NULL);

   if ((err = rsa_key_valid_op(LTC_RSA_SIGN, &op_checked)) != CRYPT_OK) {
     return err;
   }

   /* get modulus len in bits */
   modulus_bitlen = ltc_mp_count_bits(key->N);

  /* siglen must be at least the size of the modulus */
  modulus_bytelen = ltc_mp_unsigned_bin_size(key->N);
  if (modulus_bytelen > *siglen) {
     *siglen = modulus_bytelen;
     return CRYPT_BUFFER_OVERFLOW;
  }

  if (params->padding == LTC_PKCS_1_PSS) {
    /* PSS pad the key */
    x = *siglen;
    if ((err = ltc_pkcs_1_pss_encode_mgf1(hash, hashlen, params, modulus_bitlen, sig, &x)) != CRYPT_OK) {
       return err;
    }
  } else {
    /* PKCS #1 v1.5 pad the hash */
    unsigned long y;
    unsigned char *tmpin = NULL;
    const unsigned char *tmpin_ro;

    if (params->padding == LTC_PKCS_1_V1_5) {
      ltc_asn1_list digestinfo[2], siginfo[2];

    /* construct the SEQUENCE
        SEQUENCE {
           SEQUENCE {hashoid OID
                     blah    NULL
           }
         hash    OCTET STRING
        }
     */
      LTC_SET_ASN1(digestinfo, 0, LTC_ASN1_OBJECT_IDENTIFIER, hash_descriptor[op_checked.hash_alg].OID, hash_descriptor[op_checked.hash_alg].OIDlen);
      LTC_SET_ASN1(digestinfo, 1, LTC_ASN1_NULL,              NULL,                          0);
      LTC_SET_ASN1(siginfo,    0, LTC_ASN1_SEQUENCE,          digestinfo,                    2);
      LTC_SET_ASN1(siginfo,    1, LTC_ASN1_OCTET_STRING,      hash,                            hashlen);

      /* allocate memory for the encoding */
      y = ltc_mp_unsigned_bin_size(key->N);
      tmpin = XMALLOC(y);
      if (tmpin == NULL) {
         return CRYPT_MEM;
      }

      if ((err = der_encode_sequence(siginfo, 2, tmpin, &y)) != CRYPT_OK) {
         XFREE(tmpin);
         return err;
      }
      tmpin_ro = tmpin;
    } else {
      /* set the pointer and data-length to the input values */
      tmpin_ro = hash;
      y = hashlen;
    }

    x = *siglen;
    err = ltc_pkcs_1_v1_5_encode(tmpin_ro, y, LTC_PKCS_1_EMSA, modulus_bitlen, NULL, 0, sig, &x);

    if (params->padding == LTC_PKCS_1_V1_5) {
      XFREE(tmpin);
    }

    if (err != CRYPT_OK) {
      return err;
    }
  }

  /* RSA encode it */
  return ltc_mp.rsa_me(sig, x, sig, siglen, PK_PRIVATE, key);
}

#endif /* LTC_MRSA */
