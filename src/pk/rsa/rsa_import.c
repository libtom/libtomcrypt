/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file rsa_import.c
  Import a PKCS RSA key, Tom St Denis
*/

#ifdef LTC_MRSA

#ifndef S_RSA_DECODE
#define S_RSA_DECODE
static int s_rsa_decode(const unsigned char *in, unsigned long inlen, rsa_key *key)
{
   /* now it should be SEQUENCE { INTEGER, INTEGER } */
   return der_decode_sequence_multi(in, inlen,
                                        LTC_ASN1_INTEGER, 1UL, key->N,
                                        LTC_ASN1_INTEGER, 1UL, key->e,
                                        LTC_ASN1_EOL,     0UL, NULL);
}
#endif


/**
  Import an RSAPublicKey or RSAPrivateKey as defined in PKCS #1 v2.1 [two-prime only]

    The `key` passed into this function has to be already initialized and will
    NOT be free'd on error!

  @param in      The packet to import from
  @param inlen   It's length (octets)
  @param key     [out] Destination for newly imported key
  @return CRYPT_OK if successful
*/
int rsa_import_pkcs1(const unsigned char *in, unsigned long inlen, rsa_key *key)
{
   int   err;
   unsigned long version = -1;

   err = der_decode_sequence_multi(in, inlen, LTC_ASN1_SHORT_INTEGER, 1UL, &version,
                                              LTC_ASN1_EOL,     0UL, NULL);

   if (err == CRYPT_OVERFLOW) {
      /* the version would fit into an LTC_ASN1_SHORT_INTEGER
       * so we try to decode as a public key
       */
      if ((err = s_rsa_decode(in, inlen, key)) == CRYPT_OK) {
         key->type = PK_PUBLIC;
      }
      goto LBL_OUT;
   } else if (err != CRYPT_INPUT_TOO_LONG) {
      /* couldn't decode the version, so error out */
      goto LBL_OUT;
   }

   if (version == 0) {
      /* it's a private key */
      if ((err = der_decode_sequence_multi(in, inlen,
                          LTC_ASN1_SHORT_INTEGER, 1UL, &version,
                          LTC_ASN1_INTEGER, 1UL, key->N,
                          LTC_ASN1_INTEGER, 1UL, key->e,
                          LTC_ASN1_INTEGER, 1UL, key->d,
                          LTC_ASN1_INTEGER, 1UL, key->p,
                          LTC_ASN1_INTEGER, 1UL, key->q,
                          LTC_ASN1_INTEGER, 1UL, key->dP,
                          LTC_ASN1_INTEGER, 1UL, key->dQ,
                          LTC_ASN1_INTEGER, 1UL, key->qP,
                          LTC_ASN1_EOL,     0UL, NULL)) != CRYPT_OK) {
         goto LBL_OUT;
      }
      key->type = PK_PRIVATE;
   } else if (version == 1) {
      /* we don't support multi-prime RSA */
      err = CRYPT_PK_INVALID_TYPE;
      goto LBL_OUT;
   }
   err = CRYPT_OK;
LBL_OUT:
   return err;
}

/**
  Import multiple formats of RSA public and private keys.

     RSAPublicKey or RSAPrivateKey as defined in PKCS #1 v2.1 [two-prime only]
     SubjectPublicKeyInfo formatted public keys

  @param in      The packet to import from
  @param inlen   It's length (octets)
  @param key     [out] Destination for newly imported key
  @return CRYPT_OK if successful, upon error allocated memory is freed
*/
int rsa_import(const unsigned char *in, unsigned long inlen, rsa_key *key)
{
   int           err;

   LTC_ARGCHK(in          != NULL);
   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   /* SubjectPublicKeyInfo or X.509 certificate format */
   if (rsa_import_x509(in, inlen, key) == CRYPT_OK) {
      return CRYPT_OK;
   }

   /* init key */
   if ((err = rsa_init(key)) != CRYPT_OK) {
      return err;
   }
   /* Try to match against PKCS #1 standards */
   if ((err = rsa_import_pkcs1(in, inlen, key)) != CRYPT_OK) {
      rsa_free(key);
   }

   return err;
}

#endif /* LTC_MRSA */

