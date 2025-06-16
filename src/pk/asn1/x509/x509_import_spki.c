/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file x509_import_spki.c
  Import the SubjectPublicKeyInfo of an X.509 cert, Steffen Jaeckel
*/

#ifdef LTC_DER

typedef int (*import_fn)(const unsigned char *, unsigned long, void*);

static const import_fn s_import_x509_fns[LTC_PKA_NUM] = {
#ifdef LTC_MRSA
                                                [LTC_PKA_RSA] = (import_fn)rsa_import_x509,
#endif
#ifdef LTC_MDSA
                                                [LTC_PKA_DSA] = (import_fn)dsa_import,
#endif
#ifdef LTC_MECC
                                                [LTC_PKA_EC] = (import_fn)ecc_import_x509,
#endif
#ifdef LTC_CURVE25519
                                                [LTC_PKA_X25519] = (import_fn)x25519_import_x509,
                                                [LTC_PKA_ED25519] = (import_fn)ed25519_import_x509,
#endif
};

int x509_import_spki(const unsigned char *asn1_cert, unsigned long asn1_len, ltc_pka_key *k, ltc_asn1_list **root)
{
   enum ltc_pka_id pka = LTC_PKA_UNDEF;
   ltc_asn1_list *d, *spki;
   int err;
   if ((err = x509_decode_spki(asn1_cert, asn1_len, &d, &spki)) != CRYPT_OK) {
      return err;
   }
   if ((err = x509_get_pka(spki, &pka)) != CRYPT_OK) {
      goto err_out;
   }
   if (pka < 0
         || pka > LTC_ARRAY_SIZE(s_import_x509_fns)
         || s_import_x509_fns[pka] == NULL) {
      err = CRYPT_PK_INVALID_TYPE;
      goto err_out;
   }
   if ((err = s_import_x509_fns[pka](asn1_cert, asn1_len, &k->u)) == CRYPT_OK) {
      k->id = pka;
   }
err_out:
   if (err == CRYPT_OK && root) {
      *root = d;
      d = NULL;
   }
   der_free_sequence_flexi(d);
   return err;
}

#endif /* LTC_DER */
