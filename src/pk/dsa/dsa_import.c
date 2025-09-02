/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file dsa_import.c
   DSA implementation, import a DSA key, Tom St Denis
*/

#ifdef LTC_MDSA

static int s_dsa_import_pkcs1(const unsigned char *in, unsigned long inlen, dsa_key *key)
{
   int           err;
   unsigned long zero = 0;
   /* get key type */
   if ((err = der_decode_sequence_multi(in, inlen,
                          LTC_ASN1_SHORT_INTEGER, 1UL, &zero,
                          LTC_ASN1_INTEGER,      1UL, key->p,
                          LTC_ASN1_INTEGER,      1UL, key->q,
                          LTC_ASN1_INTEGER,      1UL, key->g,
                          LTC_ASN1_INTEGER,      1UL, key->y,
                          LTC_ASN1_INTEGER,      1UL, key->x,
                          LTC_ASN1_EOL,          0UL, NULL)) == CRYPT_OK) {

       key->type = PK_PRIVATE;
   }
   return err;
}

static int s_dsa_import_y(const unsigned char *in, unsigned long inlen, dsa_key *key)
{
   return der_decode_integer(in, inlen, key->y);
}

static LTC_INLINE int s_dsa_set_params(dsa_key *key, ltc_asn1_list *params)
{
   LTC_SET_ASN1(params, 0, LTC_ASN1_INTEGER, key->p, 1UL);
   LTC_SET_ASN1(params, 1, LTC_ASN1_INTEGER, key->q, 1UL);
   LTC_SET_ASN1(params, 2, LTC_ASN1_INTEGER, key->g, 1UL);
   return 3;
}

static LTC_INLINE int s_dsa_validate(dsa_key *key)
{
   int           err, stat;
   key->qord = ltc_mp_unsigned_bin_size(key->q);

   /* quick p, q, g validation, without primality testing
    * + x, y validation */
   if ((err = dsa_int_validate(key, &stat)) != CRYPT_OK) {
      return err;
   }

   if (stat == 0) {
      return CRYPT_INVALID_PACKET;
   }

   return CRYPT_OK;
}

static int s_dsa_import_spki(const unsigned char *in, unsigned long inlen, dsa_key *key)
{
   int err;
   unsigned char* tmpbuf = NULL;
   ltc_asn1_list params[3];
   unsigned long tmpbuf_len = inlen, len;

   len = s_dsa_set_params(key, params);

   tmpbuf = XCALLOC(1, tmpbuf_len);
   if (tmpbuf == NULL) {
      return CRYPT_MEM;
   }

   err = x509_decode_subject_public_key_info(in, inlen,
                                             LTC_OID_DSA,       tmpbuf, &tmpbuf_len,
                                             LTC_ASN1_SEQUENCE, params, &len);
   if (err != CRYPT_OK) {
      goto LBL_ERR;
   }

   if ((err = s_dsa_import_y(tmpbuf, tmpbuf_len, key)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   key->type = PK_PUBLIC;
LBL_ERR:
   XFREE(tmpbuf);
   return err;
}

int dsa_import_spki(const unsigned char *in, unsigned long inlen, dsa_key *key)
{
   int           err;

   LTC_ARGCHK(in  != NULL);

   /* init key */
   if ((err = dsa_int_init(key)) != CRYPT_OK) return err;

   if ((err = s_dsa_import_spki(in, inlen, key)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   if ((err = s_dsa_validate(key)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   return CRYPT_OK;
LBL_ERR:
   dsa_free(key);
   return err;
}

static int s_dsa_import_x509(const unsigned char *in, unsigned long inlen, dsa_key *key)
{
   int err;
   ltc_asn1_list params[3];
   unsigned long len;

   len = s_dsa_set_params(key, params);

   if ((err = x509_decode_public_key_from_certificate(in, inlen,
                                                      LTC_OID_DSA,
                                                      LTC_ASN1_SEQUENCE, params, &len,
                                                      (public_key_decode_cb)s_dsa_import_y, key)) == CRYPT_OK) {
      key->type = PK_PUBLIC;
      return CRYPT_OK;
   }

   return err;
}

/**
   Import a DSA key
   @param in       The binary packet to import from
   @param inlen    The length of the binary packet
   @param key      [out] Where to store the imported key
   @return CRYPT_OK if successful, upon error this function will free all allocated memory
*/
int dsa_import(const unsigned char *in, unsigned long inlen, dsa_key *key)
{
   int           err;
   unsigned char flags[1];

   LTC_ARGCHK(in  != NULL);

   /* init key */
   if ((err = dsa_int_init(key)) != CRYPT_OK) return err;

   /* try to match the old libtomcrypt format */
   err = der_decode_sequence_multi(in, inlen, LTC_ASN1_BIT_STRING, 1UL, flags,
                                              LTC_ASN1_EOL,        0UL, NULL);

   if (err == CRYPT_OK || err == CRYPT_INPUT_TOO_LONG) {
       /* private key */
       if (flags[0] == 1) {
           if ((err = der_decode_sequence_multi(in, inlen,
                                  LTC_ASN1_BIT_STRING,   1UL, flags,
                                  LTC_ASN1_INTEGER,      1UL, key->g,
                                  LTC_ASN1_INTEGER,      1UL, key->p,
                                  LTC_ASN1_INTEGER,      1UL, key->q,
                                  LTC_ASN1_INTEGER,      1UL, key->y,
                                  LTC_ASN1_INTEGER,      1UL, key->x,
                                  LTC_ASN1_EOL,          0UL, NULL)) != CRYPT_OK) {
               goto LBL_ERR;
           }
           key->type = PK_PRIVATE;
           goto LBL_OK;
       }
       /* public key */
       else if (flags[0] == 0) {
           if ((err = der_decode_sequence_multi(in, inlen,
                                      LTC_ASN1_BIT_STRING,   1UL, flags,
                                      LTC_ASN1_INTEGER,      1UL, key->g,
                                      LTC_ASN1_INTEGER,      1UL, key->p,
                                      LTC_ASN1_INTEGER,      1UL, key->q,
                                      LTC_ASN1_INTEGER,      1UL, key->y,
                                      LTC_ASN1_EOL,          0UL, NULL)) != CRYPT_OK) {
               goto LBL_ERR;
           }
           key->type = PK_PUBLIC;
           goto LBL_OK;
       }
       else {
          err = CRYPT_INVALID_PACKET;
          goto LBL_ERR;
       }
   }

   if (s_dsa_import_pkcs1(in, inlen, key) == CRYPT_OK) {
      goto LBL_OK;
   }
   if (s_dsa_import_spki(in, inlen, key) == CRYPT_OK) {
      goto LBL_OK;
   }
   if ((err = s_dsa_import_x509(in, inlen, key)) != CRYPT_OK) {
      goto LBL_ERR;
   }

LBL_OK:
   if ((err = s_dsa_validate(key)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   return CRYPT_OK;
LBL_ERR:
   dsa_free(key);
   return err;
}

#endif
