/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file pbes2_encrypt.c
  Encrypt a PKCS#8 PrivateKeyInfo with PBES2
*/

#ifdef LTC_PBES

/**
   Encrypt a PrivateKeyInfo into an EncryptedPrivateKeyInfo, PBES2 with PBKDF2 and a cipher in CBC mode

   @param out     [out] The DER encoded EncryptedPrivateKeyInfo
   @param outlen  [in/out] The max size and resulting size of the output
   @param in      The DER encoded PrivateKeyInfo, must not overlap with out
   @param inlen   The length of the input
   @param pw      The password
   @param pwlen   The length of the password, must not be 0
   @param params  The encryption parameters, NULL for the defaults
   @param prng    An active PRNG state, the source of the salt and the IV
   @param wprng   The index of the PRNG desired
   @return CRYPT_OK on success, CRYPT_BUFFER_OVERFLOW with the required size in outlen if out is too small
*/
int pbes2_encrypt(      unsigned char *out, unsigned long *outlen,
                  const unsigned char *in,  unsigned long  inlen,
                  const unsigned char *pw,  unsigned long  pwlen,
                  const pbes2_enc_params *params,
                        prng_state *prng, int wprng)
{
   static const pbes2_enc_params defaults = { NULL, 0, NULL, 0, 0 };
   const char *cipher, *prf, *oid_str[PBES2_OID_NUM];
   unsigned long oid[PBES2_OID_NUM][16], oidlen[PBES2_OID_NUM];
   unsigned long keylen, klen, iterations, saltlen, ivlen, ctlen, need, n;
   unsigned char salt[64], iv[MAXBLOCKSIZE], key[32], *ct;
   ltc_asn1_list seq_prf[2], seq_kdf_params[3], seq_kdf[2], seq_enc[2], seq_params[2], seq_alg[2], seq_epki[2];
   symmetric_CBC cbc;
   int err, cid, hid;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(pw     != NULL);

   if (params == NULL) params = &defaults;
   cipher     = params->cipher != NULL ? params->cipher : "aes";
   prf        = params->prf != NULL ? params->prf : "sha256";
   keylen     = params->keylen;
   iterations = params->iterations != 0 ? params->iterations : LTC_PBES2_DEFAULT_ITERATIONS;
   saltlen    = params->saltlen != 0 ? params->saltlen : 16;

   if (pwlen == 0 || saltlen < 8 || saltlen > sizeof(salt)) return CRYPT_INVALID_ARG;
   /* pbes_decrypt() refuses anything above this limit */
   if (iterations > LTC_PBES_MAX_ITERATIONS) return CRYPT_INVALID_ARG;
   if ((err = pbes2_find_oids(cipher, &keylen, prf, oid_str)) != CRYPT_OK) return err;
   if ((cid = find_cipher(cipher)) == -1) return CRYPT_INVALID_CIPHER;
   if ((hid = find_hash(prf)) == -1) return CRYPT_INVALID_HASH;
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) return err;
   for (n = 0; n < PBES2_OID_NUM; n++) {
      oidlen[n] = LTC_ARRAY_SIZE(oid[n]);
      if ((err = pk_oid_str_to_num(oid_str[n], oid[n], &oidlen[n])) != CRYPT_OK) return err;
   }

   ivlen = cipher_descriptor[cid].block_length;
   if (keylen > sizeof(key) || ivlen > sizeof(iv) || inlen > ULONG_MAX - ivlen) return CRYPT_INVALID_ARG;
   ctlen = inlen + ivlen - (inlen % ivlen); /* PKCS#7 padding adds 1 to ivlen bytes */

   /* PBES2-params: prf is always written, the default would be HMAC-SHA1; keyLength is left out, the cipher OID implies it */
   LTC_SET_ASN1(seq_prf,        0, LTC_ASN1_OBJECT_IDENTIFIER, oid[PBES2_OID_PRF],    oidlen[PBES2_OID_PRF]);
   LTC_SET_ASN1(seq_prf,        1, LTC_ASN1_NULL,              NULL,                  0UL);
   LTC_SET_ASN1(seq_kdf_params, 0, LTC_ASN1_OCTET_STRING,      salt,                  saltlen);
   LTC_SET_ASN1(seq_kdf_params, 1, LTC_ASN1_SHORT_INTEGER,     &iterations,           1UL);
   LTC_SET_ASN1(seq_kdf_params, 2, LTC_ASN1_SEQUENCE,          seq_prf,               2UL);
   LTC_SET_ASN1(seq_kdf,        0, LTC_ASN1_OBJECT_IDENTIFIER, oid[PBES2_OID_PBKDF2], oidlen[PBES2_OID_PBKDF2]);
   LTC_SET_ASN1(seq_kdf,        1, LTC_ASN1_SEQUENCE,          seq_kdf_params,        3UL);
   LTC_SET_ASN1(seq_enc,        0, LTC_ASN1_OBJECT_IDENTIFIER, oid[PBES2_OID_CIPHER], oidlen[PBES2_OID_CIPHER]);
   LTC_SET_ASN1(seq_enc,        1, LTC_ASN1_OCTET_STRING,      iv,                    ivlen);
   LTC_SET_ASN1(seq_params,     0, LTC_ASN1_SEQUENCE,          seq_kdf,               2UL);
   LTC_SET_ASN1(seq_params,     1, LTC_ASN1_SEQUENCE,          seq_enc,               2UL);
   LTC_SET_ASN1(seq_alg,        0, LTC_ASN1_OBJECT_IDENTIFIER, oid[PBES2_OID_PBES2],  oidlen[PBES2_OID_PBES2]);
   LTC_SET_ASN1(seq_alg,        1, LTC_ASN1_SEQUENCE,          seq_params,            2UL);
   LTC_SET_ASN1(seq_epki,       0, LTC_ASN1_SEQUENCE,          seq_alg,               2UL);
   LTC_SET_ASN1(seq_epki,       1, LTC_ASN1_OCTET_STRING,      NULL,                  ctlen);

   /* the size is known without the salt, the IV and the key, so a size query costs neither random bytes nor a KDF run */
   if ((err = der_length_sequence(seq_epki, 2, &need)) != CRYPT_OK) return err;
   if (*outlen < need) {
      *outlen = need;
      return CRYPT_BUFFER_OVERFLOW;
   }

   if (prng_descriptor[wprng].read(salt, saltlen, prng) != saltlen || prng_descriptor[wprng].read(iv, ivlen, prng) != ivlen) {
      return CRYPT_ERROR_READPRNG;
   }
   if ((ct = XMALLOC(ctlen)) == NULL) return CRYPT_MEM;
   XMEMCPY(ct, in, inlen);
   n = ctlen;
   if ((err = padding_pad(ct, inlen, &n, LTC_PAD_PKCS7 | ivlen)) != CRYPT_OK) goto LBL_ERR;
   klen = keylen;
   if ((err = pkcs_5_alg2(pw, pwlen, salt, saltlen, (int)iterations, hid, key, &klen)) != CRYPT_OK) goto LBL_ERR;
   if ((err = cbc_start(cid, iv, key, keylen, 0, &cbc)) != CRYPT_OK) goto LBL_ERR;
   if ((err = cbc_encrypt(ct, ct, ctlen, &cbc)) != CRYPT_OK) goto LBL_ERR;
   if ((err = cbc_done(&cbc)) != CRYPT_OK) goto LBL_ERR;
   seq_epki[1].data = ct;
   err = der_encode_sequence(seq_epki, 2, out, outlen);

LBL_ERR:
   zeromem(key, sizeof(key));
   zeromem(&cbc, sizeof(cbc));
   zeromem(ct, ctlen);
   XFREE(ct);
   return err;
}

#endif
