/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file pem_encode.c
  Encode a key as PEM file according to RFC 7468
*/

#ifdef LTC_PEM

/* Export the key into a new buffer */
static int s_export_key(int which, const ltc_pka_key *key, unsigned char **der, unsigned long *derlen)
{
   unsigned char dummy[1];
   unsigned long len = 0;
   int err;

   /* a too small buffer makes the exporter report the size; without a size there is nothing to allocate */
   err = pka_key_export(dummy, &len, which, key);
   if (err == CRYPT_OK || (err == CRYPT_BUFFER_OVERFLOW && len == 0)) return CRYPT_ERROR;
   if (err != CRYPT_BUFFER_OVERFLOW) return err;
   if ((*der = XMALLOC(len)) == NULL) return CRYPT_MEM;
   *derlen = len;
   if ((err = pka_key_export(*der, derlen, which, key)) != CRYPT_OK) {
      zeromem(*der, len);
      XFREE(*der);
      *der = NULL;
   }
   return err;
}

static unsigned long s_put_line(unsigned char *out, const struct str *s, unsigned long eol)
{
   unsigned long len = 0;
   if (s != NULL) {
      XMEMCPY(out, s->p, s->len);
      len = s->len;
   }
   if (eol == 2) out[len++] = '\r';
   out[len++] = '\n';
   return len;
}

/**
   Encode a key as PEM

   The label follows from the arguments: `PRIVATE KEY` for a private key, `ENCRYPTED PRIVATE KEY`
   for a private key with a password and `PUBLIC KEY` for a public key.

   @param out     [out] The destination of the PEM text, NUL terminated
   @param outlen  [in/out] The max size and resulting size of the output, the size does not count the NUL
   @param which   PK_PRIVATE|PK_STD or PK_PUBLIC|PK_STD
   @param key     The key to encode
   @param opts    The password and the format options, may be NULL
   @param prng    An active PRNG state, only used when the key gets encrypted
   @param wprng   The index of the PRNG desired
   @return CRYPT_OK on success, CRYPT_BUFFER_OVERFLOW with the required size in outlen if out is too small
*/
int pem_encode_pkcs(      unsigned char *out, unsigned long *outlen,
                          int which, const ltc_pka_key *key,
                    const pem_encode_opts *opts,
                          prng_state *prng, int wprng)
{
   const struct pem_header_id *hdr = NULL;
   unsigned char *der = NULL, *enc = NULL;
   const unsigned char *body;
   unsigned long derlen = 0, bodylen, b64len, eol, need, n, x;
   enum pem_flags pf;
   int err, encrypt;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   /* the password decides about the encryption; its length is checked by pbes2_encrypt(), which refuses an empty one */
   encrypt = opts != NULL && (opts->pw != NULL || opts->pwlen != 0);
   eol = (opts != NULL && (opts->flags & LTC_PEM_CRLF)) ? 2 : 1;

   if (which == (PK_PRIVATE | PK_STD)) {
      pf = encrypt ? pf_encrypted_pkcs8 : pf_pkcs8;
   } else if (which == (PK_PUBLIC | PK_STD) && !encrypt) {
      pf = pf_public;
   } else {
      return CRYPT_INVALID_ARG;
   }
   for (n = 0; n < pem_std_headers_num && hdr == NULL; ++n) {
      if (pem_std_headers[n].flags == pf && pem_std_headers[n].pka == LTC_PKA_UNDEF) hdr = &pem_std_headers[n];
   }
   if (hdr == NULL) return CRYPT_ERROR;

   if ((err = s_export_key(which, key, &der, &derlen)) != CRYPT_OK) return err;
   body = der;
   bodylen = derlen;
   if (encrypt) {
      /* only the size for now, the KDF must not run before the output buffer is known to be big enough */
      bodylen = 0;
      err = pbes2_encrypt(out, &bodylen, der, derlen, opts->pw, opts->pwlen, opts->enc, prng, wprng);
      if (err != CRYPT_BUFFER_OVERFLOW) {
         if (err == CRYPT_OK) err = CRYPT_ERROR;
         goto LBL_ERR;
      }
   }

   b64len = 4 * ((bodylen + 2) / 3);
   need = hdr->start.len + eol + b64len + ((b64len + 63) / 64) * eol + hdr->end.len + eol + 1;
   if (*outlen < need) {
      *outlen = need;
      err = CRYPT_BUFFER_OVERFLOW;
      goto LBL_ERR;
   }

   if (encrypt) {
      if ((enc = XMALLOC(bodylen)) == NULL) {
         err = CRYPT_MEM;
         goto LBL_ERR;
      }
      if ((err = pbes2_encrypt(enc, &bodylen, der, derlen, opts->pw, opts->pwlen, opts->enc, prng, wprng)) != CRYPT_OK) goto LBL_ERR;
      body = enc;
   }

   x = s_put_line(out, &hdr->start, eol);
   n = *outlen - x;
   if ((err = base64_encode_pem(body, bodylen, (char*)out + x, &n, eol == 2 ? BASE64_PEM_CRLF : 0)) != CRYPT_OK) goto LBL_ERR;
   x += n;
   /* base64_encode_pem() ends a line only when it is full */
   if (out[x - 1] != '\n') x += s_put_line(out + x, NULL, eol);
   x += s_put_line(out + x, &hdr->end, eol);
   out[x] = '\0';
   *outlen = x;

LBL_ERR:
   if (enc != NULL) XFREE(enc);
   zeromem(der, derlen);
   XFREE(der);
   return err;
}

#ifndef LTC_NO_FILE
/**
   Encode a key as PEM and write it to a file

   @param f       The file to write to
   @param which   PK_PRIVATE|PK_STD or PK_PUBLIC|PK_STD
   @param key     The key to encode
   @param opts    The password and the format options, may be NULL
   @param prng    An active PRNG state, only used when the key gets encrypted
   @param wprng   The index of the PRNG desired
   @return CRYPT_OK on success
*/
int pem_encode_pkcs_filehandle(FILE *f, int which, const ltc_pka_key *key,
                               const pem_encode_opts *opts,
                               prng_state *prng, int wprng)
{
   unsigned char dummy[1], *buf;
   unsigned long len = 0, pemlen;
   int err;

   LTC_ARGCHK(f   != NULL);
   LTC_ARGCHK(key != NULL);

   /* a too small buffer makes pem_encode_pkcs() report the size; without a size there is nothing to allocate */
   err = pem_encode_pkcs(dummy, &len, which, key, opts, prng, wprng);
   if (err == CRYPT_OK || (err == CRYPT_BUFFER_OVERFLOW && len == 0)) return CRYPT_ERROR;
   if (err != CRYPT_BUFFER_OVERFLOW) return err;
   if ((buf = XMALLOC(len)) == NULL) return CRYPT_MEM;
   pemlen = len;
   if ((err = pem_encode_pkcs(buf, &pemlen, which, key, opts, prng, wprng)) == CRYPT_OK && fwrite(buf, 1, pemlen, f) != pemlen) {
      err = CRYPT_ERROR;
   }
   zeromem(buf, len);
   XFREE(buf);
   return err;
}
#endif /* LTC_NO_FILE */

#endif /* LTC_PEM */
