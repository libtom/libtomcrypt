/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt.h"

/**
  @file gcm_file.c
  GCM process a file, Steffen Jaeckel
*/

#ifdef LTC_GCM_MODE
#ifndef LTC_NO_FILE

/**
  Process a file.

  c.f. gcm_filehandle() for basic documentation.

  It is possible, that in error-cases the 'out' file
  will be created and after the error occurred it will
  be removed again.

  @param cipher            Index of cipher to use
  @param key               The secret key
  @param keylen            The length of the secret key
  @param IV                The initial vector
  @param IVlen             The length of the initial vector
  @param adata             The additional authentication data (header)
  @param adatalen          The length of the adata
  @param in                The input file
  @param out               The output file
  @param taglen            The MAC tag length
  @param direction         Encrypt or Decrypt mode (GCM_ENCRYPT or GCM_DECRYPT)
  @param res               [out] Result of the operation, 1==valid, 0==invalid
  @return CRYPT_OK on success
 */
int gcm_file(      int           cipher,
               const unsigned char *key,    unsigned long keylen,
               const unsigned char *IV,     unsigned long IVlen,
               const unsigned char *adata,  unsigned long adatalen,
                        const char *in,
                        const char *out,
                     unsigned long taglen,
                               int direction,
                               int *res)
{
    int        err;
    FILE *f_in = NULL, *f_out = NULL;

    LTC_ARGCHK(in  != NULL);
    LTC_ARGCHK(out != NULL);
    LTC_ARGCHK(res != NULL);

    *res = 0;

    f_in = fopen(in, "rb");
    if (f_in == NULL) {
       err = CRYPT_FILE_NOTFOUND;
       goto LBL_ERR;
    }
    f_out = fopen(out, "w+b");
    if (f_out == NULL) {
       err = CRYPT_FILE_NOTFOUND;
       goto LBL_ERR;
    }

    err = gcm_filehandle(cipher, key, keylen, IV, IVlen, adata, adatalen, f_in, f_out, taglen, direction, res);

LBL_ERR:
    if (f_out != NULL && fclose(f_out) != 0) {
       err = CRYPT_ERROR;
    }
    if (*res != 1) {
       remove(out);
    }
    if (f_in != NULL && fclose(f_in) != 0) {
       err = CRYPT_ERROR;
    }

    return err;
}
#endif
#endif

