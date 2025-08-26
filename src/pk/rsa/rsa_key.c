/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file rsa_key.c
  Free an RSA key, Tom St Denis
  Basic operations on an RSA key, Steffen Jaeckel
*/

#ifdef LTC_MRSA
static void s_mpi_shrink_multi(void **a, ...)
{
   void **cur;
   unsigned n;
   int err;
   va_list args;
   void *tmp[10] = { 0 };
   void **arg[10] = { 0 };

   /* We re-allocate in the order that we received the varargs */
   n = 0;
   err = CRYPT_ERROR;
   cur = a;
   va_start(args, a);
   while (cur != NULL) {
      if (n >= LTC_ARRAY_SIZE(tmp)) {
         goto out;
      }
      if (*cur != NULL) {
         arg[n] = cur;
         if ((err = ltc_mp_init_copy(&tmp[n], *arg[n])) != CRYPT_OK) {
            goto out;
         }
         n++;
      }
      cur = va_arg(args, void**);
   }
   va_end(args);

   /* but we clear the old values in the reverse order */
   while (n != 0 && arg[--n] != NULL) {
      ltc_mp_clear(*arg[n]);
      *arg[n] = tmp[n];
   }
out:
   va_end(args);
   /* clean-up after an error
    * or after this was called with too many args
    */
   if ((err != CRYPT_OK) ||
         (n >= LTC_ARRAY_SIZE(tmp))) {
      for (n = 0; n < LTC_ARRAY_SIZE(tmp); ++n) {
         if (tmp[n] != NULL) {
            ltc_mp_clear(tmp[n]);
         }
      }
   }
}

/**
  This shrinks the allocated memory of a RSA key

     It will use up some more memory temporarily,
     but then it will free-up the entire sequence that
     was once allocated when the key was created/populated.

     This only works with libtommath >= 1.2.0 in earlier versions
     it has the inverse effect due to the way it worked internally.
     Also works for GNU MP, tomsfastmath naturally shows no effect.

  @param key   The RSA key to shrink
*/
void rsa_shrink_key(rsa_key *key)
{
   LTC_ARGCHKVD(key != NULL);
   s_mpi_shrink_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP, &key->p, &key->q, NULL);
}

/**
  Init an RSA key
  @param key   The RSA key to initialize
  @return CRYPT_OK if successful
*/
int rsa_init(rsa_key *key)
{
   LTC_ARGCHK(key != NULL);
   XMEMSET(&key->params, 0, sizeof(key->params));
   return ltc_mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP, &key->p, &key->q, LTC_NULL);
}

/**
  Free an RSA key from memory
  @param key   The RSA key to free
*/
void rsa_free(rsa_key *key)
{
   LTC_ARGCHKVD(key != NULL);
   ltc_mp_cleanup_multi(&key->q, &key->p, &key->qP, &key->dP, &key->dQ, &key->N, &key->d, &key->e, LTC_NULL);
   XMEMSET(&key->params, 0, sizeof(key->params));
}

static LTC_INLINE int s_rsa_key_valid_pss_algs(const rsa_key *key, int padding, int hash_idx)
{
   if (!key->params.pss_oaep) {
      return CRYPT_OK;
   }
   if (padding != LTC_PKCS_1_PSS) {
      return CRYPT_PK_TYPE_MISMATCH;
   }
   if (key->params.hash_alg == NULL || find_hash(key->params.hash_alg) != hash_idx) {
      return CRYPT_INVALID_HASH;
   }
   if (key->params.mgf1_hash_alg == NULL) {
      return CRYPT_INVALID_HASH;
   }
   return hash_is_valid(find_hash(key->params.mgf1_hash_alg));
}

static LTC_INLINE int s_rsa_key_valid_sign(const rsa_key *key, int padding, int hash_idx)
{
   if ((padding != LTC_PKCS_1_V1_5) &&
       (padding != LTC_PKCS_1_PSS) &&
       (padding != LTC_PKCS_1_V1_5_NA1)) {
     return CRYPT_PK_INVALID_PADDING;
   }

   if (padding != LTC_PKCS_1_V1_5_NA1) {
      int err;
      /* valid hash ? */
      if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
        return err;
      }
   }
   return s_rsa_key_valid_pss_algs(key, padding, hash_idx);
}

static LTC_INLINE int s_rsa_key_valid_crypt(const rsa_key *key, int padding, int hash_idx)
{
   if ((padding != LTC_PKCS_1_V1_5) &&
       (padding != LTC_PKCS_1_OAEP)) {
     return CRYPT_PK_INVALID_PADDING;
   }

   if (padding == LTC_PKCS_1_OAEP) {
      int err;
      /* valid hash? */
      if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
        return err;
      }
   }
   return s_rsa_key_valid_pss_algs(key, padding, hash_idx);
}

int rsa_key_valid_op(const rsa_key *key, ltc_rsa_op op, int padding, int hash_idx)
{
   switch (op) {
      case LTC_RSA_SIGN:
         return s_rsa_key_valid_sign(key, padding, hash_idx);
      case LTC_RSA_CRYPT:
         return s_rsa_key_valid_crypt(key, padding, hash_idx);
      default:
         return CRYPT_ERROR;
   }
}

int rsa_params_equal(const ltc_rsa_parameters *a, const ltc_rsa_parameters *b)
{
   if (!a->pss_oaep)
      return 0;
   if (a->pss_oaep != b->pss_oaep)
      return 0;
   if (a->saltlen != b->saltlen)
      return 0;
   if (!a->hash_alg || !b->hash_alg)
      return 0;
   if (XSTRCMP(a->hash_alg, b->hash_alg))
      return 0;
   if (!a->mgf1_hash_alg || !b->mgf1_hash_alg)
      return 0;
   if (XSTRCMP(a->mgf1_hash_alg, b->mgf1_hash_alg))
      return 0;
   return 1;
}

#endif
