/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include <tomcrypt_test.h>

#if defined(LTC_PKCS_1)

#include "../notes/rsa-testvectors/oaep-vect.c"



int pkcs_1_oaep_test(void)
{
  prng_state* no_prng_desc = no_prng_desc_get();
  int hash_idx = find_hash("sha1");
  unsigned int i;
  unsigned int j;

  if (ltc_mp.name == NULL) return CRYPT_NOP;

  DO(hash_is_valid(hash_idx));

  for (i = 0; i < sizeof(testcases_oaep)/sizeof(testcases_oaep[0]); ++i) {
    testcase_t* t = &testcases_oaep[i];
    rsa_key k, *key = &k;
    DOX(mp_init_multi(&key->e, &key->d, &key->N, &key->dQ,
                       &key->dP, &key->qP, &key->p, &key->q, NULL), t->name);

    DOX(mp_read_unsigned_bin(key->e, t->rsa.e, t->rsa.e_l), t->name);
    DOX(mp_read_unsigned_bin(key->d, t->rsa.d, t->rsa.d_l), t->name);
    DOX(mp_read_unsigned_bin(key->N, t->rsa.n, t->rsa.n_l), t->name);
    DOX(mp_read_unsigned_bin(key->dQ, t->rsa.dQ, t->rsa.dQ_l), t->name);
    DOX(mp_read_unsigned_bin(key->dP, t->rsa.dP, t->rsa.dP_l), t->name);
    DOX(mp_read_unsigned_bin(key->qP, t->rsa.qInv, t->rsa.qInv_l), t->name);
    DOX(mp_read_unsigned_bin(key->q, t->rsa.q, t->rsa.q_l), t->name);
    DOX(mp_read_unsigned_bin(key->p, t->rsa.p, t->rsa.p_l), t->name);
    key->type = PK_PRIVATE;

    for (j = 0; j < sizeof(t->data)/sizeof(t->data[0]); ++j) {
        rsaData_t* s = &t->data[j];
        unsigned char buf[256], obuf[256];
        unsigned long buflen = sizeof(buf), obuflen = sizeof(obuf);
        int stat;
        no_prng_desc->desc.add_entropy(s->o2, s->o2_l, no_prng_desc);
        DOX(rsa_encrypt_key(s->o1, s->o1_l, obuf, &obuflen, NULL, 0, (void*)no_prng_desc, hash_idx, key), s->name);
        COMPARE_TESTVECTOR(obuf, obuflen, s->o3, s->o3_l,s->name, j);
        DOX(rsa_decrypt_key(obuf, obuflen, buf, &buflen, NULL, 0, hash_idx, &stat, key), s->name);
        DOX(stat == 1?CRYPT_OK:CRYPT_FAIL_TESTVECTOR, s->name);
    } /* for */

    mp_clear_multi(key->d,  key->e, key->N, key->dQ, key->dP, key->qP, key->p, key->q, LTC_NULL);
  } /* for */

  no_prng_desc_free(no_prng_desc);

  return 0;
}

#else

int pkcs_1_oaep_test(void)
{
   return CRYPT_NOP;
}

#endif

