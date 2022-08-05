/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include <tomcrypt_test.h>

#if defined(LTC_PKCS_1)

#include "../notes/rsa-testvectors/pkcs1v15sign-vectors.c"



int pkcs_1_emsa_test(void)
{
  int hash_idx = find_hash("sha1");
  unsigned int i;
  unsigned int j;

  if (ltc_mp.name == NULL) return CRYPT_NOP;

  DO(hash_is_valid(hash_idx));

  for (i = 0; i < sizeof(testcases_emsa)/sizeof(testcases_emsa[0]); ++i) {
    testcase_t* t = &testcases_emsa[i];
    rsa_key k, *key = &k;
    DOX(ltc_mp_init_multi(&key->e, &key->d, &key->N, &key->dQ,
                       &key->dP, &key->qP, &key->p, &key->q, NULL), t->name);

    DOX(ltc_mp_read_unsigned_bin(key->e, t->rsa.e, t->rsa.e_l), t->name);
    DOX(ltc_mp_read_unsigned_bin(key->d, t->rsa.d, t->rsa.d_l), t->name);
    DOX(ltc_mp_read_unsigned_bin(key->N, t->rsa.n, t->rsa.n_l), t->name);
    DOX(ltc_mp_read_unsigned_bin(key->dQ, t->rsa.dQ, t->rsa.dQ_l), t->name);
    DOX(ltc_mp_read_unsigned_bin(key->dP, t->rsa.dP, t->rsa.dP_l), t->name);
    DOX(ltc_mp_read_unsigned_bin(key->qP, t->rsa.qInv, t->rsa.qInv_l), t->name);
    DOX(ltc_mp_read_unsigned_bin(key->q, t->rsa.q, t->rsa.q_l), t->name);
    DOX(ltc_mp_read_unsigned_bin(key->p, t->rsa.p, t->rsa.p_l), t->name);
    key->type = PK_PRIVATE;

    for (j = 0; j < sizeof(t->data)/sizeof(t->data[0]); ++j) {
        rsaData_t* s = &t->data[j];
        unsigned char buf[20], obuf[256];
        unsigned long buflen = sizeof(buf), obuflen = sizeof(obuf);
        int stat;
        DOX(hash_memory(hash_idx, s->o1, s->o1_l, buf, &buflen), s->name);
        DOX(rsa_sign_hash_ex(buf, buflen, obuf, &obuflen, LTC_PKCS_1_V1_5, NULL, -1, hash_idx, 0, key), s->name);
        COMPARE_TESTVECTOR(obuf, obuflen, s->o2, s->o2_l,s->name, j);
        DOX(rsa_verify_hash_ex(obuf, obuflen, buf, buflen, LTC_PKCS_1_V1_5, hash_idx, 0, &stat, key), s->name);
        DOX(stat == 1?CRYPT_OK:CRYPT_FAIL_TESTVECTOR, s->name);
    } /* for */

    ltc_mp_deinit_multi(key->d,  key->e, key->N, key->dQ, key->dP, key->qP, key->p, key->q, NULL);
  } /* for */

  return 0;
}

#else

int pkcs_1_emsa_test(void)
{
   return CRYPT_NOP;
}

#endif

