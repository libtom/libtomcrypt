#include <tomcrypt_test.h>

#ifdef LTC_PKCS_1

#include "../notes/rsa-testvectors/pss-vect.c"



int pkcs_1_pss_test(void)
{
  int prng_idx = register_prng(&no_prng_desc);
  int hash_idx = find_hash("sha1");
  unsigned int i;

  DO(prng_is_valid(prng_idx));
  DO(hash_is_valid(hash_idx));

  for (i = 0; i < sizeof(testcases)/sizeof(testcases[0]); ++i) {
    testcase_t* t = &testcases[i];
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

    unsigned int j;
    for (j = 0; j < sizeof(t->sig)/sizeof(t->sig[0]); ++j) {
        rsaSig_t* s = &t->sig[j];
        unsigned char buf[20], obuf[256];
        unsigned long buflen = sizeof(buf), obuflen = sizeof(obuf);
        int stat;
        prng_descriptor[prng_idx].add_entropy(s->salt, s->salt_l, NULL);
        DOX(hash_memory(hash_idx, s->msg, s->msg_l, buf, &buflen), s->name);
        DOX(rsa_sign_hash(buf, buflen, obuf, &obuflen, NULL, prng_idx, hash_idx, s->salt_l, key), s->name);
        DOX(memcmp(s->sig, obuf, s->sig_l)==0?CRYPT_OK:CRYPT_FAIL_TESTVECTOR, s->name);
        DOX(rsa_verify_hash(obuf, obuflen, buf, buflen, hash_idx, s->salt_l, &stat, key), s->name);
    } /* for */

    mp_clear_multi(key->d,  key->e, key->N, key->dQ, key->dP, key->qP, key->p, key->q, NULL);
  } /* for */

  unregister_prng(&no_prng_desc);

  return 0;
}

#else

int pkcs_1_pss_test(void)
{
   fprintf(stderr, "NOP");
   return 0;
}

#endif


/* $Source$ */
/* $Revision$ */
/* $Date$ */
