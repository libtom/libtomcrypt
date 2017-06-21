/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include <tomcrypt_test.h>

#ifdef LTC_MECC

static unsigned int sizes[] = {
#ifdef LTC_ECC112
14,
#endif
#ifdef LTC_ECC128
16,
#endif
#ifdef LTC_ECC160
20,
#endif
#ifdef LTC_ECC192
24,
#endif
#ifdef LTC_ECC224
28,
#endif
#ifdef LTC_ECC256
32,
#endif
#ifdef LTC_ECC384
48,
#endif
#ifdef LTC_ECC521
65
#endif
};

#ifdef LTC_ECC_SHAMIR
static int _ecc_test_shamir(void)
{
   void *a, *modulus, *mp, *kA, *kB, *rA, *rB;
   ecc_point *G, *A, *B, *C1, *C2;
   int x, y, z;
   unsigned char buf[ECC_BUF_SIZE];

   DO(mp_init_multi(&kA, &kB, &rA, &rB, &modulus, &a, NULL));
   LTC_ARGCHK((G  = ltc_ecc_new_point()) != NULL);
   LTC_ARGCHK((A  = ltc_ecc_new_point()) != NULL);
   LTC_ARGCHK((B  = ltc_ecc_new_point()) != NULL);
   LTC_ARGCHK((C1 = ltc_ecc_new_point()) != NULL);
   LTC_ARGCHK((C2 = ltc_ecc_new_point()) != NULL);

   for (x = 0; x < (int)(sizeof(sizes)/sizeof(sizes[0])); x++) {
       /* get the base point */
       for (z = 0; ltc_ecc_sets[z].size > 0; z++) {
           if (sizes[x] <= (unsigned int)ltc_ecc_sets[z].size) break;
       }
       LTC_ARGCHK(ltc_ecc_sets[z].name != NULL);

       /* load it */
       DO(mp_read_radix(G->x, ltc_ecc_sets[z].Gx, 16));
       DO(mp_read_radix(G->y, ltc_ecc_sets[z].Gy, 16));
       DO(mp_set(G->z, 1));
       DO(mp_read_radix(modulus, ltc_ecc_sets[z].prime, 16));
       DO(mp_read_radix(a, ltc_ecc_sets[z].A, 16));
       DO(mp_montgomery_setup(modulus, &mp));

       /* do 100 random tests */
       for (y = 0; y < 100; y++) {
          /* pick a random r1, r2 */
          LTC_ARGCHK(yarrow_read(buf, sizes[x], &yarrow_prng) == sizes[x]);
          DO(mp_read_unsigned_bin(rA, buf, sizes[x]));
          LTC_ARGCHK(yarrow_read(buf, sizes[x], &yarrow_prng) == sizes[x]);
          DO(mp_read_unsigned_bin(rB, buf, sizes[x]));

          /* compute rA * G = A */
          DO(ltc_mp.ecc_ptmul(rA, G, A, a, modulus, 1));

          /* compute rB * G = B */
          DO(ltc_mp.ecc_ptmul(rB, G, B, a, modulus, 1));

          /* pick a random kA, kB */
          LTC_ARGCHK(yarrow_read(buf, sizes[x], &yarrow_prng) == sizes[x]);
          DO(mp_read_unsigned_bin(kA, buf, sizes[x]));
          LTC_ARGCHK(yarrow_read(buf, sizes[x], &yarrow_prng) == sizes[x]);
          DO(mp_read_unsigned_bin(kB, buf, sizes[x]));

          /* now, compute kA*A + kB*B = C1 using the older method */
          DO(ltc_mp.ecc_ptmul(kA, A, C1, a, modulus, 0));
          DO(ltc_mp.ecc_ptmul(kB, B, C2, a, modulus, 0));
          DO(ltc_mp.ecc_ptadd(C1, C2, C1, a, modulus, mp));
          DO(ltc_mp.ecc_map(C1, modulus, mp));

          /* now compute using mul2add */
          DO(ltc_mp.ecc_mul2add(A, kA, B, kB, C2, a, modulus));

          /* is they the sames?  */
          if ((mp_cmp(C1->x, C2->x) != LTC_MP_EQ) || (mp_cmp(C1->y, C2->y) != LTC_MP_EQ) || (mp_cmp(C1->z, C2->z) != LTC_MP_EQ)) {
             fprintf(stderr, "ECC failed shamir test: size=%d, testno=%d\n", sizes[x], y);
             return 1;
          }
      }
      mp_montgomery_free(mp);
  }
  ltc_ecc_del_point(C2);
  ltc_ecc_del_point(C1);
  ltc_ecc_del_point(B);
  ltc_ecc_del_point(A);
  ltc_ecc_del_point(G);
  mp_clear_multi(kA, kB, rA, rB, modulus, a, NULL);
  return 0;
}
#endif

static int _ecc_issue108(void)
{
   void      *a, *modulus, *order;
   ecc_point *Q, *Result;
   int       i, err;

   /* init */
   if ((err = mp_init_multi(&modulus, &order, &a, NULL)) != CRYPT_OK) { return err; }
   Q      = ltc_ecc_new_point();
   Result = ltc_ecc_new_point();

   /* ECC-224 */
   i = 13;
   /* read A */
   if ((err = mp_read_radix(a, (char *)ltc_ecc_sets[i].A,  16)) != CRYPT_OK)          { goto done; }
   /* read modulus */
   if ((err = mp_read_radix(modulus, (char *)ltc_ecc_sets[i].prime, 16)) != CRYPT_OK) { goto done; }
   /* read order */
   if ((err = mp_read_radix(order, (char *)ltc_ecc_sets[i].order, 16)) != CRYPT_OK)   { goto done; }
   /* read Q */
   if ((err = mp_read_radix(Q->x, (char *)"EA3745501BBC6A70BBFDD8AEEDB18CF5073C6DC9AA7CBB5915170D60", 16)) != CRYPT_OK) { goto done; }
   if ((err = mp_read_radix(Q->y, (char *)"6C9CB8E68AABFEC989CAC5E2326E0448B7E69C3E56039BA21A44FDAC", 16)) != CRYPT_OK) { goto done; }
   mp_set(Q->z, 1);
   /* calculate nQ */
   if ((err = ltc_mp.ecc_ptmul(order, Q, Result, a, modulus, 1)) != CRYPT_OK)  { goto done; }

done:
   ltc_ecc_del_point(Result);
   ltc_ecc_del_point(Q);
   mp_clear_multi(modulus, order, a, NULL);
   return err;
}

static int _ecc_test_mp(void)
{
   void       *a, *modulus, *order;
   ecc_point  *G, *GG;
   int        i, err, primality;

   if ((err = mp_init_multi(&modulus, &order, &a, NULL)) != CRYPT_OK) {
      return err;
   }

   G   = ltc_ecc_new_point();
   GG  = ltc_ecc_new_point();
   if (G == NULL || GG == NULL) {
      mp_clear_multi(modulus, order, NULL);
      ltc_ecc_del_point(G);
      ltc_ecc_del_point(GG);
      return CRYPT_MEM;
   }

   for (i = 0; ltc_ecc_sets[i].size; i++) {
      #if 0
         printf("Testing %d\n", ltc_ecc_sets[i].size);
      #endif
      if ((err = mp_read_radix(a, (char *)ltc_ecc_sets[i].A,  16)) != CRYPT_OK)            { goto done; }
      if ((err = mp_read_radix(modulus, (char *)ltc_ecc_sets[i].prime, 16)) != CRYPT_OK)   { goto done; }
      if ((err = mp_read_radix(order, (char *)ltc_ecc_sets[i].order, 16)) != CRYPT_OK)     { goto done; }

      /* is prime actually prime? */
      if ((err = mp_prime_is_prime(modulus, 8, &primality)) != CRYPT_OK)                   { goto done; }
      if (primality == 0) {
         err = CRYPT_FAIL_TESTVECTOR;
         goto done;
      }

      /* is order prime ? */
      if ((err = mp_prime_is_prime(order, 8, &primality)) != CRYPT_OK)                     { goto done; }
      if (primality == 0) {
         err = CRYPT_FAIL_TESTVECTOR;
         goto done;
      }

      if ((err = mp_read_radix(G->x, (char *)ltc_ecc_sets[i].Gx, 16)) != CRYPT_OK)         { goto done; }
      if ((err = mp_read_radix(G->y, (char *)ltc_ecc_sets[i].Gy, 16)) != CRYPT_OK)         { goto done; }
      mp_set(G->z, 1);

      /* then we should have G == (order + 1)G */
      if ((err = mp_add_d(order, 1, order)) != CRYPT_OK)                                   { goto done; }
      if ((err = ltc_mp.ecc_ptmul(order, G, GG, a, modulus, 1)) != CRYPT_OK)               { goto done; }
      if (mp_cmp(G->x, GG->x) != LTC_MP_EQ || mp_cmp(G->y, GG->y) != LTC_MP_EQ) {
         err = CRYPT_FAIL_TESTVECTOR;
         goto done;
      }
   }
   err = CRYPT_OK;
done:
   ltc_ecc_del_point(GG);
   ltc_ecc_del_point(G);
   mp_clear_multi(order, modulus, a, NULL);
   return err;
}

int ecc_tests(void)
{
  unsigned char buf[4][4096], ch;
  unsigned long x, y, z, s;
  int           stat, stat2;
  ecc_key usera, userb, pubKey, privKey;

  DO(_ecc_test_mp());
  DO(_ecc_issue108());

  for (s = 0; s < (sizeof(sizes)/sizeof(sizes[0])); s++) {
     /* make up two keys */
     DO(ecc_make_key (&yarrow_prng, find_prng ("yarrow"), sizes[s], &usera));
     DO(ecc_make_key (&yarrow_prng, find_prng ("yarrow"), sizes[s], &userb));

     /* make the shared secret */
     x = sizeof(buf[0]);
     DO(ecc_shared_secret (&usera, &userb, buf[0], &x));

     y = sizeof(buf[1]);
     DO(ecc_shared_secret (&userb, &usera, buf[1], &y));

     if (y != x) {
       fprintf(stderr, "ecc Shared keys are not same size.");
       return 1;
     }

     if (memcmp (buf[0], buf[1], x)) {
       fprintf(stderr, "ecc Shared keys not same contents.");
       return 1;
     }

     /* now export userb */
     y = sizeof(buf[0]);
     DO(ecc_export (buf[1], &y, PK_PUBLIC, &userb));
     ecc_free (&userb);

     /* import and make the shared secret again */
     DO(ecc_import (buf[1], y, &userb));

     z = sizeof(buf[0]);
     DO(ecc_shared_secret (&usera, &userb, buf[2], &z));

     if (z != x) {
       fprintf(stderr, "failed.  Size don't match?");
       return 1;
     }
     if (memcmp (buf[0], buf[2], x)) {
       fprintf(stderr, "Failed.  Contents didn't match.");
       return 1;
     }

     /* export with ANSI X9.63 */
     y = sizeof(buf[1]);
     DO(ecc_ansi_x963_export(&userb, buf[1], &y));
     ecc_free (&userb);

     /* now import the ANSI key */
     DO(ecc_ansi_x963_import(buf[1], y, &userb));

     /* shared secret */
     z = sizeof(buf[0]);
     DO(ecc_shared_secret (&usera, &userb, buf[2], &z));

     if (z != x) {
       fprintf(stderr, "failed.  Size don't match?");
       return 1;
     }
     if (memcmp (buf[0], buf[2], x)) {
       fprintf(stderr, "Failed.  Contents didn't match.");
       return 1;
     }

     ecc_free (&usera);
     ecc_free (&userb);

     /* test encrypt_key */
     DO(ecc_make_key (&yarrow_prng, find_prng ("yarrow"), sizes[s], &usera));

     /* export key */
     x = sizeof(buf[0]);
     DO(ecc_export(buf[0], &x, PK_PUBLIC, &usera));
     DO(ecc_import(buf[0], x, &pubKey));
     x = sizeof(buf[0]);
     DO(ecc_export(buf[0], &x, PK_PRIVATE, &usera));
     DO(ecc_import(buf[0], x, &privKey));

     for (ch = 0; ch < 32; ch++) {
        buf[0][ch] = ch;
     }
     y = sizeof (buf[1]);
     DO(ecc_encrypt_key (buf[0], 32, buf[1], &y, &yarrow_prng, find_prng ("yarrow"), find_hash ("sha256"), &pubKey));
     zeromem (buf[0], sizeof (buf[0]));
     x = sizeof (buf[0]);
     DO(ecc_decrypt_key (buf[1], y, buf[0], &x, &privKey));
     if (x != 32) {
       fprintf(stderr, "Failed (length)");
       return 1;
     }
     for (ch = 0; ch < 32; ch++) {
        if (buf[0][ch] != ch) {
           fprintf(stderr, "Failed (contents)");
           return 1;
        }
     }
     /* test sign_hash */
     for (ch = 0; ch < 16; ch++) {
        buf[0][ch] = ch;
     }
     x = sizeof (buf[1]);
     DO(ecc_sign_hash (buf[0], 16, buf[1], &x, &yarrow_prng, find_prng ("yarrow"), &privKey));
     DO(ecc_verify_hash (buf[1], x, buf[0], 16, &stat, &pubKey));
     buf[0][0] ^= 1;
     DO(ecc_verify_hash (buf[1], x, buf[0], 16, &stat2, &privKey));
     if (!(stat == 1 && stat2 == 0)) {
        fprintf(stderr, "ecc_verify_hash failed %d, %d, ", stat, stat2);
        return 1;
     }
     /* test sign_hash_rfc7518 */
     for (ch = 0; ch < 16; ch++) {
        buf[0][ch] = ch;
     }
     x = sizeof (buf[1]);
     DO(ecc_sign_hash_rfc7518(buf[0], 16, buf[1], &x, &yarrow_prng, find_prng ("yarrow"), &privKey));
     DO(ecc_verify_hash_rfc7518(buf[1], x, buf[0], 16, &stat, &pubKey));
     buf[0][0] ^= 1;
     DO(ecc_verify_hash_rfc7518(buf[1], x, buf[0], 16, &stat2, &privKey));
     if (!(stat == 1 && stat2 == 0)) {
        fprintf(stderr, "ecc_verify_hash_rfc7518 failed %d, %d, ", stat, stat2);
        return 1;
     }
     ecc_free (&usera);
     ecc_free (&pubKey);
     ecc_free (&privKey);
  }
#ifdef LTC_ECC_SHAMIR
  return _ecc_test_shamir();
#else
  return 0;
#endif
}

#else

int ecc_tests(void)
{
   return CRYPT_NOP;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
