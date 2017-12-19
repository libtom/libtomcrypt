/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include <tomcrypt_test.h>

#if defined(LTC_MECC)

static unsigned int sizes[] = {
#ifdef LTC_ECC_SECP112R1
14,
#endif
#ifdef LTC_ECC_SECP128R1
16,
#endif
#ifdef LTC_ECC_SECP160R1
20,
#endif
#ifdef LTC_ECC_SECP192R1
24,
#endif
#ifdef LTC_ECC_SECP224R1
28,
#endif
#ifdef LTC_ECC_SECP256R1
32,
#endif
#ifdef LTC_ECC_SECP384R1
48,
#endif
#ifdef LTC_ECC_SECP512R1
66
#endif
};

#ifdef LTC_ECC_SHAMIR
static int _ecc_test_shamir(void)
{
   void *a, *modulus, *mp, *kA, *kB, *rA, *rB;
   void *mu, *ma;
   ecc_point *G, *A, *B, *C1, *C2;
   int x, y, z;
   unsigned char buf[ECC_BUF_SIZE];

   DO(mp_init_multi(&kA, &kB, &rA, &rB, &modulus, &a, &mu, &ma, NULL));
   LTC_ARGCHK((G  = ltc_ecc_new_point()) != NULL);
   LTC_ARGCHK((A  = ltc_ecc_new_point()) != NULL);
   LTC_ARGCHK((B  = ltc_ecc_new_point()) != NULL);
   LTC_ARGCHK((C1 = ltc_ecc_new_point()) != NULL);
   LTC_ARGCHK((C2 = ltc_ecc_new_point()) != NULL);

   for (x = 0; x < (int)(sizeof(sizes)/sizeof(sizes[0])); x++) {
       /* get the base point */
       for (z = 0; ltc_ecc_curves[z].prime != NULL; z++) {
           DO(mp_read_radix(modulus, ltc_ecc_curves[z].prime, 16));
           if (sizes[x] <= mp_unsigned_bin_size(modulus)) break;
       }
       LTC_ARGCHK(ltc_ecc_curves[z].prime != NULL);

       /* load it */
       DO(mp_read_radix(G->x, ltc_ecc_curves[z].Gx, 16));
       DO(mp_read_radix(G->y, ltc_ecc_curves[z].Gy, 16));
       DO(mp_set(G->z, 1));
       DO(mp_read_radix(a, ltc_ecc_curves[z].A, 16));
       DO(mp_montgomery_setup(modulus, &mp));
       DO(mp_montgomery_normalization(mu, modulus));
       DO(mp_mulmod(a, mu, modulus, ma));

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
          DO(ltc_mp.ecc_mul2add(A, kA, B, kB, C2, ma, modulus));

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
  mp_clear_multi(kA, kB, rA, rB, modulus, a, mu, ma, NULL);
  return 0;
}
#endif

static int _ecc_issue108(void)
{
   void      *a, *modulus, *order;
   ecc_point *Q, *Result;
   int       err;
   const ltc_ecc_curve* dp;

   /* init */
   if ((err = mp_init_multi(&modulus, &order, &a, NULL)) != CRYPT_OK) { return err; }
   Q      = ltc_ecc_new_point();
   Result = ltc_ecc_new_point();

   /* ECC-224 AKA SECP224R1 */
   if ((err = ecc_get_curve("SECP224R1", &dp)) != CRYPT_OK)               { goto done; }
   /* read A */
   if ((err = mp_read_radix(a, (char *)dp->A,  16)) != CRYPT_OK)          { goto done; }
   /* read modulus */
   if ((err = mp_read_radix(modulus, (char *)dp->prime, 16)) != CRYPT_OK) { goto done; }
   /* read order */
   if ((err = mp_read_radix(order, (char *)dp->order, 16)) != CRYPT_OK)   { goto done; }
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

   for (i = 0; ltc_ecc_curves[i].prime != NULL; i++) {
      if ((err = mp_read_radix(a, (char *)ltc_ecc_curves[i].A,  16)) != CRYPT_OK)            { goto done; }
      if ((err = mp_read_radix(modulus, (char *)ltc_ecc_curves[i].prime, 16)) != CRYPT_OK)   { goto done; }
      if ((err = mp_read_radix(order, (char *)ltc_ecc_curves[i].order, 16)) != CRYPT_OK)     { goto done; }

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

      if ((err = mp_read_radix(G->x, (char *)ltc_ecc_curves[i].Gx, 16)) != CRYPT_OK)       { goto done; }
      if ((err = mp_read_radix(G->y, (char *)ltc_ecc_curves[i].Gy, 16)) != CRYPT_OK)       { goto done; }
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

int _ecc_old_api(void)
{
   unsigned char buf[4][4096], ch;
   unsigned long x, y, z, s;
   int           stat, stat2;
   ecc_key usera, userb, pubKey, privKey;
   int low, high;

   ecc_sizes(&low, &high);
   if (low < 14 || high < 14 || low > 100 || high > 100 || high < low) return CRYPT_FAIL_TESTVECTOR;

   for (s = 0; s < (sizeof(sizes)/sizeof(sizes[0])); s++) {
      /* make up two keys */
      DO(ecc_make_key (&yarrow_prng, find_prng ("yarrow"), sizes[s], &usera));
      DO(ecc_make_key (&yarrow_prng, find_prng ("yarrow"), sizes[s], &userb));
      if (ecc_get_size(&usera) != (int)sizes[s]) return CRYPT_FAIL_TESTVECTOR;
      if (ecc_get_size(&userb) != (int)sizes[s]) return CRYPT_FAIL_TESTVECTOR;

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
   return CRYPT_OK;
}

int _ecc_new_api(void)
{
   const char* names[] = {
#ifdef LTC_ECC_SECP112R1
      "SECP112R1", "ECC-112",
      "secp112r1",              /* name is case-insensitive */
      "S E C-P-1_1_2r1",        /* should pass fuzzy matching */
#endif
#ifdef LTC_ECC_SECP112R2
      "SECP112R2",
#endif
#ifdef LTC_ECC_SECP128R1
      "SECP128R1", "ECC-128",
#endif
#ifdef LTC_ECC_SECP128R2
      "SECP128R2",
#endif
#ifdef LTC_ECC_SECP160R1
      "SECP160R1", "ECC-160",
#endif
#ifdef LTC_ECC_SECP160R2
      "SECP160R2",
#endif
#ifdef LTC_ECC_SECP160K1
      "SECP160K1",
#endif
#ifdef LTC_ECC_BRAINPOOLP160R1
      "BRAINPOOLP160R1",
#endif
#ifdef LTC_ECC_SECP192R1
      "SECP192R1", "NISTP192", "PRIME192V1", "ECC-192", "P-192",
#endif
#ifdef LTC_ECC_PRIME192V2
      "PRIME192V2",
#endif
#ifdef LTC_ECC_PRIME192V3
      "PRIME192V3",
#endif
#ifdef LTC_ECC_SECP192K1
      "SECP192K1",
#endif
#ifdef LTC_ECC_BRAINPOOLP192R1
      "BRAINPOOLP192R1",
#endif
#ifdef LTC_ECC_SECP224R1
      "SECP224R1", "NISTP224", "ECC-224", "P-224",
#endif
#ifdef LTC_ECC_SECP224K1
      "SECP224K1",
#endif
#ifdef LTC_ECC_BRAINPOOLP224R1
      "BRAINPOOLP224R1",
#endif
#ifdef LTC_ECC_PRIME239V1
      "PRIME239V1",
#endif
#ifdef LTC_ECC_PRIME239V2
      "PRIME239V2",
#endif
#ifdef LTC_ECC_PRIME239V3
      "PRIME239V3",
#endif
#ifdef LTC_ECC_SECP256R1
      "SECP256R1", "NISTP256", "PRIME256V1", "ECC-256", "P-256",
#endif
#ifdef LTC_ECC_SECP256K1
      "SECP256K1",
#endif
#ifdef LTC_ECC_BRAINPOOLP256R1
      "BRAINPOOLP256R1",
#endif
#ifdef LTC_ECC_BRAINPOOLP320R1
      "BRAINPOOLP320R1",
#endif
#ifdef LTC_ECC_SECP384R1
      "SECP384R1", "NISTP384", "ECC-384", "P-384",
#endif
#ifdef LTC_ECC_BRAINPOOLP384R1
      "BRAINPOOLP384R1",
#endif
#ifdef LTC_ECC_BRAINPOOLP512R1
      "BRAINPOOLP512R1",
#endif
#ifdef LTC_ECC_SECP521R1
      "SECP521R1", "NISTP521", "ECC-521", "P-521",
#endif
   };
   int i, j, stat;
   const ltc_ecc_curve* dp;
   ecc_key key, privkey, pubkey;
   unsigned char buf[1000];
   unsigned long len;
   unsigned char data16[16] = { 0xd1, 0xd1, 0xd1, 0xd1, 0xd1, 0xd1, 0xd1, 0xd1, 0xd1, 0xd1, 0xd1, 0xd1, 0xd1, 0xd1, 0xd1, 0xd1 };
   unsigned long len16;

   if (ltc_mp.name == NULL) return CRYPT_NOP;

   for (i = 0; i < (int)(sizeof(names)/sizeof(names[0])); i++) {
      DO(ecc_get_curve(names[i], &dp));
      /* make new key */
      DO(ecc_make_key_ex(&yarrow_prng, find_prng ("yarrow"), &key, dp));
      len = sizeof(buf);
      DO(ecc_export(buf, &len, PK_PRIVATE, &key));
      DO(ecc_import_ex(buf, len, &privkey, dp));
      ecc_free(&privkey);
      len = sizeof(buf);
      DO(ecc_export(buf, &len, PK_PUBLIC, &key));
      DO(ecc_import_ex(buf, len, &pubkey, dp));
      ecc_free(&pubkey);
      len = sizeof(buf);
      DO(ecc_ansi_x963_export(&key, buf, &len));
      ecc_free(&key);
      DO(ecc_ansi_x963_import_ex(buf, len, &pubkey, dp));
      ecc_free(&pubkey);

      /* generate new key */
      DO(ecc_set_dp(dp, &key));
      DO(ecc_generate_key(&yarrow_prng, find_prng ("yarrow"), &key));
      len = sizeof(buf);
      DO(ecc_get_key(buf, &len, PK_PRIVATE, &key));
      ecc_free(&key);

      /* load exported private key */
      DO(ecc_set_dp(dp, &privkey));
      DO(ecc_set_key(buf, len, PK_PRIVATE, &privkey));

#ifndef USE_TFM
      /* XXX-FIXME: TFM does not support sqrtmod_prime */
      /* export compressed public key */
      len = sizeof(buf);
      DO(ecc_get_key(buf, &len, PK_PUBLIC|PK_COMPRESSED, &privkey));
      if (len != 1 + (unsigned)ecc_get_size(&privkey)) return CRYPT_FAIL_TESTVECTOR;
      /* load exported public+compressed key */
      DO(ecc_set_dp(dp, &pubkey));
      DO(ecc_set_key(buf, len, PK_PUBLIC, &pubkey));
      ecc_free(&pubkey);
#endif

      /* export long public key */
      len = sizeof(buf);
      DO(ecc_get_key(buf, &len, PK_PUBLIC, &privkey));
      if (len != 1 + 2 * (unsigned)ecc_get_size(&privkey)) return CRYPT_FAIL_TESTVECTOR;
      /* load exported public key */
      DO(ecc_set_dp(dp, &pubkey));
      DO(ecc_set_key(buf, len, PK_PUBLIC, &pubkey));

      /* test signature */
      len = sizeof(buf);
      DO(ecc_sign_hash(data16, 16, buf, &len, &yarrow_prng, find_prng ("yarrow"), &privkey));
      stat = 0;
      DO(ecc_verify_hash(buf, len, data16, 16, &stat, &pubkey));
      if (stat != 1) return CRYPT_FAIL_TESTVECTOR;

      /* test encryption */
      len = sizeof(buf);
      DO(ecc_encrypt_key(data16, 16, buf, &len, &yarrow_prng, find_prng("yarrow"), find_hash("sha256"), &pubkey));
      zeromem(data16, 16);
      len16 = 16;
      DO(ecc_decrypt_key(buf, len, data16, &len16, &privkey));
      if (len16 != 16) return CRYPT_FAIL_TESTVECTOR;
      for (j = 0; j < 16; j++) if (data16[j] != 0xd1) return CRYPT_FAIL_TESTVECTOR;

      /* cleanup */
      ecc_free(&privkey);
      ecc_free(&pubkey);
   }
   return CRYPT_OK;
}

int ecc_tests(void)
{
   DO(_ecc_old_api()); /* up to 1.18 */
   DO(_ecc_new_api());
   DO(_ecc_test_mp());
   DO(_ecc_issue108());
#ifdef LTC_ECC_SHAMIR
   DO(_ecc_test_shamir());
#endif
   return CRYPT_OK;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
