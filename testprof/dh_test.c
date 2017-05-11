#include <tomcrypt_test.h>

#ifdef LTC_MDH

#ifdef DH4096
#define KEYSIZE 4096
#else
#define KEYSIZE 2048
#endif

int dh_test (void)
{
  unsigned char buf[3][4096], ch;
  unsigned long x, y, z;
  int           stat, stat2;
  dh_key        usera, userb;

   if (register_prng(&yarrow_desc) == -1) {
      printf("Error registering yarrow PRNG\n");
      exit(-1);
   }
   if (register_hash(&md5_desc) == -1) {
      printf("Error registering md5 hash\n");
      exit(-1);
   }

  DO(dh_compat_test());


  /* make up two keys */
  DO(dh_make_key (&yarrow_prng, find_prng ("yarrow"), KEYSIZE/8, &usera));
  DO(dh_make_key (&yarrow_prng, find_prng ("yarrow"), KEYSIZE/8, &userb));

  /* make the shared secret */
  x = KEYSIZE;
  DO(dh_shared_secret (&usera, &userb, buf[0], &x));

  y = KEYSIZE;
  DO(dh_shared_secret (&userb, &usera, buf[1], &y));
  if (y != x) {
    fprintf(stderr, "DH Shared keys are not same size.\n");
    dh_free (&usera);
    dh_free (&userb);
    return 1;
  }
  if (memcmp (buf[0], buf[1], x)) {
    fprintf(stderr, "DH Shared keys not same contents.\n");
    dh_free (&usera);
    dh_free (&userb);
    return 1;
  }

  /* now export userb */
  y = KEYSIZE;
  DO(dh_export (buf[1], &y, PK_PUBLIC, &userb));
  dh_free (&userb);

  /* import and make the shared secret again */
  DO(dh_import (buf[1], y, &userb));
  z = KEYSIZE;
  DO(dh_shared_secret (&usera, &userb, buf[2], &z));

  dh_free (&usera);
  dh_free (&userb);

  if (z != x) {
    fprintf(stderr, "failed.  Size don't match?\n");
    return 1;
  }
  if (memcmp (buf[0], buf[2], x)) {
    fprintf(stderr, "Failed.  Content didn't match.\n");
    return 1;
  }

/* test encrypt_key */
  dh_make_key (&yarrow_prng, find_prng ("yarrow"), KEYSIZE/8, &usera);
  for (ch = 0; ch < 16; ch++) {
    buf[0][ch] = ch;
  }
  y = sizeof (buf[1]);
  DO(dh_encrypt_key (buf[0], 16, buf[1], &y, &yarrow_prng, find_prng ("yarrow"), find_hash ("md5"), &usera));
  zeromem (buf[0], sizeof (buf[0]));
  x = sizeof (buf[0]);
  DO(dh_decrypt_key (buf[1], y, buf[0], &x, &usera));
  if (x != 16) {
    fprintf(stderr, "Failed (length)\n");
    dh_free (&usera);
    return 1;
  }
  for (ch = 0; ch < 16; ch++)
    if (buf[0][ch] != ch) {
      fprintf(stderr, "Failed (contents)\n");
      dh_free (&usera);
      return 1;
    }

/* test sign_hash */
  for (ch = 0; ch < 16; ch++) {
     buf[0][ch] = ch;
  }
  x = sizeof (buf[1]);
  DO(dh_sign_hash (buf[0], 16, buf[1], &x, &yarrow_prng, find_prng ("yarrow"), &usera));
  DO(dh_verify_hash (buf[1], x, buf[0], 16, &stat, &usera));
  buf[0][0] ^= 1;
  DO(dh_verify_hash (buf[1], x, buf[0], 16, &stat2, &usera));
  dh_free (&usera);
  if (!(stat == 1 && stat2 == 0)) {
     fprintf(stderr, "dh_sign/verify_hash %d %d", stat, stat2);
     return 1;
  }
  return 0;
}
#else

int dh_test(void)
{
   return CRYPT_NOP;
}

#endif
