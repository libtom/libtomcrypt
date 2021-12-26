/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/**
  @file openssh-privkey.c
  OpenSSH Private Key decryption demo, Steffen Jaeckel
*/

#include <tomcrypt.h>
#include <stdarg.h>

static int verbose = 0;

static void print_err(const char *fmt, ...)
{
   va_list args;

   if (!verbose) return;

   va_start(args, fmt);
   vfprintf(stderr, fmt, args);
}

static void die_(int err, int line)
{
   verbose = 1;
   print_err("%3d: LTC sez %s\n", line, error_to_string(err));
   exit(EXIT_FAILURE);
}

#define die(i) do { die_(i, __LINE__); } while(0)
#define DIE(s, ...) do { verbose = 1; print_err("%3d: " s "\n", __LINE__, ##__VA_ARGS__); exit(EXIT_FAILURE); } while(0)

static int password_get(void **p, unsigned long *l, void *u)
{
   (void)u;
   *p = strdup("abc123");
   *l = strlen(*p);
   return 0;
}

int main(int argc, char **argv)
{
   int err;

   FILE *f = NULL;
   ltc_pka_key k;
   password_ctx pw_ctx = { .callback = password_get };

   if ((err = register_all_ciphers()) != CRYPT_OK) {
      die(err);
   }
   if ((err = register_all_hashes()) != CRYPT_OK) {
      die(err);
   }
   if ((err = crypt_mp_init("ltm")) != CRYPT_OK) {
      die(err);
   }

   if (argc > 1) f = fopen(argv[1], "r");
   else f = stdin;
   if (f == NULL) DIE("fopen sez no");

   if ((err = pem_decode_openssh_filehandle(f, &k, &pw_ctx))) {
      die(err);
   }
   return EXIT_SUCCESS;
}

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
