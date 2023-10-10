/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/**
  @file openssh-privkey.c
  OpenSSH Private Key decryption demo, Steffen Jaeckel
*/

#include <tomcrypt.h>
#include <stdarg.h>
#include <termios.h>

#if defined(LTC_PEM_SSH)
static void print_err(const char *fmt, ...)
{
   va_list args;

   va_start(args, fmt);
   vfprintf(stderr, fmt, args);
   va_end(args);
}

static void die_(int err, int line)
{
   print_err("%3d: LTC sez %s\n", line, error_to_string(err));
   exit(EXIT_FAILURE);
}

#define die(i) do { die_(i, __LINE__); } while(0)
#define DIE(s, ...) do { print_err("%3d: " s "\n", __LINE__, ##__VA_ARGS__); exit(EXIT_FAILURE); } while(0)

static char* getpassword(const char *prompt, size_t maxlen)
{
   char *wr, *end, *pass = XCALLOC(1, maxlen + 1);
   struct termios tio;
   tcflag_t c_lflag;
   if (pass == NULL)
      return NULL;
   wr = pass;
   end = pass + maxlen;

   tcgetattr(0, &tio);
   c_lflag = tio.c_lflag;
   tio.c_lflag &= ~ECHO;
   tcsetattr(0, TCSANOW, &tio);

   printf("%s", prompt);
   fflush(stdout);
   while (pass < end) {
      int c = getchar();
      if (c == '\r' || c == '\n' || c == -1)
         break;
      *wr++ = c;
   }
   tio.c_lflag = c_lflag;
   tcsetattr(0, TCSAFLUSH, &tio);
   printf("\n");
   return pass;
}

static int password_get(void **p, unsigned long *l, void *u)
{
   (void)u;
   *p = getpassword("Enter passphrase: ", 256);
   *l = strlen(*p);
   return 0;
}

static void print(ltc_pka_key *k)
{
   int err = CRYPT_OK;
   unsigned char buf[256];
   unsigned long lbuf = sizeof(buf);
   char pubkey[256*4/3];
   unsigned long lpubkey = sizeof(pubkey);
   void *mpint = NULL;
   switch (k->id) {
      case LTC_PKA_ED25519:
         ltc_mp.init(&mpint);
         ltc_mp.unsigned_read(mpint, k->u.ed25519.pub, sizeof(k->u.ed25519.pub));
         if ((err = ssh_encode_sequence_multi(buf, &lbuf,
                                              LTC_SSHDATA_STRING, "ssh-ed25519", strlen("ssh-ed25519"),
                                              LTC_SSHDATA_MPINT, mpint,
                                              0, NULL)) != CRYPT_OK)
            goto errout;
         if ((err = base64_encode(buf, lbuf, pubkey, &lpubkey)) != CRYPT_OK)
            goto errout;
         printf("\rssh-ed25519 %s\n", pubkey);
         break;
      default:
         print_err("Unsupported key type: %d\n", k->id);
         break;
   }
errout:
   if (mpint != NULL)
      ltc_mp.deinit(mpint);
   if (err != CRYPT_OK)
      die(err);
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
   print(&k);
   return EXIT_SUCCESS;
}
#else
int main(void) { return EXIT_FAILURE; }
#endif
