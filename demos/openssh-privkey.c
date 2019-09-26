/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/**
  @file openssh-privkey.c
  OpenSSH Private Key decryption demo, Steffen Jaeckel
*/

#include <bsd/string.h>
#include <tomcrypt.h>
#include <stdarg.h>

static int verbose = 1;

static void print_hex(const char* what, const void* v, const unsigned long l)
{
  const unsigned char* p = v;
  unsigned long x, y = 0, z;

  if (!verbose) return;

  fprintf(stderr, "%s contents: \n", what);
  for (x = 0; x < l; ) {
      fprintf(stderr, "%02X ", p[x]);
      if (!(++x % 16) || x == l) {
         if((x % 16) != 0) {
            z = 16 - (x % 16);
            if(z >= 8)
               fprintf(stderr, " ");
            for (; z != 0; --z) {
               fprintf(stderr, "   ");
            }
         }
         fprintf(stderr, " | ");
         for(; y < x; y++) {
            if((y % 8) == 0)
               fprintf(stderr, " ");
            if(isgraph(p[y]))
               fprintf(stderr, "%c", p[y]);
            else
               fprintf(stderr, ".");
         }
         fprintf(stderr, "\n");
      }
      else if((x % 8) == 0) {
         fprintf(stderr, " ");
      }
  }
}

static void print_err(const char *fmt, ...)
{
   va_list args;

   if (!verbose) return;

   va_start(args, fmt);
   vfprintf(stderr, fmt, args);
}

static void die_(int err, int line)
{
   print_err("%3d: LTC sez %s\n", line, error_to_string(err));
   exit(EXIT_FAILURE);
}

#define die(i) do { die_(i, __LINE__); } while(0)
#define DIE(s) do { print_err("%3d: " s "\n", __LINE__); exit(EXIT_FAILURE); } while(0)


enum blockcipher_mode {
   none, cbc, ctr, stream, gcm
};
struct ssh_blockcipher {
   const char *name;
   const char *cipher;
   int len;
   enum blockcipher_mode mode;
};

/* Table as of
 * https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-17
 */
const struct ssh_blockcipher ssh_ciphers[] =
{
   { "aes256-cbc", "aes", 256 / 8, cbc },
   { 0 },
};


struct ssh_decode_ctx {
   unsigned char *orig;
   size_t len, rd;
   void *cur;
};

ulong32 read_length_and_advance(int is_length, struct ssh_decode_ctx *ctx) {
   ulong32 r;
   ctx->cur = &ctx->orig[ctx->rd];

   LOAD32H(r, ctx->cur);
   print_err("%u\n", r);
   if (is_length && ctx->rd + r > ctx->len) DIE("too long");
   ctx->rd += 4;

   ctx->cur = &ctx->orig[ctx->rd];
   if (is_length) print_hex("next", ctx->cur, r);
   return r;
}

/* The basic format of the key is described here:
 * https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
 */

int main(int argc, char **argv)
{
   if (argc < 2) return EXIT_FAILURE;

   int err;
   if ((err = register_all_ciphers()) != CRYPT_OK) {
      die(err);
   }
   if ((err = register_all_hashes()) != CRYPT_OK) {
      die(err);
   }

   char pem[100 * 72];
   size_t w = 0;
   const char *b64_start = "-----BEGIN OPENSSH PRIVATE KEY-----";
   const char *b64_end = "-----END OPENSSH PRIVATE KEY-----";
   char buf[72];
   FILE *f = fopen(argv[1], "r");
   if (f == NULL) DIE("fopen sez no");
   while (fgets(buf, sizeof(buf), f)) {
      const char *start = strstr(buf, b64_start);
      if (start == buf) break;
   }
   while (fgets(buf, sizeof(buf), f)) {
      char *end = strstr(buf, b64_end);
      if (end != NULL) {
         if (end == buf) break;
         *end = '\0';
      }
      size_t l = strlcpy(pem + w, buf, sizeof(pem) - w);
      if (l == 0) {
         DIE("strlcpy sez no");
      }
      w += l;
   }

   unsigned char b64_decoded[sizeof(pem)];
   unsigned long b64_decoded_len = sizeof(pem);
   if ((err = base64_sane_decode(pem, w, b64_decoded, &b64_decoded_len)) != CRYPT_OK) {
      die(err);
   }
   print_hex("decoded", b64_decoded, b64_decoded_len);

   void *magic = strstr((const char*)b64_decoded, "openssh-key-v1");
   if (magic == NULL) DIE("magic not found");
   if (magic != b64_decoded) DIE("magic not at the beginning");
   struct ssh_decode_ctx dec_ctx;
   dec_ctx.orig = b64_decoded;
   dec_ctx.len = b64_decoded_len;
   dec_ctx.rd = strlen("openssh-key-v1") + 1;

   ulong32 l = read_length_and_advance(1, &dec_ctx);

   const struct ssh_blockcipher *c = NULL;
   for (size_t i = 0; i < sizeof(ssh_ciphers)/sizeof(ssh_ciphers[0]); ++i) {
      if (memcmp(dec_ctx.cur, ssh_ciphers[i].name, l) == 0) {
         c = &ssh_ciphers[i];
         break;
      }
   }
   if (c == NULL) DIE("can't find cipher");
   dec_ctx.rd += l;

   l = read_length_and_advance(1, &dec_ctx);

   if (memcmp(dec_ctx.cur, "bcrypt", l) != 0)  DIE("unsupported kdf");
   dec_ctx.rd += l;

   l = read_length_and_advance(1, &dec_ctx);

   unsigned char salt[32];
   unsigned long salt_len = read_length_and_advance(1, &dec_ctx);

   memcpy(salt, dec_ctx.cur, salt_len);
   dec_ctx.rd += salt_len;

   ulong32 rounds = read_length_and_advance(0, &dec_ctx);

   ulong32 num_pubkeys = read_length_and_advance(1, &dec_ctx);

   l = read_length_and_advance(1, &dec_ctx);
   l = read_length_and_advance(1, &dec_ctx);
   if (memcmp(dec_ctx.cur, "ssh-ed25519", l) != 0)  DIE("unsupported pka");
   dec_ctx.rd += l;

   unsigned char pubkey[32];
   unsigned long pubkey_len = read_length_and_advance(1, &dec_ctx);

   memcpy(pubkey, dec_ctx.cur, pubkey_len);
   dec_ctx.rd += pubkey_len;

   l = read_length_and_advance(1, &dec_ctx);

   unsigned char decrypted_privkey[sizeof(pem)];
   unsigned long decrypted_privkey_len = sizeof(decrypted_privkey);

   int cipher = find_cipher(c->cipher);

   unsigned char symkey[128];
   unsigned long symkey_len = c->len + cipher_descriptor[cipher].block_length;

   if (sizeof(symkey) < symkey_len) DIE("too small");

   if ((err = bcrypt("abc123", 6, salt, salt_len, rounds, find_hash("sha512"), symkey, &symkey_len)) != CRYPT_OK) {
      die(err);
   }

   symmetric_CBC cbc_ctx;
   if ((err = cbc_start(cipher, symkey + c->len, symkey, c->len, 0, &cbc_ctx)) != CRYPT_OK) {
      die(err);
   }
   if ((err = cbc_decrypt(dec_ctx.cur, decrypted_privkey, l, &cbc_ctx)) != CRYPT_OK) {
      die(err);
   }
   decrypted_privkey_len = l;
   print_hex("decrypted", decrypted_privkey, decrypted_privkey_len);

   dec_ctx.orig = decrypted_privkey;
   dec_ctx.len = decrypted_privkey_len;
   dec_ctx.rd = 0;

   ulong32 check1 = read_length_and_advance(0, &dec_ctx);
   ulong32 check2 = read_length_and_advance(0, &dec_ctx);

   if (check1 != check2) DIE("decrypt failed");

   l = read_length_and_advance(1, &dec_ctx);
   if (memcmp(dec_ctx.cur, "ssh-ed25519", l) != 0)  DIE("unsupported pka");
   dec_ctx.rd += l;

   l = read_length_and_advance(1, &dec_ctx);
   if (memcmp(dec_ctx.cur, pubkey, l) != 0)  DIE("pubkey's don't match");
   dec_ctx.rd += l;

   unsigned char privkey[64];
   unsigned long privkey_len = read_length_and_advance(1, &dec_ctx);

   memcpy(privkey, dec_ctx.cur, privkey_len);

   if (memcmp(&privkey[32], pubkey, 32) != 0)  DIE("pubkey in privkey doesn't match");

   curve25519_key k;
   if ((err = ed25519_set_key(privkey, 32, &privkey[32], 32, &k)) != CRYPT_OK) {
      die(err);
   }

   return EXIT_SUCCESS;
}

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
