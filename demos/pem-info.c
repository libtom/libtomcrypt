/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
/* print all PEM related infos */
#include "tomcrypt_private.h"

#if defined(LTC_PEM_SSH)
extern const struct blockcipher_info pem_dek_infos[];
extern const unsigned long pem_dek_infos_num;

extern const struct blockcipher_info ssh_ciphers[];
extern const unsigned long ssh_ciphers_num;

static const struct {
   const char *is, *should;
} cipher_name_map[] = {
   { "", "none" },
   { "aes", "AES" },
   { "blowfish", "Blowfish" },
   { "c20p1305", "ChaCha20Poly1305" },
   { "camellia", "Camellia" },
   { "cast5", "CAST5" },
   { "chacha20", "ChaCha20" },
   { "3des", "3DES (EDE)" },
   { "des", "DES" },
   { "desx", "DES-X" },
   { "idea", "IDEA" },
   { "rc5", "RC5" },
   { "rc2", "RC2" },
   { "seed", "SEED" },
   { "serpent", "Serpent" },
   { "twofish", "Twofish" },
};

static const char *s_map_cipher(const char *name)
{
   unsigned long n;
   for (n = 0; n < sizeof(cipher_name_map)/sizeof(cipher_name_map[0]); ++n) {
      if (strcmp(name, cipher_name_map[n].is) == 0)
         return cipher_name_map[n].should;
   }
   fprintf(stderr, "Error: Can't map %s\n", name);
   exit(1);
}

static const struct {
   enum cipher_mode mode;
   const char *name;
} cipher_mode_map[] = {
   { cm_none,   "none",   },
   { cm_cbc,    "CBC",    },
   { cm_cfb,    "CFB",    },
   { cm_ctr,    "CTR",    },
   { cm_ofb,    "OFB",    },
   { cm_stream, "STREAM", },
   { cm_gcm,    "GCM",    },
};

static const char *s_map_mode(enum cipher_mode mode)
{
   size_t n;
   mode &= cm_modes;
   for (n = 0; n < sizeof(cipher_mode_map)/sizeof(cipher_mode_map[0]); ++n) {
      if (cipher_mode_map[n].mode == mode)
         return cipher_mode_map[n].name;
   }
   fprintf(stderr, "Error: Can't map cipher_mode %d\n", mode);
   exit(1);
}

int main(void)
{
   unsigned long n;
   printf("PEM ciphers:\n\n");
   for (n = 0; n < pem_dek_infos_num; ++n) {
      char nbuf[32] = {0};
      size_t nlen = strlen(pem_dek_infos[n].name);
      memcpy(nbuf, pem_dek_infos[n].name, nlen);
      nbuf[nlen-1] = '}';
      printf("\\hline \\texttt{%-18s & %-15s & %-25ld & %-6s \\\\\n",
                               nbuf, s_map_cipher(pem_dek_infos[n].algo),
                                              pem_dek_infos[n].keylen * 8,
                                                       s_map_mode(pem_dek_infos[n].mode));
   }

   printf("\nSSH ciphers:\n\n");
   for (n = 0; n < ssh_ciphers_num; ++n) {
      char nbuf[32] = {0};
      size_t nlen = strlen(ssh_ciphers[n].name);
      memcpy(nbuf, ssh_ciphers[n].name, nlen);
      nbuf[nlen] = '}';
      printf("\\hline \\texttt{%-30s & %-16s & %-24ld & %-6s \\\\\n",
                               nbuf, s_map_cipher(ssh_ciphers[n].algo),
                               ssh_ciphers[n].keylen * 8,
                                                       s_map_mode(ssh_ciphers[n].mode));
   }

   return 0;
}
#else
int main(void) { return EXIT_FAILURE; }
#endif
