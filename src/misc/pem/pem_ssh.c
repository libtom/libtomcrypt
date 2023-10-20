/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file pem_ssh.c
  SSH specific functionality to process PEM files, Steffen Jaeckel

  The basic format of the key is described here:
  https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
*/

#if defined(LTC_PEM_SSH)

/* Table as of
 * https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-17
 */
const struct blockcipher_info ssh_ciphers[] =
{
   { .name = "none",            .algo = "",         .keylen = 0,       .mode = cm_none },
   { .name = "aes128-cbc",      .algo = "aes",      .keylen = 128 / 8, .mode = cm_cbc  },
   { .name = "aes128-ctr",      .algo = "aes",      .keylen = 128 / 8, .mode = cm_ctr  },
   { .name = "aes192-cbc",      .algo = "aes",      .keylen = 192 / 8, .mode = cm_cbc  },
   { .name = "aes192-ctr",      .algo = "aes",      .keylen = 192 / 8, .mode = cm_ctr  },
   { .name = "aes256-cbc",      .algo = "aes",      .keylen = 256 / 8, .mode = cm_cbc  },
   { .name = "aes256-ctr",      .algo = "aes",      .keylen = 256 / 8, .mode = cm_ctr  },
   { .name = "blowfish128-cbc", .algo = "blowfish", .keylen = 128 / 8, .mode = cm_cbc  },
   { .name = "blowfish128-ctr", .algo = "blowfish", .keylen = 128 / 8, .mode = cm_ctr  },
   { .name = "des-cbc",         .algo = "des",      .keylen = 64 / 8,  .mode = cm_cbc  },
   { .name = "3des-cbc",        .algo = "3des",     .keylen = 192 / 8, .mode = cm_cbc  },
   { .name = "3des-ctr",        .algo = "3des",     .keylen = 192 / 8, .mode = cm_ctr  },
   { .name = "serpent128-cbc",  .algo = "serpent",  .keylen = 128 / 8, .mode = cm_cbc  },
   { .name = "serpent128-ctr",  .algo = "serpent",  .keylen = 128 / 8, .mode = cm_ctr  },
   { .name = "serpent192-cbc",  .algo = "serpent",  .keylen = 192 / 8, .mode = cm_cbc  },
   { .name = "serpent192-ctr",  .algo = "serpent",  .keylen = 192 / 8, .mode = cm_ctr  },
   { .name = "serpent256-cbc",  .algo = "serpent",  .keylen = 256 / 8, .mode = cm_cbc  },
   { .name = "serpent256-ctr",  .algo = "serpent",  .keylen = 256 / 8, .mode = cm_ctr  },
   { .name = "twofish128-cbc",  .algo = "twofish",  .keylen = 128 / 8, .mode = cm_cbc  },
   { .name = "twofish128-ctr",  .algo = "twofish",  .keylen = 128 / 8, .mode = cm_ctr  },
   { .name = "twofish192-cbc",  .algo = "twofish",  .keylen = 192 / 8, .mode = cm_cbc  },
   { .name = "twofish192-ctr",  .algo = "twofish",  .keylen = 192 / 8, .mode = cm_ctr  },
   { .name = "twofish-cbc",     .algo = "twofish",  .keylen = 256 / 8, .mode = cm_cbc  },
   { .name = "twofish256-cbc",  .algo = "twofish",  .keylen = 256 / 8, .mode = cm_cbc  },
   { .name = "twofish256-ctr",  .algo = "twofish",  .keylen = 256 / 8, .mode = cm_ctr  },
};

struct kdf_options {
   const char *name;
   const struct blockcipher_info *cipher;
   unsigned char salt[64];
   ulong32 saltlen;
   ulong32 num_rounds;
   struct password pw;
};

#ifdef LTC_MECC
static int s_ssh_find_init_ecc(const char *pka, ltc_pka_key *key)
{
   int err;
   const char* prefix = "ecdsa-sha2-";
   unsigned long prefixlen = XSTRLEN(prefix);
   const ltc_ecc_curve *cu;
   if (strstr(pka, prefix) == NULL) return CRYPT_PK_INVALID_TYPE;
   if ((err = ecc_find_curve(pka + prefixlen, &cu)) != CRYPT_OK) return err;
   return ecc_set_curve(cu, &key->u.ecc);
}

static int s_ssh_decode_ecdsa(const unsigned char *in, unsigned long *inlen, ltc_pka_key *pka_key, enum pem_flags type)
{
   int err;
   unsigned char groupname[64], buf0[512], buf1[512];
   unsigned long groupnamelen = sizeof(groupname), buf0len = sizeof(buf0), buf1len = sizeof(buf1);
   unsigned long remaining, cur_len, keylen;
   const unsigned char *p, *key;

   p = in;
   cur_len = *inlen;
   remaining = *inlen;

   err = ssh_decode_sequence_multi(p, &cur_len,
                                     LTC_SSHDATA_STRING, groupname, &groupnamelen,
                                     LTC_SSHDATA_STRING, buf0, &buf0len,
                                     LTC_SSHDATA_STRING, buf1, &buf1len,
                                     LTC_SSHDATA_EOL,    NULL);
   if (err == CRYPT_OK) {
      key = buf1;
      keylen = buf1len;
   } else if (err == CRYPT_BUFFER_OVERFLOW && buf0len != sizeof(buf0) && buf1len == sizeof(buf1)) {
      key = buf0;
      keylen = buf0len;
   } else {
      goto cleanup;
   }

   remaining -= cur_len;
   cur_len = remaining;

   err = ecc_set_key(key, keylen, type == pf_public ? PK_PUBLIC : PK_PRIVATE, &pka_key->u.ecc);

cleanup:
   zeromem(groupname, sizeof(groupname));
   zeromem(buf0, sizeof(buf0));
   zeromem(buf1, sizeof(buf1));
   if (err == CRYPT_OK) {
      pka_key->id = LTC_PKA_EC;
      *inlen -= remaining;
   }

   return err;
}
#endif

#ifdef LTC_CURVE25519
static int s_ssh_decode_ed25519(const unsigned char *in, unsigned long *inlen, ltc_pka_key *key, enum pem_flags type)
{
   int err;
   unsigned char pubkey[64], privkey[96];
   unsigned long pubkeylen = sizeof(pubkey), privkeylen = sizeof(privkey);
   unsigned long remaining, cur_len;
   const unsigned char *p;

   p = in;
   cur_len = *inlen;
   remaining = *inlen;

   if ((err = ssh_decode_sequence_multi(p, &cur_len,
                                        LTC_SSHDATA_STRING, pubkey, &pubkeylen,
                                        LTC_SSHDATA_EOL,    NULL)) != CRYPT_OK) {
      goto cleanup;
   }

   if (type == pf_public) {
      if ((err = ed25519_import_raw(pubkey, pubkeylen, PK_PUBLIC, &key->u.ed25519)) != CRYPT_OK) {
         goto cleanup;
      }
      key->id = LTC_PKA_ED25519;
      goto cleanup;
   }

   p += cur_len;
   remaining -= cur_len;
   cur_len = remaining;

   if ((err = ssh_decode_sequence_multi(p, &cur_len,
                                        LTC_SSHDATA_STRING, privkey, &privkeylen,
                                        LTC_SSHDATA_EOL,    NULL)) != CRYPT_OK) {
      goto cleanup;
   }
   if ((err = ed25519_import_raw(privkey, privkeylen, PK_PRIVATE, &key->u.ed25519)) != CRYPT_OK) {
      goto cleanup;
   }

   key->id = LTC_PKA_ED25519;

cleanup:
   zeromem(pubkey, sizeof(pubkey));
   zeromem(privkey, sizeof(privkey));
   if (err == CRYPT_OK) {
      remaining -= cur_len;
      *inlen -= remaining;
   }

   return err;
}
#endif

#ifdef LTC_MRSA
static int s_ssh_decode_dsa(const unsigned char *in, unsigned long *inlen, ltc_pka_key *key, enum pem_flags type)
{
   int err, stat;
   unsigned long remaining, cur_len;
   const unsigned char *p;
   if ((err = dsa_int_init(&key->u.dsa)) != CRYPT_OK) {
      return err;
   }

   p = in;
   cur_len = *inlen;
   remaining = *inlen;

   if ((err = ssh_decode_sequence_multi(p, &cur_len,
                                        LTC_SSHDATA_MPINT, key->u.dsa.p,
                                        LTC_SSHDATA_MPINT, key->u.dsa.q,
                                        LTC_SSHDATA_MPINT, key->u.dsa.g,
                                        LTC_SSHDATA_MPINT, key->u.dsa.y,
                                        LTC_SSHDATA_EOL,    NULL)) != CRYPT_OK) {
      goto cleanup;
   }
   key->u.dsa.qord = mp_unsigned_bin_size(key->u.dsa.q);
   if ((err = dsa_int_validate_pqg(&key->u.dsa, &stat)) != CRYPT_OK) {
      goto cleanup;
   }
   if (stat == 0) {
      err = CRYPT_INVALID_PACKET;
      goto cleanup;
   }

   if (type == pf_public) {
      key->id = LTC_PKA_DSA;
      key->u.dsa.type = PK_PUBLIC;
      goto cleanup;
   }

   p += cur_len;
   remaining -= cur_len;
   cur_len = remaining;

   if ((err = ssh_decode_sequence_multi(p, &cur_len,
                                        LTC_SSHDATA_MPINT, key->u.dsa.x,
                                        LTC_SSHDATA_EOL,    NULL)) != CRYPT_OK) {
      goto cleanup;
   }

   key->id = LTC_PKA_DSA;
   key->u.dsa.type = PK_PRIVATE;

cleanup:
   if (err != CRYPT_OK) {
      dsa_free(&key->u.dsa);
   } else {
      remaining -= cur_len;
      *inlen -= remaining;
   }

   return err;

}
#endif

#ifdef LTC_MRSA
static int s_ssh_decode_rsa(const unsigned char *in, unsigned long *inlen, ltc_pka_key *key, enum pem_flags type)
{
   int err;
   void *tmp1, *tmp2;
   unsigned long remaining, cur_len;
   const unsigned char *p;

   if ((err = rsa_init(&key->u.rsa)) != CRYPT_OK) {
      return err;
   }

   p = in;
   cur_len = *inlen;
   remaining = *inlen;

   /* ssh-rsa public and private keys contain `e` and `N` in a different order
    * public contains `e`, then `N`
    * private contains `N`, then `e`
    * change the order later on if we import a public key */
   if ((err = ssh_decode_sequence_multi(p, &cur_len,
                                        LTC_SSHDATA_MPINT, key->u.rsa.N,
                                        LTC_SSHDATA_MPINT, key->u.rsa.e,
                                        LTC_SSHDATA_EOL,    NULL)) != CRYPT_OK) {
      goto cleanup;
   }

   p += cur_len;
   remaining -= cur_len;
   cur_len = remaining;

   if (type == pf_public) {
      /* c.f. comment above */
      void *exch = key->u.rsa.N;
      key->u.rsa.N = key->u.rsa.e;
      key->u.rsa.e = exch;
      key->id = LTC_PKA_RSA;
      key->u.rsa.type = PK_PUBLIC;
      *inlen -= remaining;
      goto cleanup;
   }

   if ((err = mp_init_multi(&tmp1, &tmp2, NULL)) != CRYPT_OK) {
      goto cleanup;
   }

   if ((err = ssh_decode_sequence_multi(p, &cur_len,
                                        LTC_SSHDATA_MPINT, key->u.rsa.d,
                                        LTC_SSHDATA_MPINT, key->u.rsa.qP,
                                        LTC_SSHDATA_MPINT, key->u.rsa.p,
                                        LTC_SSHDATA_MPINT, key->u.rsa.q,
                                        LTC_SSHDATA_EOL,    NULL)) != CRYPT_OK) {
      goto cleanup_tmps;
   }

   if ((err = mp_sub_d(key->u.rsa.p, 1, tmp1)) != CRYPT_OK)                   { goto cleanup_tmps; } /* tmp1 = q-1 */
   if ((err = mp_sub_d(key->u.rsa.q, 1, tmp2)) != CRYPT_OK)                   { goto cleanup_tmps; } /* tmp2 = p-1 */
   if ((err = mp_mod(key->u.rsa.d, tmp1, key->u.rsa.dP)) != CRYPT_OK)         { goto cleanup_tmps; } /* dP = d mod p-1 */
   if ((err = mp_mod(key->u.rsa.d, tmp2, key->u.rsa.dQ)) != CRYPT_OK)         { goto cleanup_tmps; } /* dQ = d mod q-1 */

   key->id = LTC_PKA_RSA;
   key->u.rsa.type = PK_PRIVATE;

cleanup_tmps:
   mp_clear_multi(tmp2, tmp1, NULL);
cleanup:
   if (err != CRYPT_OK) {
      rsa_free(&key->u.rsa);
   } else {
      remaining -= cur_len;
      *inlen -= remaining;
   }

   return err;
}
#endif

struct ssh_pka {
   const char *name;
   int (*init)(const char*, ltc_pka_key*);
   int (*decode)(const unsigned char*, unsigned long*, ltc_pka_key*, enum pem_flags);
};

struct ssh_pka ssh_pkas[] = {
#ifdef LTC_CURVE25519
                             { "ssh-ed25519", NULL,                s_ssh_decode_ed25519 },
#endif
#ifdef LTC_MRSA
                             { "ssh-rsa",     NULL,                s_ssh_decode_rsa },
#endif
#ifdef LTC_MDSA
                             { "ssh-dss",     NULL,                s_ssh_decode_dsa },
#endif
#ifdef LTC_MECC
                             { NULL,          s_ssh_find_init_ecc, s_ssh_decode_ecdsa },
#endif
};

static int s_decode_key(const unsigned char *in, unsigned long *inlen, ltc_pka_key *key, enum pem_flags type)
{
   int err;
   ulong32 check1, check2;
   unsigned char pka[64], comment[256];
   unsigned long pkalen = sizeof(pka), commentlen = sizeof(comment);
   unsigned long remaining, cur_len;
   const unsigned char *p;
   unsigned long n;

   LTC_ARGCHK(in    != NULL);
   LTC_ARGCHK(inlen != NULL);
   LTC_ARGCHK(key   != NULL);

   p = in;
   cur_len = *inlen;
   remaining = *inlen;

   if (type != pf_public) {
      if ((err = ssh_decode_sequence_multi(p, &cur_len,
                                           LTC_SSHDATA_UINT32, &check1,
                                           LTC_SSHDATA_UINT32, &check2,
                                           LTC_SSHDATA_EOL,    NULL)) != CRYPT_OK) {
         return err;
      }
      if (check1 != check2) {
         return CRYPT_INVALID_PACKET;
      }

      p += cur_len;
      remaining -= cur_len;
      cur_len = remaining;
   }
   if ((err = ssh_decode_sequence_multi(p, &cur_len,
                                        LTC_SSHDATA_STRING, pka, &pkalen,
                                        LTC_SSHDATA_EOL,    NULL)) != CRYPT_OK) {
      return err;
   }

   p += cur_len;
   remaining -= cur_len;
   cur_len = remaining;

   for (n = 0; n < sizeof(ssh_pkas)/sizeof(ssh_pkas[0]); ++n) {
      if (ssh_pkas[n].name != NULL) {
         if (XSTRCMP((char*)pka, ssh_pkas[n].name) != 0) continue;
      } else {
         if ((ssh_pkas[n].init == NULL) ||
               (ssh_pkas[n].init((char*)pka, key) != CRYPT_OK)) continue;
      }
      if ((err = ssh_pkas[n].decode(p, &cur_len, key, type)) != CRYPT_OK) {
         return err;
      }
      break;
   }
   if (n == sizeof(ssh_pkas)/sizeof(ssh_pkas[0])) {
      return CRYPT_PK_INVALID_TYPE;
   }

   p += cur_len;
   remaining -= cur_len;
   cur_len = remaining;

   if (cur_len != 0) {
      if ((err = ssh_decode_sequence_multi(p, &cur_len,
                                           LTC_SSHDATA_STRING, comment, &commentlen,
                                           LTC_SSHDATA_EOL,    NULL)) != CRYPT_OK) {
         return err;
      }
   }

   p += cur_len;
   remaining -= cur_len;

   return remaining ? padding_depad(p, &remaining, LTC_PAD_SSH) : CRYPT_OK;
}

static int s_decrypt_private_keys(unsigned char *in, unsigned long *inlen, struct kdf_options *opts)
{
   int err, cipher;
   unsigned long symkey_len;
   unsigned char symkey[MAXBLOCKSIZE];

   LTC_ARGCHK(in    != NULL);
   LTC_ARGCHK(inlen != NULL);
   LTC_ARGCHK(opts  != NULL);

   cipher = find_cipher(opts->cipher->algo);
   if (cipher == -1) {
      return CRYPT_INVALID_CIPHER;
   }
   symkey_len = opts->cipher->keylen + cipher_descriptor[cipher].block_length;

   if (sizeof(symkey) < symkey_len) {
      return CRYPT_OVERFLOW;
   }

   if ((err = bcrypt_pbkdf_openbsd(opts->pw.pw, opts->pw.l, opts->salt, opts->saltlen,
                                   opts->num_rounds, find_hash("sha512"), symkey, &symkey_len)) != CRYPT_OK) {
      return err;
   }

   err = pem_decrypt(in, inlen,
                     symkey, opts->cipher->keylen,
                     symkey + opts->cipher->keylen, cipher_descriptor[cipher].block_length,
                     opts->cipher, LTC_PAD_SSH);

   zeromem(symkey, sizeof(symkey));

   return err;
}

static int s_decode_header(unsigned char *in, unsigned long *inlen, struct kdf_options *opts)
{
   int err;
   unsigned char ciphername[64], kdfname[64], kdfoptions[128], pubkey1[2048];
   unsigned long ciphernamelen = sizeof(ciphername), kdfnamelen = sizeof(kdfname);
   unsigned long kdfoptionslen = sizeof(kdfoptions), pubkey1len = sizeof(pubkey1);
   ulong32 num_keys;
   unsigned long i;

   void *magic = strstr((const char*)in, "openssh-key-v1");
   unsigned long slen = XSTRLEN("openssh-key-v1");
   unsigned char *start = &in[slen + 1];
   unsigned long len = *inlen - slen - 1;

   if (magic == NULL || magic != in) {
      return CRYPT_INVALID_PACKET;
   }

   if ((err = ssh_decode_sequence_multi(start, &len,
                                        LTC_SSHDATA_STRING, ciphername, &ciphernamelen,
                                        LTC_SSHDATA_STRING, kdfname, &kdfnamelen,
                                        LTC_SSHDATA_STRING, kdfoptions, &kdfoptionslen,
                                        LTC_SSHDATA_UINT32, &num_keys,
                                        LTC_SSHDATA_STRING, pubkey1, &pubkey1len,
                                        LTC_SSHDATA_EOL,    NULL)) != CRYPT_OK) {
      return err;
   }
   if (num_keys != 1) {
      return CRYPT_INVALID_PACKET;
   }

   *inlen = len + slen + 1;

   for (i = 0; i < sizeof(ssh_ciphers)/sizeof(ssh_ciphers[0]); ++i) {
      if (XSTRCMP((char*)ciphername, ssh_ciphers[i].name) == 0) {
         opts->cipher = &ssh_ciphers[i];
         break;
      }
   }
   if (opts->cipher == NULL) {
      return CRYPT_INVALID_CIPHER;
   }

   if (XSTRCMP((char*)kdfname, "none") == 0) {
      /* NOP */
      opts->name = "none";
   } else if (XSTRCMP((char*)kdfname, "bcrypt") == 0) {
      opts->name = "bcrypt";
      opts->saltlen = sizeof(opts->salt);
      len = kdfoptionslen;
      if ((err = ssh_decode_sequence_multi(kdfoptions, &len,
                                           LTC_SSHDATA_STRING, opts->salt, &opts->saltlen,
                                           LTC_SSHDATA_UINT32, &opts->num_rounds,
                                           LTC_SSHDATA_EOL,    NULL)) != CRYPT_OK) {
         return err;
      }
      if (len != kdfoptionslen) {
         return CRYPT_INPUT_TOO_LONG;
      }
   } else {
      return CRYPT_INVALID_PACKET;
   }

   return err;
}


static const struct pem_header_id pem_openssh[] = {
   {
     SET_CSTR(.start, "-----BEGIN OPENSSH PRIVATE KEY-----"),
     SET_CSTR(.end, "-----END OPENSSH PRIVATE KEY-----"),
     .has_more_headers = no
   },
   {
     SET_CSTR(.start, "---- BEGIN SSH2 PUBLIC KEY ----"),
     SET_CSTR(.end, "---- END SSH2 PUBLIC KEY ----"),
     .has_more_headers = maybe,
     .flags = pf_public
   },
};
static const unsigned long pem_openssh_num = sizeof(pem_openssh)/sizeof(pem_openssh[0]);

static int s_decode_openssh(struct get_char *g, ltc_pka_key *k, const password_ctx *pw_ctx)
{
   unsigned char *pem = NULL, *p, *privkey = NULL;
   unsigned long n, w, l, privkey_len;
   int err;
   struct pem_headers hdr;
   struct kdf_options opts = { 0 };
   XMEMSET(k, 0, sizeof(*k));
   w = LTC_PEM_READ_BUFSIZE * 2;
retry:
   pem = XREALLOC(pem, w);
   for (n = 0; n < pem_openssh_num; ++n) {
      hdr.id = &pem_openssh[n];
      err = pem_read(pem, &w, &hdr, g);
      if (err == CRYPT_BUFFER_OVERFLOW) {
         goto retry;
      } else if (err == CRYPT_OK) {
         break;
      } else if (err != CRYPT_UNKNOWN_PEM) {
         goto cleanup;
      }
      hdr.id = NULL;
   }
   /* id not found */
   if (hdr.id == NULL) {
      goto cleanup;
   }
   p = pem;
   l = w;
   if (hdr.id->flags != pf_public) {
      if ((err = s_decode_header(pem, &w, &opts)) != CRYPT_OK) {
         goto cleanup;
      }
      p = pem + w;
      l -= w;
      w = l;

      privkey_len = l;
      privkey = XMALLOC(privkey_len);

      if ((err = ssh_decode_sequence_multi(p, &w,
                                           LTC_SSHDATA_STRING, privkey, &privkey_len,
                                           LTC_SSHDATA_EOL,    NULL)) != CRYPT_OK) {
         goto cleanup;
      }

      if (XSTRCMP(opts.name, "none") != 0) {
         if ((pw_ctx == NULL) || (pw_ctx->callback == NULL)) {
            err = CRYPT_PW_CTX_MISSING;
            goto cleanup;
         }
         if (pw_ctx->callback(&opts.pw.pw, &opts.pw.l, pw_ctx->userdata)) {
            err = CRYPT_ERROR;
            goto cleanup;
         }
         w = privkey_len;
         if ((err = s_decrypt_private_keys(privkey, &privkey_len, &opts)) != CRYPT_OK) {
            goto cleanup;
         }
         zeromem(opts.pw.pw, opts.pw.l);
      }

      p = privkey;
      w = privkey_len;
   }
   if ((err = s_decode_key(p, &w, k, hdr.id->flags)) != CRYPT_OK) {
      goto cleanup;
   }

cleanup:
   password_free(&opts.pw, pw_ctx);
   if (privkey) {
      zeromem(privkey, privkey_len);
      XFREE(privkey);
   }
   XFREE(pem);
   return err;
}

#ifndef LTC_NO_FILE
int pem_decode_openssh_filehandle(FILE *f, ltc_pka_key *k, const password_ctx *pw_ctx)
{
   LTC_ARGCHK(f != NULL);
   LTC_ARGCHK(k != NULL);
   {
      struct get_char g = { .get = pem_get_char_from_file, .f = f };
      return s_decode_openssh(&g, k, pw_ctx);
   }
}
#endif /* LTC_NO_FILE */

int pem_decode_openssh(const void *buf, unsigned long len, ltc_pka_key *k, const password_ctx *pw_ctx)
{
   LTC_ARGCHK(buf != NULL);
   LTC_ARGCHK(len != 0);
   LTC_ARGCHK(k != NULL);
   {
      struct get_char g = { .get = pem_get_char_from_buf, SET_BUFP(.buf, buf, len) };
      return s_decode_openssh(&g, k, pw_ctx);
   }
}

#endif /* defined(LTC_PEM_SSH) */
