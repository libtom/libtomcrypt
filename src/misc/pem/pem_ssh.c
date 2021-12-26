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

enum blockcipher_mode {
   none, cbc, ctr, stream, gcm
};
struct ssh_blockcipher {
   const char *name;
   const char *algo;
   int len;
   enum blockcipher_mode mode;
};

/* Table as of
 * https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-17
 */
const struct ssh_blockcipher ssh_ciphers[] =
{
   { "none", "", 0, none },
   { "aes256-cbc", "aes", 256 / 8, cbc },
   { 0 },
};

struct kdf_options {
   const char *name;
   const struct ssh_blockcipher *cipher;
   unsigned char salt[64];
   ulong32 saltlen;
   ulong32 num_rounds;
   struct password pw;
};

#ifdef LTC_MECC
int ssh_find_init_ecc(const char *pka, ltc_pka_key *key)
{
   int err;
   const char* prefix = "ecdsa-sha2-";
   unsigned long prefixlen = XSTRLEN(prefix);
   const ltc_ecc_curve *cu;
   if (strstr(pka, prefix) == NULL) return CRYPT_PK_INVALID_TYPE;
   if ((err = ecc_find_curve(pka + prefixlen, &cu)) != CRYPT_OK) return err;
   return ecc_set_curve(cu, &key->u.ecc);
}

int ssh_decode_ecdsa(const unsigned char *in, unsigned long *inlen, ltc_pka_key *key)
{
   int err;
   unsigned char groupname[64], group[512], privkey[512];
   unsigned long groupnamelen = sizeof(groupname), grouplen = sizeof(group), privkeylen = sizeof(privkey);

   if ((err = ssh_decode_sequence_multi(in, inlen,
                                        LTC_SSHDATA_STRING, groupname, &groupnamelen,
                                        LTC_SSHDATA_STRING, group, &grouplen,
                                        LTC_SSHDATA_STRING, privkey, &privkeylen,
                                        LTC_SSHDATA_EOL,    NULL)) != CRYPT_OK) {
      goto cleanup;
   }

   if ((err = ecc_set_key(privkey, privkeylen, PK_PRIVATE, &key->u.ecc)) != CRYPT_OK) {
      goto cleanup;
   }

   key->id = LTC_PKA_EC;

cleanup:
   zeromem(groupname, sizeof(groupname));
   zeromem(group, sizeof(group));
   zeromem(privkey, sizeof(privkey));

   return err;
}
#endif

#ifdef LTC_CURVE25519
int ssh_decode_ed25519(const unsigned char *in, unsigned long *inlen, ltc_pka_key *key)
{
   int err;
   unsigned char pubkey[2048], privkey[2048];
   unsigned long pubkeylen = sizeof(pubkey), privkeylen = sizeof(privkey);

   if ((err = ssh_decode_sequence_multi(in, inlen,
                                        LTC_SSHDATA_STRING, pubkey, &pubkeylen,
                                        LTC_SSHDATA_STRING, privkey, &privkeylen,
                                        LTC_SSHDATA_EOL,    NULL)) != CRYPT_OK) {
      goto cleanup;
   }

   if ((err = ed25519_import_raw(&privkey[32], 32, PK_PRIVATE, &key->u.curve25519)) != CRYPT_OK) {
      goto cleanup;
   }

   key->id = LTC_PKA_CURVE25519;

cleanup:
   zeromem(pubkey, sizeof(pubkey));
   zeromem(privkey, sizeof(privkey));

   return err;
}
#endif

#ifdef LTC_MRSA
int ssh_decode_rsa(const unsigned char *in, unsigned long *inlen, ltc_pka_key *key)
{
   int err;
   void *tmp1, *tmp2;
   if ((err = mp_init_multi(&tmp1, &tmp2, NULL)) != CRYPT_OK) {
      goto cleanup;
   }
   if ((err = rsa_init(&key->u.rsa)) != CRYPT_OK) {
      goto cleanup;
   }

   if ((err = ssh_decode_sequence_multi(in, inlen,
                                        LTC_SSHDATA_MPINT, key->u.rsa.N,
                                        LTC_SSHDATA_MPINT, key->u.rsa.e,
                                        LTC_SSHDATA_MPINT, key->u.rsa.d,
                                        LTC_SSHDATA_MPINT, key->u.rsa.qP,
                                        LTC_SSHDATA_MPINT, key->u.rsa.q,
                                        LTC_SSHDATA_MPINT, key->u.rsa.p,
                                        LTC_SSHDATA_EOL,    NULL)) != CRYPT_OK) {
      goto cleanup;
   }

   if ((err = mp_sub_d(key->u.rsa.p, 1,  tmp1)) != CRYPT_OK)                     { goto cleanup; } /* tmp1 = q-1 */
   if ((err = mp_sub_d(key->u.rsa.q, 1,  tmp2)) != CRYPT_OK)                     { goto cleanup; } /* tmp2 = p-1 */
   if ((err = mp_mod( key->u.rsa.d,  tmp1,  key->u.rsa.dP)) != CRYPT_OK)         { goto cleanup; } /* dP = d mod p-1 */
   if ((err = mp_mod( key->u.rsa.d,  tmp2,  key->u.rsa.dQ)) != CRYPT_OK)         { goto cleanup; } /* dQ = d mod q-1 */

   key->id = LTC_PKA_RSA;

cleanup:
   mp_clear_multi(tmp2, tmp1, NULL);

   return err;
}
#endif

struct ssh_pka {
   const char *name;
   int (*init)(const char*, ltc_pka_key*);
   int (*decode)(const unsigned char*, unsigned long*, ltc_pka_key*);
};

struct ssh_pka ssh_pkas[] = {
#ifdef LTC_CURVE25519
                             { "ssh-ed25519", NULL,              ssh_decode_ed25519 },
#endif
#ifdef LTC_MRSA
                             { "ssh-rsa",     NULL,              ssh_decode_rsa },
#endif
#ifdef LTC_MECC
                             { NULL,          ssh_find_init_ecc, ssh_decode_ecdsa },
#endif
};

static int s_decode_private_key(const unsigned char *in, unsigned long *inlen, ltc_pka_key *key)
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

   if ((err = ssh_decode_sequence_multi(p, &cur_len,
                                        LTC_SSHDATA_UINT32, &check1,
                                        LTC_SSHDATA_UINT32, &check2,
                                        LTC_SSHDATA_STRING, pka, &pkalen,
                                        LTC_SSHDATA_EOL,    NULL)) != CRYPT_OK) {
      return err;
   }
   if (check1 != check2) {
      return CRYPT_INVALID_PACKET;
   }

   p += cur_len;
   remaining = *inlen - cur_len;
   cur_len = remaining;

   for (n = 0; n < sizeof(ssh_pkas)/sizeof(ssh_pkas[0]); ++n) {
      if (ssh_pkas[n].name != NULL) {
         if (XSTRCMP((char*)pka, ssh_pkas[n].name) != 0) continue;
      } else {
         if ((ssh_pkas[n].init == NULL) ||
               (ssh_pkas[n].init((char*)pka, key) != CRYPT_OK)) continue;
      }
      if ((err = ssh_pkas[n].decode(p, &cur_len, key)) != CRYPT_OK) {
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

   if ((err = ssh_decode_sequence_multi(p, &cur_len,
                                        LTC_SSHDATA_STRING, comment, &commentlen,
                                        LTC_SSHDATA_EOL,    NULL)) != CRYPT_OK) {
      return err;
   }

   p += cur_len;
   remaining -= cur_len;

   return remaining ? padding_depad(p, &remaining, LTC_PAD_SSH) : CRYPT_OK;
}

static int s_decrypt_private_keys(unsigned char *in, unsigned long *inlen, struct kdf_options *opts)
{
   int err, cipher;
   unsigned char symkey[128];
   unsigned long symkey_len;
   symmetric_CBC cbc_ctx;

   LTC_ARGCHK(in    != NULL);
   LTC_ARGCHK(inlen != NULL);
   LTC_ARGCHK(opts  != NULL);

   cipher = find_cipher(opts->cipher->algo);
   if (cipher == -1) {
      return CRYPT_INVALID_CIPHER;
   }
   symkey_len = opts->cipher->len + cipher_descriptor[cipher].block_length;

   if (sizeof(symkey) < symkey_len) {
      return CRYPT_OVERFLOW;
   }

   if ((err = bcrypt_pbkdf_openbsd(opts->pw.pw, opts->pw.l, opts->salt, opts->saltlen, opts->num_rounds, find_hash("sha512"), symkey, &symkey_len)) != CRYPT_OK) {
      return err;
   }

   if ((err = cbc_start(cipher, symkey + opts->cipher->len, symkey, opts->cipher->len, 0, &cbc_ctx)) != CRYPT_OK) {
      goto cleanup;
   }
   if ((err = cbc_decrypt(in, in, *inlen, &cbc_ctx)) != CRYPT_OK) {
      goto cleanup;
   }
   if ((err = cbc_done(&cbc_ctx)) != CRYPT_OK) {
      goto cleanup;
   }

cleanup:
   zeromem(symkey, sizeof(symkey));
   zeromem(&cbc_ctx, sizeof(cbc_ctx));

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

static const struct pem_headers pem_openssh =
   {
     SET_CSTR(.start, "-----BEGIN OPENSSH PRIVATE KEY-----"),
     SET_CSTR(.end, "-----END OPENSSH PRIVATE KEY-----"),
     .has_more_headers = 0
   };

static int s_decode_openssh(struct get_char *g, ltc_pka_key *k, password_ctx *pw_ctx)
{
   unsigned char *pem = NULL, *p, *privkey = NULL;
   unsigned long w, l, privkey_len;
   int err;
   struct pem_headers hdr = pem_openssh;
   struct kdf_options opts = { 0 };
   w = LTC_PEM_READ_BUFSIZE * 2;
retry:
   pem = XREALLOC(pem, w);
   err = pem_read(pem, &w, &hdr, g);
   if (err == CRYPT_BUFFER_OVERFLOW) {
      goto retry;
   } else if (err != CRYPT_OK) {
      goto cleanup;
   }
   l = w;
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
      /* hard-coded pass for demo keys */
      if (!pw_ctx || !pw_ctx->callback) {
         err = CRYPT_INVALID_ARG;
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
   }

   w = privkey_len;
   if ((err = s_decode_private_key(privkey, &w, k)) != CRYPT_OK) {
      goto cleanup;
   }

cleanup:
   if (opts.pw.pw) {
      zeromem(opts.pw.pw, opts.pw.l);
      XFREE(opts.pw.pw);
   }
   if (privkey) {
      zeromem(privkey, privkey_len);
      XFREE(privkey);
   }
   XFREE(pem);
   return err;
}

int pem_decode_openssh_filehandle(FILE *f, ltc_pka_key *k, password_ctx *pw_ctx)
{
   struct get_char g = { .get = pem_get_char_from_file, .f = f };
   return s_decode_openssh(&g, k, pw_ctx);
}

int pem_decode_openssh(void *buf, unsigned long len, ltc_pka_key *k, password_ctx *pw_ctx)
{
   struct get_char g = { .get = pem_get_char_from_buf, SET_BUFP(.buf, buf, len) };
   return s_decode_openssh(&g, k, pw_ctx);
}

#endif /* defined(LTC_PEM_SSH) */
