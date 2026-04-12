/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include <tomcrypt_test.h>

/**
  @file common.c

  Steffen Jaeckel
*/

LTC_NOP_TEST(nop_test)

void run_cmd(int res, int line, const char *file, const char *cmd, const char *algorithm)
{
   if (res != CRYPT_OK) {
#ifdef LTC_NO_TEST
      if (res == CRYPT_NOP)
         return;
#endif
      fprintf(stderr, "%s (%d)%s%s\n%s:%d:%s\n",
              error_to_string(res), res,
              (algorithm ? " - " : ""), (algorithm ? algorithm : ""),
              file, line, cmd);
      if (res != CRYPT_NOP) {
         exit(EXIT_FAILURE);
      }
   }
}

/* Read one DER tag+length, hdr is the size of the header, len the size of the value */
static int s_der_tlv(const unsigned char *p, unsigned long avail, unsigned long *hdr, unsigned long *len)
{
   unsigned long l, n, i;

   if (avail < 2) return CRYPT_INVALID_PACKET;
   l = p[1];
   if ((l & 0x80) == 0) {
      *hdr = 2;
      *len = l;
   } else {
      n = l & 0x7f;
      if (n == 0 || n > 4 || avail < 2 + n) return CRYPT_INVALID_PACKET;
      for (l = 0, i = 0; i < n; ++i) l = (l << 8) | p[2 + i];
      *hdr = 2 + n;
      *len = l;
   }
   if (*len > avail - *hdr) return CRYPT_INVALID_PACKET;

   return CRYPT_OK;
}

void print_hex(const char* what, const void* v, const unsigned long l)
{
  const unsigned char* p = v;
  unsigned long x, y = 0, z;
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

#ifdef LTC_TEST_READDIR

#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

static off_t fsize(const char *filename)
{
   struct stat st;

   if (stat(filename, &st) == 0) {
      if (S_ISDIR(st.st_mode))
         return -2;
      /* filename is no regular file */
      if (!S_ISREG(st.st_mode))
         return 0;
      return st.st_size;
   }

   return -1;
}
static DIR *s_opendir(const char *path, char *mypath, unsigned long l)
{
#ifdef CMAKE_SOURCE_DIR
#define SOURCE_PREFIX CMAKE_SOURCE_DIR "/"
#else
#define SOURCE_PREFIX ""
#endif
   DIR *d = NULL;
   int r = snprintf(mypath, l, "%s%s", SOURCE_PREFIX, path);
   if (r > 0 && (unsigned int)r < l) {
      d = opendir(mypath);
   }

   return d;
}

static int s_read_and_process(FILE *f, unsigned long sz, void *ctx, dir_iter_cb process)
{
   int err = CRYPT_OK;
   void* buf;
   if (f == NULL)
      return CRYPT_FILE_NOTFOUND;
   buf = XMALLOC(sz + 1);
   if (buf == NULL)
      return CRYPT_MEM;
   if (fread(buf, 1, sz, f) != sz) {
      err = CRYPT_ERROR;
      goto out;
   }
   ((unsigned char *)buf)[sz] = 0x0;
   err = process(buf, sz, ctx);
out:
   XFREE(buf);
   return err;
}

int test_process_dir(const char *path, void *ctx, dir_iter_cb iter, dir_fiter_cb fiter, dir_cleanup_cb cleanup, const char *test)
{
   char mypath[PATH_MAX];
   DIR *d = s_opendir(path, mypath, sizeof(mypath));
   struct dirent *de;
   char fname[PATH_MAX];
   FILE *f = NULL;
   off_t fsz;
   int err = CRYPT_FILE_NOTFOUND;
   if (d == NULL)
      return CRYPT_FILE_NOTFOUND;
   while((de = readdir(d)) != NULL) {
      fname[0] = '\0';
      if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0 || strcmp(de->d_name, "README.txt") == 0)
         continue;
      strcat(fname, mypath);
      strcat(fname, "/");
      strcat(fname, de->d_name);
      fsz = fsize(fname);
      if (fsz == -2)
         continue;
      if (fsz == -1) {
         err = CRYPT_FILE_NOTFOUND;
         break;
      }
#if defined(LTC_TEST_DBG) && LTC_TEST_DBG > 1
      fprintf(stderr, "%s: Try to process %s\n", test, fname);
#endif
      f = fopen(fname, "rb");

      if (iter) {
         err = s_read_and_process(f, fsz, ctx, iter);
      } else if (fiter) {
         err = fiter(f, ctx);
      } else {
         err = CRYPT_NOP;
#if defined(LTC_TEST_DBG) && LTC_TEST_DBG > 1
         fprintf(stderr, "%s: No call-back set for %s\n", test, fname);
#endif
      }

      if (err == CRYPT_NOP) {
#if defined(LTC_TEST_DBG) && LTC_TEST_DBG > 1
         fprintf(stderr, "%s: Skip: %s\n", test, fname);
#endif
         err = CRYPT_OK;
         goto continue_loop;
      } else if (err != CRYPT_OK) {
#if defined(LTC_TEST_DBG)
         fprintf(stderr, "%s: Test %s failed (cause: %s).\n\n", test, fname, error_to_string(err));
#else
         LTC_UNUSED_PARAM(test);
#endif
         break;
      }
      if (cleanup != NULL) {
         cleanup(ctx);
      }

continue_loop:
      if (f != NULL) fclose(f);
      f = NULL;
   }
   if (f != NULL) fclose(f);
   closedir(d);
   return err;
}
#endif

#ifdef LTC_BASE64
/**
   Decode the body of the first PEM block in a buffer

   @param pem      The PEM encoded data
   @param pemlen   The length of the PEM encoded data
   @param label    The expected PEM label, e.g. "CERTIFICATE"
   @param der      [out] Where to store the decoded data
   @param derlen   [in/out] The size of der resp. the length of the decoded data
   @return CRYPT_OK on success, CRYPT_NOP if the block carries a different label
*/
int test_pem_to_der(const void *pem, unsigned long pemlen, const char *label, unsigned char *der, unsigned long *derlen)
{
   const char *p = pem, *stop = p + pemlen, *line;
   char *b64;
   unsigned long b64len = 0, linelen, labellen = XSTRLEN(label);
   int err = CRYPT_INVALID_PACKET, in_body = 0;

   b64 = XMALLOC(pemlen + 1);
   if (b64 == NULL) return CRYPT_MEM;

   while (p < stop) {
      line = p;
      while (p < stop && *p != '\n' && *p != '\r') ++p;
      linelen = (unsigned long)(p - line);
      if (linelen >= 11 && XMEMCMP(line, "-----BEGIN ", 11) == 0) {
         if (linelen < 11 + labellen || XMEMCMP(line + 11, label, labellen) != 0) {
            err = CRYPT_NOP;
            goto out;
         }
         in_body = 1;
      } else if (linelen >= 8 && XMEMCMP(line, "-----END", 8) == 0) {
         break;
      } else if (in_body) {
         XMEMCPY(b64 + b64len, line, linelen);
         b64len += linelen;
      }
      while (p < stop && (*p == '\n' || *p == '\r')) ++p;
   }
   if (in_body) err = base64_decode(b64, b64len, der, derlen);

out:
   XFREE(b64);
   return err;
}
#endif

/**
   Locate the signed part and the signature of a DER encoded X.509 certificate

   Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }

   @param der      The DER encoded certificate
   @param derlen   The length of the certificate
   @param tbs      [out] The tbsCertificate, tag and length included as that is what gets signed
   @param tbslen   [out] The length of the tbsCertificate
   @param sig      [out] The signature
   @param siglen   [out] The length of the signature
   @return CRYPT_OK on success
*/
int test_x509_split(const unsigned char *der, unsigned long derlen,
                    const unsigned char **tbs, unsigned long *tbslen,
                    const unsigned char **sig, unsigned long *siglen)
{
   const unsigned char *p;
   unsigned long avail, hdr, len;
   int err;

   if ((err = s_der_tlv(der, derlen, &hdr, &len)) != CRYPT_OK) return err;
   if (der[0] != 0x30) return CRYPT_INVALID_PACKET;
   p = der + hdr;
   avail = len;

   if ((err = s_der_tlv(p, avail, &hdr, &len)) != CRYPT_OK) return err;
   if (p[0] != 0x30) return CRYPT_INVALID_PACKET;
   *tbs = p;
   *tbslen = hdr + len;
   p += hdr + len;
   avail -= hdr + len;

   /* skip signatureAlgorithm */
   if ((err = s_der_tlv(p, avail, &hdr, &len)) != CRYPT_OK) return err;
   p += hdr + len;
   avail -= hdr + len;

   if ((err = s_der_tlv(p, avail, &hdr, &len)) != CRYPT_OK) return err;
   /* a BIT STRING with no unused bits */
   if (p[0] != 0x03 || len < 1 || p[hdr] != 0) return CRYPT_INVALID_PACKET;
   *sig = p + hdr + 1;
   *siglen = len - 1;

   return CRYPT_OK;
}


prng_state yarrow_prng;
