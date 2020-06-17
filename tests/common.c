/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "common.h"

/**
  @file common.c

  Steffen Jaeckel
*/

void run_cmd(int res, int line, const char *file, const char *cmd, const char *algorithm)
{
   if (res != CRYPT_OK) {
      fprintf(stderr, "%s (%d)%s%s\n%s:%d:%s\n",
              error_to_string(res), res,
              (algorithm ? " - " : ""), (algorithm ? algorithm : ""),
              file, line, cmd);
      if (res != CRYPT_NOP) {
         exit(EXIT_FAILURE);
      }
   }
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

int do_compare_testvector(const void* is, const unsigned long is_len, const void* should, const unsigned long should_len, const char* what, int which)
{
   if (compare_testvector(is, is_len, should, should_len, what, which) == 0) {
      return CRYPT_OK;
   } else {
      return CRYPT_FAIL_TESTVECTOR;
   }
}


#ifdef LTC_TEST_READDIR

#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

static off_t fsize(const char *filename)
{
   struct stat st;

   if (stat(filename, &st) == 0) return st.st_size;

   return -1;
}

int test_process_dir(const char *path, void *ctx, dir_iter_cb process, dir_cleanup_cb cleanup, const char *test)
{
   DIR *d = opendir(path);
   struct dirent *de;
   char fname[PATH_MAX];
   void* buf = NULL;
   FILE *f = NULL;
   off_t fsz;
   unsigned long sz;
   int err = CRYPT_FILE_NOTFOUND;
   if (d == NULL)
      return CRYPT_FILE_NOTFOUND;
   while((de = readdir(d)) != NULL) {
      fname[0] = '\0';
      if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0 || strcmp(de->d_name, "README.txt") == 0)
         continue;
      strcat(fname, path);
      strcat(fname, "/");
      strcat(fname, de->d_name);
      fsz = fsize(fname);
      if (fsz == -1) {
         err = CRYPT_FILE_NOTFOUND;
         break;
      }
#if defined(LTC_TEST_DBG) && LTC_TEST_DBG > 1
      fprintf(stderr, "%s: Try to process %s\n", test, fname);
#endif
      f = fopen(fname, "rb");
      sz = fsz;
      buf = XMALLOC(fsz);
      if (fread(buf, 1, sz, f) != sz) {
         err = CRYPT_ERROR;
         break;
      }

      err = process(buf, sz, ctx);
      if (err == CRYPT_NOP) {
#if defined(LTC_TEST_DBG) && LTC_TEST_DBG > 1
         fprintf(stderr, "%s: Skip: %s\n", test, fname);
#endif
         break;
      } else if (err != CRYPT_OK) {
#if defined(LTC_TEST_DBG)
         fprintf(stderr, "%s: Test %s failed (cause: %s).\n\n", test, fname, error_to_string(err));
#else
         LTC_UNUSED_PARAM(test);
#endif
         break;
      }
      if ((err != CRYPT_NOP) && (cleanup != NULL)) {
         cleanup(ctx);
      }

      XFREE(buf);
      buf = NULL;
      fclose(f);
      f = NULL;
   }
   if (buf != NULL) XFREE(buf);
   if (f != NULL) fclose(f);
   closedir(d);
   return err;
}
#endif


prng_state yarrow_prng;
