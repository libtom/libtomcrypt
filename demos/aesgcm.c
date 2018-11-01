/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/**
  @file aesgcm.c
  AES128-GCM demo - file en-&decryption, Steffen Jaeckel
  Uses the format: |ciphertext|tag-16-bytes|
*/

#define _GNU_SOURCE

#include <tomcrypt.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "gcm-file/gcm_filehandle.c"
#include "gcm-file/gcm_file.c"


static off_t fsize(const char *filename)
{
   struct stat st;

   if (stat(filename, &st) == 0) return st.st_size;

   return -1;
}

#if defined(__linux__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 14)
#define HAS_SYNCFS
#endif
#endif

static int mv(const char *old_name, const char *new_name)
{
   int fd;
   if (rename(old_name, new_name) == -1) return -1;
   fd = open(new_name, 0);
   if (fd == -1) return -1;
#if !defined(_WIN32)
   if (fsync(fd) != 0) goto OUT;
#if defined(HAS_SYNCFS)
   syncfs(fd);
#else
   sync();
#endif
OUT:
#endif
   close(fd);
   return 0;
}

/* https://stackoverflow.com/a/23898449 */
static void scan_hex(const char* str, uint8_t* bytes, size_t blen)
{
   uint8_t  pos;
   uint8_t  idx0;
   uint8_t  idx1;

   const uint8_t hashmap[] =
   {
     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, /* 01234567 */
     0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 89:;<=>? */
     0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, /* @ABCDEFG */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* HIJKLMNO */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* PQRSTUVW */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* XYZ[\]^_ */
     0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, /* `abcdefg */
   };

   for (pos = 0; ((pos < (blen*2)) && (pos < strlen(str))); pos += 2)
   {
      idx0 = (uint8_t)(str[pos+0] & 0x1F) ^ 0x10;
      idx1 = (uint8_t)(str[pos+1] & 0x1F) ^ 0x10;
      bytes[pos/2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
   }
}

static void die(int ret)
{
   fprintf(stderr, "Usage: aesgcm <-e|-d> <infile> <outfile> <96 char hex-string 'IV | key'>\n");
   exit(ret);
}

int main(int argc, char **argv)
{
   int ret = 0, err, arg, direction, res, tmp;
   size_t keylen;
   uint8_t keybuf[48] = {0};
   char *out = NULL;
   const char *mode, *in_file, *out_file, *key_string;

   if (argc < 5) die(__LINE__);

   arg = 1;
   mode = argv[arg++];
   in_file = argv[arg++];
   out_file = argv[arg++];
   key_string = argv[arg++];

   if(strcmp(mode, "-d") == 0) direction = GCM_DECRYPT;
   else if(strcmp(mode, "-e") == 0) direction = GCM_ENCRYPT;
   else die(__LINE__);

   if (fsize(in_file) <= 0) die(__LINE__);

   keylen = strlen(key_string);
   if (keylen != 96) die(__LINE__);

   scan_hex(key_string, keybuf, sizeof(keybuf));

   register_all_ciphers();

   if(asprintf(&out, "%s-XXXXXX", out_file) < 0) die(__LINE__);
   if((tmp = mkstemp(out)) == -1) {
      ret = __LINE__;
      goto cleanup;
   }
   close(tmp);
   if((err = gcm_file(find_cipher("aes"), &keybuf[16], 32, keybuf, 16, NULL, 0, in_file, out, 16, direction, &res)) != CRYPT_OK) {
      fprintf(stderr, "boooh %s\n", error_to_string(err));
      ret = __LINE__;
      goto cleanup;
   }

   if(res != 1) {
      ret = __LINE__;
   }
   else
   {
      if (mv(out, out_file) != 0) ret = __LINE__;
   }

cleanup:
   if(ret != 0) unlink(out);
   free(out);


   return ret;
}

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
