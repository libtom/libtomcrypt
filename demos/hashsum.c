/*
 * Written by Daniel Richards <kyhwana@world-net.co.nz> 6/7/2002
 * hash.c: This app uses libtomcrypt to hash either stdin or a file
 * This file is Public Domain. No rights are reserved.
 * Compile with 'gcc hashsum.c -o hashsum -ltomcrypt'
 * This example isn't really big enough to warrent splitting into
 * more functions ;)
*/

#include <tomcrypt.h>

#if _POSIX_C_SOURCE >= 200112L
#include <libgen.h>
#else
#define basename(x) x
#endif

int errno;

void register_algs(void);

int main(int argc, char **argv)
{
   int idx, z;
   unsigned long w, x;
   unsigned char hash_buffer[MAXBLOCKSIZE];

   /* You need to register algorithms before using them */
   register_algs();
   if (argc < 2) {
      printf("usage: %s algorithm file [file ...]\n", basename(argv[0]));
      printf("Algorithms:\n");
      w = 0;
      for (x = 0; hash_descriptor[x].name != NULL; x++) {
         w += printf("%-14s", hash_descriptor[x].name);
         if (w >= 70) {
            printf("\n");
            w = 0;
         }
      }
      printf("\n");
      exit(EXIT_SUCCESS);
   }

   idx = find_hash(argv[1]);
   if (idx == -1) {
      fprintf(stderr, "\nInvalid hash specified on command line.\n");
      return EXIT_FAILURE;
   }

   if (argc == 2) {
      w = sizeof(hash_buffer);
      if ((errno = hash_filehandle(idx, stdin, hash_buffer, &w)) != CRYPT_OK) {
         fprintf(stderr, "File hash error: %s\n", error_to_string(errno));
         return EXIT_FAILURE;
      } else {
          for (x = 0; x < w; x++) {
              printf("%02x",hash_buffer[x]);
          }
          printf(" *-\n");
      }
   } else {
      for (z = 2; z < argc; z++) {
         w = sizeof(hash_buffer);
         if ((errno = hash_file(idx,argv[z],hash_buffer,&w)) != CRYPT_OK) {
            fprintf(stderr, "File hash error: %s\n", error_to_string(errno));
            return EXIT_FAILURE;
         } else {
             for (x = 0; x < w; x++) {
                 printf("%02x",hash_buffer[x]);
             }
             printf(" *%s\n", argv[z]);
         }
      }
   }
   return EXIT_SUCCESS;
}

void register_algs(void)
{
  int err;
  LTC_UNUSED_PARAM(err);

#ifdef LTC_TIGER
  register_hash (&tiger_desc);
#endif
#ifdef LTC_MD2
  register_hash (&md2_desc);
#endif
#ifdef LTC_MD4
  register_hash (&md4_desc);
#endif
#ifdef LTC_MD5
  register_hash (&md5_desc);
#endif
#ifdef LTC_SHA1
  register_hash (&sha1_desc);
#endif
#ifdef LTC_SHA224
  register_hash (&sha224_desc);
#endif
#ifdef LTC_SHA256
  register_hash (&sha256_desc);
#endif
#ifdef LTC_SHA384
  register_hash (&sha384_desc);
#endif
#ifdef LTC_SHA512
  register_hash (&sha512_desc);
#endif
#ifdef LTC_SHA512_224
  register_hash (&sha512_224_desc);
#endif
#ifdef LTC_SHA512_256
  register_hash (&sha512_256_desc);
#endif
#ifdef LTC_SHA3
  register_hash (&sha3_224_desc);
  register_hash (&sha3_256_desc);
  register_hash (&sha3_384_desc);
  register_hash (&sha3_512_desc);
#endif
#ifdef LTC_RIPEMD128
  register_hash (&rmd128_desc);
#endif
#ifdef LTC_RIPEMD160
  register_hash (&rmd160_desc);
#endif
#ifdef LTC_RIPEMD256
  register_hash (&rmd256_desc);
#endif
#ifdef LTC_RIPEMD320
  register_hash (&rmd320_desc);
#endif
#ifdef LTC_WHIRLPOOL
  register_hash (&whirlpool_desc);
#endif
#ifdef LTC_BLAKE2S
  register_hash (&blake2s_128_desc);
  register_hash (&blake2s_160_desc);
  register_hash (&blake2s_224_desc);
  register_hash (&blake2s_256_desc);
#endif
#ifdef LTC_BLAKE2B
  register_hash (&blake2b_160_desc);
  register_hash (&blake2b_256_desc);
  register_hash (&blake2b_384_desc);
  register_hash (&blake2b_512_desc);
#endif
#ifdef LTC_CHC_HASH
  register_hash(&chc_desc);
  if ((err = chc_register(register_cipher(&aes_enc_desc))) != CRYPT_OK) {
     printf("chc_register error: %s\n", error_to_string(err));
     exit(EXIT_FAILURE);
  }
#endif

}

/* $Source$ */
/* $Revision$ */
/* $Date$ */
