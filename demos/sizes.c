/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt.h"

/**
  @file demo_crypt_sizes.c

  Demo how to get various sizes to dynamic languages
  like Python - Larry Bugbee, February 2013
*/


int main(void) {

    /* given a specific size name, get and print its size */
    char name[] = "ecc_key";
    unsigned int size;
    char *sizes_list;
    unsigned int sizes_list_len;
    if(crypt_get_size(name, &size) != 0)
      exit(EXIT_FAILURE);
    printf("\n  size of '%s' is %u \n\n", name, size);

    /* get and print the length of the names (and sizes) list */
    if(crypt_list_all_sizes(NULL, &sizes_list_len) != 0)
       exit(EXIT_FAILURE);
    printf("  need to allocate %u bytes \n\n", sizes_list_len);

    /* get and print the names (and sizes) list */
    sizes_list = malloc(sizes_list_len);
    if(crypt_list_all_sizes(sizes_list, &sizes_list_len) != 0)
       exit(EXIT_FAILURE);
    printf("  supported sizes:\n\n%s\n\n", sizes_list);
    return 0;
}

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
