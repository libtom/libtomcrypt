/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */
#include "tomcrypt.h"

/**
  @file demo_crypt_sizes.c

  Demo how to get various sizes to dynamic languages
  like Python - Larry Bugbee, February 2013
*/


int main(void) {
    int rc;

    // given a specific size name, get and print its size
    char name[] = "ecc_key";
    int size;
    rc = crypt_get_size(name, &size);
    printf("\n  size of '%s' is %d \n\n", name, size);

    // get and print the length of the names (and sizes) list
    char *sizes_list;
    unsigned long sizes_list_len;
    rc = crypt_list_all_sizes(NULL, &sizes_list_len);
    printf("  need to allocate %lu bytes \n\n", sizes_list_len);

    // get and print the names (and sizes) list
    sizes_list = malloc(sizes_list_len);
    rc = crypt_list_all_sizes(sizes_list, &sizes_list_len);
    printf("  supported sizes:\n\n%s\n\n", sizes_list);
}


/* $Source:  $ */
/* $Revision:  $ */
/* $Date:  $ */
