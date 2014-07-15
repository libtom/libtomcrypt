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
  @file demo_crypt_constants.c

  Demo how to get various constants to dynamic languages
  like Python

  Larry Bugbee, February 2013
*/


int main(void) {
    // given a specific constant name, get and print its value
    char name[] = "CTR_COUNTER_BIG_ENDIAN";
    int  value;

    if (crypt_get_constant(name, &value) != 0)
      exit(EXIT_FAILURE);
    printf("\n  %s is %d \n\n", name, value);

    // get and print the length of the names (and values) list
    char *names_list;
    unsigned long names_list_len;

    if (crypt_list_all_constants(NULL, &names_list_len) != 0)
      exit(EXIT_FAILURE);
    printf("  need to allocate %lu bytes \n\n", names_list_len);

    // get and print the names (and values) list
    if ((names_list = malloc(names_list_len)) == NULL)
      exit(EXIT_FAILURE);
    if (crypt_list_all_constants(names_list, &names_list_len) != 0)
      exit(EXIT_FAILURE);
    printf("  supported constants:\n\n%s\n\n", names_list);
    free(names_list);

    return 0;
}


/* $Source$ */
/* $Revision$ */
/* $Date$ */
