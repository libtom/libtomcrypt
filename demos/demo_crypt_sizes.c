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


// in lieu of a header file
int crypt_get_size(const char* namein, int *sizeout);
int crypt_list_all_sizes(char *names_list, 
                         unsigned long *names_list_size);


int main(void) {
    int rc;
    printf("\n");
    
    // given a specific size name, get and print its size
    char name[] = "ecc_key_struct_size";
    int size;
    rc = crypt_get_size(name, &size);
    printf("  %s is %d \n", name, size);
    printf("\n");
    
    // get and print the length of the names (and sizes) list
    char *sizes_list;
    unsigned long sizes_list_len;
    rc = crypt_list_all_sizes(NULL, &sizes_list_len);
    printf("  need to allocate %lu bytes \n", sizes_list_len);
    printf("\n");
    
    // get and print the names (and sizes) list
    sizes_list = malloc(sizes_list_len);
    rc = crypt_list_all_sizes(sizes_list, &sizes_list_len);
    printf("  supported sizes: %s \n", sizes_list);
    printf("\n");
}


/* $Source:  $ */
/* $Revision:  $ */
/* $Date:  $ */
