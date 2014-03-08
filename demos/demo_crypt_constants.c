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
#include "tomcrypt_misc.h"

/**
  @file demo_crypt_constants.c
  
  Demo how to get various constants to dynamic languages 
  like Python
  
  Larry Bugbee, February 2013
*/


int main(void) {
    int rc;
    
    printf("\n");
    
    // given a specific constant name, get and print its value
    char name[] = "CTR_COUNTER_BIG_ENDIAN";
    int  value;
    
    rc = crypt_get_constant(name, &value);
    printf("  %s is %d \n", name, value);
    printf("\n");
    
    // get and print the length of the names (and values) list
    char *names_list;
    unsigned long names_list_len;
    
    rc = crypt_list_all_constants(NULL, &names_list_len);
    printf("  need to allocate %lu bytes \n", names_list_len);
    printf("\n");
    
    // get and print the names (and values) list
    names_list = malloc(names_list_len);
    rc = crypt_list_all_constants(names_list, &names_list_len);
    printf("  supported constants: \n%s \n", names_list);
    printf("\n");
}


/* $Source:  $ */
/* $Revision:  $ */
/* $Date:  $ */
