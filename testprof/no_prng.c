/* LibTomCrypt, modular cryptographic library
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * http://libtom.org
 */
#include "tomcrypt.h"

/**
  @file no_prng.c
  NO PRNG, Steffen Jaeckel
*/

#ifdef LTC_PKCS_1

static unsigned char no_prng_entropy[1024];
static unsigned long no_prng_len = 0;
static unsigned long no_prng_offset = 0;

/**
  Start the PRNG
  @param prng     [out] The PRNG state to initialize
  @return CRYPT_OK if successful
*/
int no_prng_start(prng_state *prng)
{
    LTC_UNUSED_PARAM(prng);
    no_prng_len = 0;
    no_prng_offset = 0;

    return CRYPT_OK;
}

/**
  Add entropy to the PRNG state
  @param in       The data to add
  @param inlen    Length of the data to add
  @param prng     PRNG state to update
  @return CRYPT_OK if successful
*/
int no_prng_add_entropy(const unsigned char *in, unsigned long inlen, prng_state *prng)
{
    LTC_UNUSED_PARAM(prng);
    LTC_ARGCHK(in  != NULL);
    LTC_ARGCHK(inlen <= sizeof(no_prng_entropy));

    no_prng_len = MIN(inlen, sizeof(no_prng_entropy));
    memcpy(no_prng_entropy, in, no_prng_len);
    no_prng_offset = 0;

    return CRYPT_OK;

}

/**
  Make the PRNG ready to read from
  @param prng   The PRNG to make active
  @return CRYPT_OK if successful
*/
int no_prng_ready(prng_state *prng)
{
    LTC_ARGCHK(prng != NULL);

    return CRYPT_OK;
}

/**
  Read from the PRNG
  @param out      Destination
  @param outlen   Length of output
  @param prng     The active PRNG to read from
  @return Number of octets read
*/
unsigned long no_prng_read(unsigned char *out, unsigned long outlen, prng_state *prng)
{
   LTC_UNUSED_PARAM(prng);
   LTC_ARGCHK(out != NULL);

   outlen = MIN(outlen, no_prng_len - no_prng_offset);
   memcpy(out, &no_prng_entropy[no_prng_offset], outlen);
   no_prng_offset += outlen;

   return outlen;
}

/**
  Terminate the PRNG
  @param prng   The PRNG to terminate
  @return CRYPT_OK if successful
*/
int no_prng_done(prng_state *prng)
{
   LTC_UNUSED_PARAM(prng);
   return CRYPT_OK;
}

/**
  Export the PRNG state
  @param out       [out] Destination
  @param outlen    [in/out] Max size and resulting size of the state
  @param prng      The PRNG to export
  @return CRYPT_OK if successful
*/
int no_prng_export(unsigned char *out, unsigned long *outlen, prng_state *prng)
{
   LTC_UNUSED_PARAM(out);
   LTC_UNUSED_PARAM(outlen);
   LTC_UNUSED_PARAM(prng);
   return CRYPT_OK;
}

/**
  Import a PRNG state
  @param in       The PRNG state
  @param inlen    Size of the state
  @param prng     The PRNG to import
  @return CRYPT_OK if successful
*/
int no_prng_import(const unsigned char *in, unsigned long inlen, prng_state *prng)
{
   LTC_UNUSED_PARAM(in);
   LTC_UNUSED_PARAM(inlen);
   LTC_UNUSED_PARAM(prng);
   return CRYPT_OK;
}

/**
  PRNG self-test
  @return CRYPT_OK if successful, CRYPT_NOP if self-testing has been disabled
*/
int no_prng_test(void)
{
   return CRYPT_OK;
}

const struct ltc_prng_descriptor no_prng_desc =
{
   "no_prng", 0,
    &no_prng_start,
    &no_prng_add_entropy,
    &no_prng_ready,
    &no_prng_read,
    &no_prng_done,
    &no_prng_export,
    &no_prng_import,
    &no_prng_test
};

#endif


/* $Source$ */
/* $Revision$ */
/* $Date$ */
