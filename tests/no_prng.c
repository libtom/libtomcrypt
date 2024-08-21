/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt.h"
#include "tomcrypt_test.h"

/**
  @file no_prng.c
  NO PRNG, Steffen Jaeckel
*/

#ifdef LTC_PKCS_1

typedef struct
{
   prng_state state;
   char name[64];
   unsigned char entropy[1024];
   unsigned long len;
   unsigned long offset;
} no_prng_desc_t;

/**
  Start the PRNG
  @param prng     [out] The PRNG state to initialize
  @return CRYPT_OK if successful
*/
static int no_prng_start(prng_state *prng)
{
   no_prng_desc_t *no_prng = (no_prng_desc_t*) prng;
   LTC_ARGCHK(no_prng != NULL);
   LTC_ARGCHK(no_prng->name == (char*)no_prng + offsetof(no_prng_desc_t, name));
   no_prng->len = 0;
   no_prng->offset = 0;
   return CRYPT_OK;
}

/**
  Add entropy to the PRNG state
  @param in       The data to add
  @param inlen    Length of the data to add
  @param prng     PRNG state to update
  @return CRYPT_OK if successful
*/
static int no_prng_add_entropy(const unsigned char *in, unsigned long inlen, prng_state *prng)
{
   no_prng_desc_t *no_prng = (no_prng_desc_t*) prng;
   LTC_ARGCHK(no_prng != NULL);
   LTC_ARGCHK(no_prng->name == (char*)no_prng + offsetof(no_prng_desc_t, name));
   LTC_ARGCHK(in != NULL);
   LTC_ARGCHK(inlen <= sizeof(no_prng->entropy));

   no_prng->len = MIN(inlen, sizeof(no_prng->entropy));
   memcpy(no_prng->entropy, in, no_prng->len);
   no_prng->offset = 0;

   return CRYPT_OK;

}

/**
  Make the PRNG ready to read from
  @param prng   The PRNG to make active
  @return CRYPT_OK if successful
*/
static int no_prng_ready(prng_state *prng)
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
static unsigned long no_prng_read(unsigned char *out, unsigned long outlen, prng_state *prng)
{
   no_prng_desc_t *no_prng = (no_prng_desc_t*) prng;
   LTC_ARGCHK(no_prng != NULL);
   LTC_ARGCHK(no_prng->name == (char*)no_prng + offsetof(no_prng_desc_t, name));
   LTC_ARGCHK(out != NULL);

   outlen = MIN(outlen, no_prng->len - no_prng->offset);
   memcpy(out, &no_prng->entropy[no_prng->offset], outlen);
   no_prng->offset += outlen;

   return outlen;
}

/**
  Terminate the PRNG
  @param prng   The PRNG to terminate
  @return CRYPT_OK if successful
*/
static int no_prng_done(prng_state *prng)
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
static int no_prng_export(unsigned char *out, unsigned long *outlen, prng_state *prng)
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
static int no_prng_import(const unsigned char *in, unsigned long inlen, prng_state *prng)
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
static int no_prng_test(void)
{
   return CRYPT_OK;
}

static const struct ltc_prng_descriptor no_prng_desc =
{
    NULL, 0,
    &no_prng_start,
    &no_prng_add_entropy,
    &no_prng_ready,
    &no_prng_read,
    &no_prng_done,
    &no_prng_export,
    &no_prng_import,
    &no_prng_test
};

prng_state* no_prng_desc_get(void)
{
   int ret;
   no_prng_desc_t* no_prng = XMALLOC(sizeof(*no_prng));
   if (no_prng == NULL) return NULL;
   XMEMCPY(&no_prng->state.desc, &no_prng_desc, sizeof(no_prng_desc));
   ret = snprintf(no_prng->name, sizeof(no_prng->name), "no_prng@%p", no_prng);
   if((ret >= (int)sizeof(no_prng->name)) || (ret == -1)) {
      XFREE(no_prng);
      return NULL;
   }
   no_prng->state.desc.name = no_prng->name;
   return &no_prng->state;
}

void no_prng_desc_free(prng_state* prng)
{
   no_prng_desc_t *no_prng = (no_prng_desc_t*) prng;
   LTC_ARGCHKVD(no_prng != NULL);
   LTC_ARGCHKVD(no_prng->state.desc.name == (char*)no_prng + offsetof(no_prng_desc_t, name));
   XFREE(no_prng);
}

#endif

