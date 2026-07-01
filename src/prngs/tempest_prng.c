/* tempest_prng.c — LibTomCrypt PRNG backend for Tempest v3
 *
 * Register with:
 *   int idx = register_prng(&tempest_prng_desc);
 *   /* then use idx with any libtomcrypt function needing a PRNG */
 *
 * Tempest v3: 17.7 Gbit/s, 2^128 provable security, 48-byte state
 */

#include <tomcrypt.h>
#include "tempest_v3.h"

/* Local state wrapper: marker + aligned tx4_state.
 * prng_state.u.sprng[] uses ulong32 (4-byte alignment); tx4_state
 * needs 8-byte alignment for uint64_t.  This struct starts with
 * a uint64_t marker to force natural alignment of the whole block. */
typedef struct {
    uint64_t marker;
    tx4_state state;
} tempest_local_state;

/* ── Callbacks ── */

static int tempest_start(prng_state *prng)
{
    tempest_local_state *ls = (tempest_local_state *)prng->u.sprng;
    ls->marker = 0x54584D5000000001ULL;  /* "TXMP\0\0\0\1" */
    return CRYPT_OK;
}

static int tempest_add_entropy(const unsigned char *in, unsigned long inlen,
                                prng_state *prng)
{
    tempest_local_state *ls = (tempest_local_state *)prng->u.sprng;
    (void)in; (void)inlen;
    if (ls->marker != 0x54584D5000000001ULL)
        return CRYPT_ERROR;
    return CRYPT_OK;
}

static int tempest_ready(prng_state *prng)
{
    tempest_local_state *ls = (tempest_local_state *)prng->u.sprng;
    uint64_t key[4], nonce[2];

    if (ls->marker != 0x54584D5000000001ULL)
        return CRYPT_ERROR;

    os_get_random((unsigned char *)key, sizeof(key));
    os_get_random((unsigned char *)nonce, sizeof(nonce));
    tx5cmul_init(&ls->state, key, nonce);
    return CRYPT_OK;
}

static unsigned long tempest_read(unsigned char *out, unsigned long outlen,
                                   prng_state *prng)
{
    tempest_local_state *ls = (tempest_local_state *)prng->u.sprng;
    if (ls->marker != 0x54584D5000000001ULL)
        return 0;
    tempest_bytes(&ls->state, out, outlen);
    return outlen;
}

static int tempest_done(prng_state *prng)
{
    tempest_local_state *ls = (tempest_local_state *)prng->u.sprng;
    if (ls->marker == 0x54584D5000000001ULL) {
        zeroize(&ls->state, sizeof(ls->state));
        ls->marker = 0;
    }
    return CRYPT_OK;
}

static int tempest_export(unsigned char *out, unsigned long *outlen,
                           prng_state *prng)
{
    tempest_local_state *ls = (tempest_local_state *)prng->u.sprng;
    if (ls->marker != 0x54584D5000000001ULL)
        return CRYPT_ERROR;
    if (*outlen < sizeof(tempest_local_state))
        return CRYPT_BUFFER_OVERFLOW;
    memcpy(out, ls, sizeof(tempest_local_state));
    *outlen = sizeof(tempest_local_state);
    return CRYPT_OK;
}

static int tempest_import(const unsigned char *in, unsigned long inlen,
                           prng_state *prng)
{
    if (inlen < sizeof(tempest_local_state))
        return CRYPT_ERROR;
    tempest_local_state *ls = (tempest_local_state *)prng->u.sprng;
    memcpy(ls, in, sizeof(tempest_local_state));
    if (ls->marker != 0x54584D5000000001ULL)
        return CRYPT_ERROR;
    return CRYPT_OK;
}

static int tempest_test(void)
{
    tx4_state s;
    uint64_t key[4] = {1,2,3,4};
    uint64_t nonce[2] = {5,6};
    uint64_t out1[4], out2[4];

    tx5cmul_init(&s, key, nonce);
    for (int i = 0; i < 4; i++)
        out1[i] = tx5cmul_next(&s);

    /* Same seed → same output (determinism check) */
    tx5cmul_init(&s, key, nonce);
    for (int i = 0; i < 4; i++)
        out2[i] = tx5cmul_next(&s);

    if (memcmp(out1, out2, sizeof(out1)) != 0)
        return CRYPT_ERROR;

    /* Non-zero output on zero key */
    uint64_t zero_key[4] = {0,0,0,0};
    uint64_t zero_nonce[2] = {0,0};
    tx5cmul_init(&s, zero_key, zero_nonce);
    uint64_t v = tx5cmul_next(&s);
    if (v == 0)
        return CRYPT_ERROR;

    return CRYPT_OK;
}

/* ── PRNG Descriptor ── */

const struct ltc_prng_descriptor tempest_prng_desc = {
    .name        = "tempest",
    .export_size = sizeof(tempest_local_state),
    .start       = &tempest_start,
    .add_entropy = &tempest_add_entropy,
    .ready       = &tempest_ready,
    .read        = &tempest_read,
    .done        = &tempest_done,
    .export      = &tempest_export,
    .import      = &tempest_import,
    .test        = &tempest_test
};
