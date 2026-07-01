/* tempest_v3.h — 4-cmul Tempest v3 (dual-output)
 * ADD pre-diffusion + 4-cmul Fibonacci-weave + AND-mix output
 * 2^128 CSPRNG, 17.7 Gbit/s (provable-security: 128 bits/round)
 * Passes NIST 15/15 + TestU01 all 5 levels + PractRand 1 TiB
 * See results/ for full test logs */
#ifndef TEMPEST_V3_H
#define TEMPEST_V3_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct { uint64_t u,v,w,z,r,weyl; } tx4_state;

/* ── Core API ── */
void tx5cmul_init(tx4_state *s, const uint64_t key[4], const uint64_t nonce[2]);
void tx5cmul_seed(tx4_state *s, uint64_t seed);
uint64_t tx5cmul_next(tx4_state *s);
void   tx5cmul_next2(tx4_state *s, uint64_t out[2]);

/* ── Python-friendly aliases (same functionality) ── */
void    tempest_init(tx4_state *s, const uint64_t key[4], const uint64_t nonce[2]);
uint64_t tempest_u64(tx4_state *s);
void    tempest_u64x2(tx4_state *s, uint64_t out[2]);
void    tempest_bytes(tx4_state *s, uint8_t *buf, size_t n);

#ifdef __cplusplus
}
#endif
#endif
