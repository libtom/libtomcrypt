/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* Forward declare */
typedef struct password_ctx password_ctx;

/* ---- Post-Quantum Cryptography ---- */

/* Maximum length of the optional context string accepted by ML-DSA and SLH-DSA
   signing/verification (FIPS 204 5.2 and FIPS 205 10.2). */
#define LTC_PQC_CTX_MAX_BYTES 255

/** Private-key representation selected by mlkem_export_ex() and mldsa_export_ex() */
enum ltc_pqc_privkey_format {
   LTC_PQC_PRIVKEY_AUTO     = 0, /* seed if the key has one, expanded key otherwise */
   LTC_PQC_PRIVKEY_SEED     = 1,
   LTC_PQC_PRIVKEY_EXPANDED = 2,
   LTC_PQC_PRIVKEY_BOTH     = 3
};

/* ---- ML-KEM (FIPS 203) ---- */
#ifdef LTC_MLKEM

/** ML-KEM parameter set identifiers */
enum ltc_mlkem_id {
   LTC_MLKEM_512  = 0,
   LTC_MLKEM_768  = 1,
   LTC_MLKEM_1024 = 2
};

/* ML-KEM byte-length constants (fixed across all parameter sets) */
#define LTC_MLKEM_M_BYTES             32 /* encaps entropy m (mlkem_encaps_ex)            */
#define LTC_MLKEM_SHARED_SECRET_BYTES 32 /* output of mlkem_encaps / mlkem_decaps         */
#define LTC_MLKEM_KEYGEN_SEED_BYTES   64 /* seed for mlkem_make_key_from_seed (d || z)    */

/** ML-KEM key */
typedef struct mlkem_key {
   /** Algorithm identifier (ltc_mlkem_id) */
   int alg;
   /** Type of key, PK_PRIVATE or PK_PUBLIC */
   int type;
   /** Public key (encapsulation key) */
   unsigned char *pk;
   unsigned long  pklen;
   /** Secret key (decapsulation key, private only) */
   unsigned char *sk;
   unsigned long  sklen;
   /** Key generation seed d || z, valid while has_seed is set */
   unsigned char  seed[LTC_MLKEM_KEYGEN_SEED_BYTES];
   /** Non-zero if seed[] holds the seed this key was generated from */
   int has_seed;
} mlkem_key;

int mlkem_make_key(prng_state *prng, int wprng, int alg, mlkem_key *key);
int mlkem_make_key_from_seed(int alg, const unsigned char *seed, unsigned long seedlen, mlkem_key *key);
void mlkem_free(mlkem_key *key);

int mlkem_export_raw(unsigned char *out, unsigned long *outlen, int which, const mlkem_key *key);
int mlkem_import_raw(const unsigned char *in, unsigned long inlen, int which, int alg, mlkem_key *key);
int mlkem_check_key(const mlkem_key *key);
int mlkem_has_seed(const mlkem_key *key);
int mlkem_export_seed(unsigned char *out, unsigned long *outlen, const mlkem_key *key);
#ifdef LTC_DER
int mlkem_export(unsigned char *out, unsigned long *outlen, int which, const mlkem_key *key);
int mlkem_export_ex(unsigned char *out, unsigned long *outlen, int which, enum ltc_pqc_privkey_format format, const mlkem_key *key);
int mlkem_import(const unsigned char *in, unsigned long inlen, mlkem_key *key);
int mlkem_import_x509(const unsigned char *in, unsigned long inlen, mlkem_key *key);
#endif
#ifdef LTC_PKCS_8
int mlkem_import_pkcs8(const unsigned char *in, unsigned long inlen, const password_ctx *pw_ctx, mlkem_key *key);
#endif

int mlkem_encaps(unsigned char   *ct,            unsigned long *ctlen,
                 unsigned char   *shared_secret, unsigned long *sslen,
                 prng_state      *prng,          int            wprng,
                 const mlkem_key *key);

int mlkem_encaps_ex(unsigned char       *ct,            unsigned long *ctlen,
                    unsigned char       *shared_secret, unsigned long *sslen,
                    const unsigned char *m,             unsigned long  mlen,
                    const mlkem_key     *key);

int mlkem_decaps(unsigned char       *shared_secret, unsigned long *sslen,
                 const unsigned char *ct,            unsigned long  ctlen,
                 const mlkem_key     *key);

int mlkem_get_sizes(int alg,
                    unsigned long *public_key_sz,
                    unsigned long *secret_key_sz,
                    unsigned long *ciphertext_sz,
                    unsigned long *shared_secret_sz,
                    unsigned long *keygen_seed_sz,
                    unsigned long *encaps_entropy_sz);

int mlkem_find_alg(const char *name_or_oid, int *alg);
int mlkem_alg_name(int alg, const char **name);

#endif /* LTC_MLKEM */


/* ---- ML-DSA (FIPS 204) ---- */
#ifdef LTC_MLDSA

/** ML-DSA parameter set identifiers */
enum ltc_mldsa_id {
   LTC_MLDSA_44 = 0,
   LTC_MLDSA_65 = 1,
   LTC_MLDSA_87 = 2
};

/* ML-DSA byte-length constants (fixed across all parameter sets) */
#define LTC_MLDSA_RND_BYTES         32 /* per-signature rnd (mldsa_sign_ex)         */
#define LTC_MLDSA_MU_BYTES          64 /* external mu (mldsa_sign_ex_mu)            */
#define LTC_MLDSA_KEYGEN_SEED_BYTES 32 /* seed for mldsa_make_key_from_seed (xi)    */

/** ML-DSA key */
typedef struct mldsa_key {
   /** Algorithm identifier (ltc_mldsa_id) */
   int alg;
   /** Type of key, PK_PRIVATE or PK_PUBLIC */
   int type;
   /** Public key (verification key) */
   unsigned char *pk;
   unsigned long  pklen;
   /** Secret key (signing key, private only) */
   unsigned char *sk;
   unsigned long  sklen;
   /** Key generation seed xi, valid while has_seed is set */
   unsigned char  seed[LTC_MLDSA_KEYGEN_SEED_BYTES];
   /** Non-zero if seed[] holds the seed this key was generated from */
   int has_seed;
} mldsa_key;

int mldsa_make_key(prng_state *prng, int wprng, int alg, mldsa_key *key);
int mldsa_make_key_from_seed(int alg, const unsigned char *seed, unsigned long seedlen, mldsa_key *key);
void mldsa_free(mldsa_key *key);

int mldsa_export_raw(unsigned char *out, unsigned long *outlen, int which, const mldsa_key *key);
int mldsa_import_raw(const unsigned char *in, unsigned long inlen, int which, int alg, mldsa_key *key);
int mldsa_check_key(const mldsa_key *key);
int mldsa_has_seed(const mldsa_key *key);
int mldsa_export_seed(unsigned char *out, unsigned long *outlen, const mldsa_key *key);
#ifdef LTC_DER
int mldsa_export(unsigned char *out, unsigned long *outlen, int which, const mldsa_key *key);
int mldsa_export_ex(unsigned char *out, unsigned long *outlen, int which, enum ltc_pqc_privkey_format format, const mldsa_key *key);
int mldsa_import(const unsigned char *in, unsigned long inlen, mldsa_key *key);
int mldsa_import_x509(const unsigned char *in, unsigned long inlen, mldsa_key *key);
#endif
#ifdef LTC_PKCS_8
int mldsa_import_pkcs8(const unsigned char *in, unsigned long inlen, const password_ctx *pw_ctx, mldsa_key *key);
#endif

int mldsa_sign(const unsigned char *msg,  unsigned long  msglen,
                     unsigned char *sig,  unsigned long *siglen,
               const unsigned char *ctx,  unsigned long  ctxlen,
                     prng_state    *prng, int            wprng,
               const mldsa_key     *key);

int mldsa_sign_ex(const unsigned char *msg,  unsigned long  msglen,
                        unsigned char *sig,  unsigned long *siglen,
                  const unsigned char *ctx,  unsigned long  ctxlen,
                  const unsigned char *rnd,  unsigned long  rndlen,
                  const mldsa_key     *key);

int mldsa_sign_ex_mu(const unsigned char *mu,  unsigned long  mulen,
                           unsigned char *sig, unsigned long *siglen,
                     const unsigned char *rnd, unsigned long  rndlen,
                     const mldsa_key     *key);

int mldsa_verify(const unsigned char *sig,  unsigned long  siglen,
                 const unsigned char *msg,  unsigned long  msglen,
                 const unsigned char *ctx,  unsigned long  ctxlen,
                       int           *stat,
                 const mldsa_key     *key);

int mldsa_compute_mu(      unsigned char *mu,  unsigned long *mulen,
                     const unsigned char *msg, unsigned long  msglen,
                     const unsigned char *ctx, unsigned long  ctxlen,
                     const mldsa_key     *key);

int mldsa_verify_mu(const unsigned char *sig, unsigned long  siglen,
                    const unsigned char *mu,  unsigned long  mulen,
                          int           *stat,
                    const mldsa_key     *key);

int mldsa_get_sizes(int alg,
                    unsigned long *public_key_sz,
                    unsigned long *secret_key_sz,
                    unsigned long *signature_sz,
                    unsigned long *rnd_sz,
                    unsigned long *mu_sz,
                    unsigned long *keygen_seed_sz);

int mldsa_find_alg(const char *name_or_oid, int *alg);
int mldsa_alg_name(int alg, const char **name);

#endif /* LTC_MLDSA */


/* ---- SLH-DSA (FIPS 205) ---- */
#ifdef LTC_SLHDSA

/** SLH-DSA parameter set identifiers */
enum ltc_slhdsa_id {
   LTC_SLHDSA_SHA2_128S  = 0,
   LTC_SLHDSA_SHA2_128F  = 1,
   LTC_SLHDSA_SHA2_192S  = 2,
   LTC_SLHDSA_SHA2_192F  = 3,
   LTC_SLHDSA_SHA2_256S  = 4,
   LTC_SLHDSA_SHA2_256F  = 5,
   LTC_SLHDSA_SHAKE_128S = 6,
   LTC_SLHDSA_SHAKE_128F = 7,
   LTC_SLHDSA_SHAKE_192S = 8,
   LTC_SLHDSA_SHAKE_192F = 9,
   LTC_SLHDSA_SHAKE_256S = 10,
   LTC_SLHDSA_SHAKE_256F = 11,
   LTC_SLHDSA_HASH_SHA2_128S_WITH_SHA256 = 12,
   LTC_SLHDSA_HASH_SHA2_128F_WITH_SHA256 = 13,
   LTC_SLHDSA_HASH_SHA2_192S_WITH_SHA512 = 14,
   LTC_SLHDSA_HASH_SHA2_192F_WITH_SHA512 = 15,
   LTC_SLHDSA_HASH_SHA2_256S_WITH_SHA512 = 16,
   LTC_SLHDSA_HASH_SHA2_256F_WITH_SHA512 = 17,
   LTC_SLHDSA_HASH_SHAKE_128S_WITH_SHAKE128 = 18,
   LTC_SLHDSA_HASH_SHAKE_128F_WITH_SHAKE128 = 19,
   LTC_SLHDSA_HASH_SHAKE_192S_WITH_SHAKE256 = 20,
   LTC_SLHDSA_HASH_SHAKE_192F_WITH_SHAKE256 = 21,
   LTC_SLHDSA_HASH_SHAKE_256S_WITH_SHAKE256 = 22,
   LTC_SLHDSA_HASH_SHAKE_256F_WITH_SHAKE256 = 23
};

/** SLH-DSA key */
typedef struct slhdsa_key {
   /** Algorithm identifier (ltc_slhdsa_id) */
   int alg;
   /** Type of key, PK_PRIVATE or PK_PUBLIC */
   int type;
   /** Public key (verification key) */
   unsigned char *pk;
   unsigned long  pklen;
   /** Secret key (signing key, private only) */
   unsigned char *sk;
   unsigned long  sklen;
} slhdsa_key;

int slhdsa_make_key(prng_state *prng, int wprng, int alg, slhdsa_key *key);
int slhdsa_make_key_from_seed(int alg, const unsigned char *seed, unsigned long seedlen, slhdsa_key *key);
void slhdsa_free(slhdsa_key *key);

int slhdsa_check_key(const slhdsa_key *key);

int slhdsa_export_raw(unsigned char *out, unsigned long *outlen, int which, const slhdsa_key *key);
int slhdsa_import_raw(const unsigned char *in, unsigned long inlen, int which, int alg, slhdsa_key *key);
#ifdef LTC_DER
int slhdsa_export(unsigned char *out, unsigned long *outlen, int which, const slhdsa_key *key);
int slhdsa_import(const unsigned char *in, unsigned long inlen, slhdsa_key *key);
int slhdsa_import_x509(const unsigned char *in, unsigned long inlen, slhdsa_key *key);
#endif
#ifdef LTC_PKCS_8
int slhdsa_import_pkcs8(const unsigned char *in, unsigned long inlen, const password_ctx *pw_ctx, slhdsa_key *key);
#endif

int slhdsa_sign(const unsigned char *msg,  unsigned long  msglen,
                      unsigned char *sig,  unsigned long *siglen,
                const unsigned char *ctx,  unsigned long  ctxlen,
                      prng_state    *prng, int            wprng,
                const slhdsa_key    *key);

int slhdsa_sign_ex(const unsigned char *msg,     unsigned long  msglen,
                         unsigned char *sig,     unsigned long *siglen,
                   const unsigned char *ctx,     unsigned long  ctxlen,
                   const unsigned char *optrand, unsigned long  optrandlen,
                   const slhdsa_key    *key);

int slhdsa_verify(const unsigned char *sig,  unsigned long  siglen,
                  const unsigned char *msg,  unsigned long  msglen,
                  const unsigned char *ctx,  unsigned long  ctxlen,
                        int           *stat,
                  const slhdsa_key    *key);

int slhdsa_get_sizes(int alg,
                     unsigned long *public_key_sz,
                     unsigned long *secret_key_sz,
                     unsigned long *signature_sz,
                     unsigned long *optrand_sz,
                     unsigned long *keygen_seed_sz);

int slhdsa_find_alg(const char *name_or_oid, int *alg);
int slhdsa_alg_name(int alg, const char **name);

#endif /* LTC_SLHDSA */
