/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtomcrypt.org
 */

/**
  @file ecc_sys.c
  ECC Crypto, Tom St Denis
*/
  
/**
  Encrypt a symmetric key with ECC 
  @param in         The symmetric key you want to encrypt
  @param inlen      The length of the key to encrypt (octets)
  @param out        [out] The destination for the ciphertext
  @param outlen     [in/out] The max size and resulting size of the ciphertext
  @param prng       An active PRNG state
  @param wprng      The index of the PRNG you wish to use 
  @param hash       The index of the hash you want to use 
  @param key        The ECC key you want to encrypt to
  @return CRYPT_OK if successful
*/
int ecc_encrypt_key(const unsigned char *in,   unsigned long inlen,
                          unsigned char *out,  unsigned long *outlen, 
                          prng_state *prng, int wprng, int hash, 
                          ecc_key *key)
{
    unsigned char *pub_expt, *ecc_shared, *skey;
    ecc_key        pubkey;
    unsigned long  x, y, pubkeysize;
    int            err;

    LTC_ARGCHK(in      != NULL);
    LTC_ARGCHK(out     != NULL);
    LTC_ARGCHK(outlen  != NULL);
    LTC_ARGCHK(key     != NULL);

    /* check that wprng/cipher/hash are not invalid */
    if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
       return err;
    }

    if ((err = hash_is_valid(hash)) != CRYPT_OK) {
       return err;
    }

    if (inlen > hash_descriptor[hash].hashsize) {
       return CRYPT_INVALID_HASH;
    }

    /* make a random key and export the public copy */
    if ((err = ecc_make_key(prng, wprng, ecc_get_size(key), &pubkey)) != CRYPT_OK) {
       return err;
    }

    pub_expt   = XMALLOC(ECC_BUF_SIZE);
    ecc_shared = XMALLOC(ECC_BUF_SIZE);
    skey       = XMALLOC(MAXBLOCKSIZE);
    if (pub_expt == NULL || ecc_shared == NULL || skey == NULL) {
       if (pub_expt != NULL) {
          XFREE(pub_expt);
       }
       if (ecc_shared != NULL) {
          XFREE(ecc_shared);
       }
       if (skey != NULL) {
          XFREE(skey);
       }
       ecc_free(&pubkey);
       return CRYPT_MEM;
    }

    pubkeysize = ECC_BUF_SIZE;
    if ((err = ecc_export(pub_expt, &pubkeysize, PK_PUBLIC, &pubkey)) != CRYPT_OK) {
       ecc_free(&pubkey);
       goto LBL_ERR;
    }
    
    /* make random key */
    x        = ECC_BUF_SIZE;
    if ((err = ecc_shared_secret(&pubkey, key, ecc_shared, &x)) != CRYPT_OK) {
       ecc_free(&pubkey);
       goto LBL_ERR;
    }
    ecc_free(&pubkey);
    y = MAXBLOCKSIZE;
    if ((err = hash_memory(hash, ecc_shared, x, skey, &y)) != CRYPT_OK) {
       goto LBL_ERR;
    }
    
    /* Encrypt key */
    for (x = 0; x < inlen; x++) {
      skey[x] ^= in[x];
    }

    err = der_encode_sequence_multi(out, outlen,
                                    LTC_ASN1_OBJECT_IDENTIFIER,  hash_descriptor[hash].OIDlen,   hash_descriptor[hash].OID,
                                    LTC_ASN1_OCTET_STRING,       pubkeysize,                     pub_expt,
                                    LTC_ASN1_OCTET_STRING,       inlen,                          skey,
                                    LTC_ASN1_EOL,                0UL,                            NULL);

LBL_ERR:
#ifdef LTC_CLEAN_STACK
    /* clean up */
    zeromem(pub_expt,   ECC_BUF_SIZE);
    zeromem(ecc_shared, ECC_BUF_SIZE);
    zeromem(skey,       MAXBLOCKSIZE);
#endif

    XFREE(skey);
    XFREE(ecc_shared);
    XFREE(pub_expt);

    return err;
}

/**
  Decrypt an ECC encrypted key
  @param in       The ciphertext
  @param inlen    The length of the ciphertext (octets)
  @param out      [out] The plaintext
  @param outlen   [in/out] The max size and resulting size of the plaintext
  @param key      The corresponding private ECC key
  @return CRYPT_OK if successful
*/
int ecc_decrypt_key(const unsigned char *in,  unsigned long  inlen,
                          unsigned char *out, unsigned long *outlen, 
                          ecc_key *key)
{
   unsigned char *ecc_shared, *skey, *pub_expt;
   unsigned long  x, y, hashOID[32];
   int            hash, err;
   ecc_key        pubkey;
   ltc_asn1_list  decode[3];

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   /* right key type? */
   if (key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }
   
   /* decode to find out hash */
   LTC_SET_ASN1(decode, 0, LTC_ASN1_OBJECT_IDENTIFIER, hashOID, sizeof(hashOID)/sizeof(hashOID[0]));
 
   if ((err = der_decode_sequence(in, inlen, decode, 1)) != CRYPT_OK) {
      return err;
   }
   for (hash = 0; hash_descriptor[hash].name   != NULL             && 
                  (hash_descriptor[hash].OIDlen != decode[0].size   || 
                   memcmp(hash_descriptor[hash].OID, hashOID, sizeof(unsigned long)*decode[0].size)); hash++);

   if (hash_descriptor[hash].name == NULL) {
      return CRYPT_INVALID_PACKET;
   }

   /* we now have the hash! */

   /* allocate memory */
   pub_expt   = XMALLOC(ECC_BUF_SIZE);
   ecc_shared = XMALLOC(ECC_BUF_SIZE);
   skey       = XMALLOC(MAXBLOCKSIZE);
   if (pub_expt == NULL || ecc_shared == NULL || skey == NULL) {
      if (pub_expt != NULL) {
         XFREE(pub_expt);
      }
      if (ecc_shared != NULL) {
         XFREE(ecc_shared);
      }
      if (skey != NULL) {
         XFREE(skey);
      }
      return CRYPT_MEM;
   }
   LTC_SET_ASN1(decode, 1, LTC_ASN1_OCTET_STRING,      pub_expt,  ECC_BUF_SIZE);
   LTC_SET_ASN1(decode, 2, LTC_ASN1_OCTET_STRING,      skey,      MAXBLOCKSIZE);

   /* read the structure in now */
   if ((err = der_decode_sequence(in, inlen, decode, 3)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* import ECC key from packet */
   if ((err = ecc_import(decode[1].data, decode[1].size, &pubkey)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* make shared key */
   x = ECC_BUF_SIZE;
   if ((err = ecc_shared_secret(key, &pubkey, ecc_shared, &x)) != CRYPT_OK) {
      ecc_free(&pubkey);
      goto LBL_ERR;
   }
   ecc_free(&pubkey);

   y = MAXBLOCKSIZE;
   if ((err = hash_memory(hash, ecc_shared, x, ecc_shared, &y)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* ensure the hash of the shared secret is at least as big as the encrypt itself */
   if (decode[2].size > y) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   }

   /* avoid buffer overflow */
   if (*outlen < decode[2].size) {
      err = CRYPT_BUFFER_OVERFLOW;
      goto LBL_ERR;
   }

   /* Decrypt the key */
   for (x = 0; x < decode[2].size; x++) {
     out[x] = skey[x] ^ ecc_shared[x];
   }
   *outlen = x;

   err = CRYPT_OK;
LBL_ERR:
#ifdef LTC_CLEAN_STACK
   zeromem(pub_expt,   ECC_BUF_SIZE);
   zeromem(ecc_shared, ECC_BUF_SIZE);
   zeromem(skey,       MAXBLOCKSIZE);
#endif

   XFREE(pub_expt);
   XFREE(ecc_shared);
   XFREE(skey);

   return err;
}

/**
  Sign a message digest
  @param in        The message digest to sign
  @param inlen     The length of the digest
  @param out       [out] The destination for the signature
  @param outlen    [in/out] The max size and resulting size of the signature
  @param prng      An active PRNG state
  @param wprng     The index of the PRNG you wish to use
  @param key       A private ECC key
  @return CRYPT_OK if successful
*/
int ecc_sign_hash(const unsigned char *in,  unsigned long inlen, 
                        unsigned char *out, unsigned long *outlen, 
                        prng_state *prng, int wprng, ecc_key *key)
{
   ecc_key       pubkey;
   void          *r, *s, *e, *p;
   int           err;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   /* is this a private key? */
   if (key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }
   
   /* is the IDX valid ?  */
   if (is_valid_idx(key->idx) != 1) {
      return CRYPT_PK_INVALID_TYPE;
   }
   
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   /* get the hash and load it as a bignum into 'e' */
   /* init the bignums */
   if ((err = mp_init_multi(&r, &s, &p, &e, NULL)) != CRYPT_OK) { 
      ecc_free(&pubkey);
      goto LBL_ERR;
   }
   if ((err = mp_read_radix(p, (char *)ltc_ecc_sets[key->idx].order, 64)) != CRYPT_OK)        { goto error; }
   if ((err = mp_read_unsigned_bin(e, (unsigned char *)in, (int)inlen)) != CRYPT_OK)  { goto error; }

   /* make up a key and export the public copy */
   for (;;) {
      if ((err = ecc_make_key(prng, wprng, ecc_get_size(key), &pubkey)) != CRYPT_OK) {
         return err;
      }

      /* find r = x1 mod n */
      if ((err = mp_mod(pubkey.pubkey.x, p, r)) != CRYPT_OK)                           { goto error; }

      if (mp_iszero(r)) {
         ecc_free(&pubkey);
      } else { 
        /* find s = (e + xr)/k */
        if ((err = mp_invmod(pubkey.k, p, pubkey.k)) != CRYPT_OK)            { goto error; } /* k = 1/k */
        if ((err = mp_mulmod(key->k, r, p, s)) != CRYPT_OK)                 { goto error; } /* s = xr */
        if ((err = mp_add(e, s, s)) != CRYPT_OK)                      { goto error; } /* s = e +  xr */
        if ((err = mp_mod(s, p, s)) != CRYPT_OK)                      { goto error; } /* s = e +  xr */
        if ((err = mp_mulmod(s, pubkey.k, p, s)) != CRYPT_OK)               { goto error; } /* s = (e + xr)/k */

        if (mp_iszero(s)) {
           ecc_free(&pubkey);
        } else {
           break;
        }
      }
   }

   /* store as SEQUENCE { r, s -- integer } */
   err = der_encode_sequence_multi(out, outlen,
                             LTC_ASN1_INTEGER, 1UL, r,
                             LTC_ASN1_INTEGER, 1UL, s,
                             LTC_ASN1_EOL, 0UL, NULL);
   goto LBL_ERR;
error:
LBL_ERR:
   mp_clear_multi(r, s, p, e, NULL);
   ecc_free(&pubkey);

   return err;   
}

/* verify 
 *
 * w  = s^-1 mod n
 * u1 = xw 
 * u2 = rw
 * X = u1*G + u2*Q
 * v = X_x1 mod n
 * accept if v == r
 */

/**
   Verify an ECC signature
   @param sig         The signature to verify
   @param siglen      The length of the signature (octets)
   @param hash        The hash (message digest) that was signed
   @param hashlen     The length of the hash (octets)
   @param stat        Result of signature, 1==valid, 0==invalid
   @param key         The corresponding public ECC key
   @return CRYPT_OK if successful (even if the signature is not valid)
*/
int ecc_verify_hash(const unsigned char *sig,  unsigned long siglen,
                    const unsigned char *hash, unsigned long hashlen, 
                    int *stat, ecc_key *key)
{
   ecc_point    *mG, *mQ;
   void          *r, *s, *v, *w, *u1, *u2, *e, *p, *m;
   void          *mp;
   int           err;

   LTC_ARGCHK(sig  != NULL);
   LTC_ARGCHK(hash != NULL);
   LTC_ARGCHK(stat != NULL);
   LTC_ARGCHK(key  != NULL);

   /* default to invalid signature */
   *stat = 0;
   mp    = NULL;

   /* is the IDX valid ?  */
   if (is_valid_idx(key->idx) != 1) {
      return CRYPT_PK_INVALID_TYPE;
   }

   /* allocate ints */
   if ((err = mp_init_multi(&r, &s, &v, &w, &u1, &u2, &p, &e, &m, NULL)) != CRYPT_OK) {
      return CRYPT_MEM;
   }

   /* allocate points */
   mG = ltc_ecc_new_point();
   mQ = ltc_ecc_new_point();
   if (mQ  == NULL || mG == NULL) {
      err = CRYPT_MEM;
      goto done;
   }

   /* parse header */
   if ((err = der_decode_sequence_multi(sig, siglen,
                                  LTC_ASN1_INTEGER, 1UL, r,
                                  LTC_ASN1_INTEGER, 1UL, s,
                                  LTC_ASN1_EOL, 0UL, NULL)) != CRYPT_OK) {
      goto done;
   }

   /* get the order */
   if ((err = mp_read_radix(p, (char *)ltc_ecc_sets[key->idx].order, 64)) != CRYPT_OK)                  { goto error; }

   /* get the modulus */
   if ((err = mp_read_radix(m, (char *)ltc_ecc_sets[key->idx].prime, 64)) != CRYPT_OK)                  { goto error; }

   /* check for zero */
   if (mp_iszero(r) || mp_iszero(s) || mp_cmp(r, p) != LTC_MP_LT || mp_cmp(s, p) != LTC_MP_LT) {
      err = CRYPT_INVALID_PACKET;
      goto done;
   }

   /* read hash */
   if ((err = mp_read_unsigned_bin(e, (unsigned char *)hash, (int)hashlen)) != CRYPT_OK)                { goto error; }

   /*  w  = s^-1 mod n */
   if ((err = mp_invmod(s, p, w)) != CRYPT_OK)                                                          { goto error; }

   /* u1 = ew */
   if ((err = mp_mulmod(e, w, p, u1)) != CRYPT_OK)                                                      { goto error; }

   /* u2 = rw */
   if ((err = mp_mulmod(r, w, p, u2)) != CRYPT_OK)                                                      { goto error; }

   /* find mG = u1*G */
   if ((err = mp_read_radix(mG->x, (char *)ltc_ecc_sets[key->idx].Gx, 64)) != CRYPT_OK)                 { goto error; }
   if ((err = mp_read_radix(mG->y, (char *)ltc_ecc_sets[key->idx].Gy, 64)) != CRYPT_OK)                 { goto error; }
   mp_set(mG->z, 1);  
   if ((err = ltc_ecc_mulmod(u1, mG, mG, m, 0)) != CRYPT_OK)                                            { goto done; }

   /* find mQ = u2*Q */
   if ((err = mp_copy(key->pubkey.x, mQ->x)) != CRYPT_OK)                                               { goto error; }
   if ((err = mp_copy(key->pubkey.y, mQ->y)) != CRYPT_OK)                                               { goto error; }
   if ((err = mp_copy(key->pubkey.z, mQ->z)) != CRYPT_OK)                                               { goto error; }
   if ((err = ltc_ecc_mulmod(u2, mQ, mQ, m, 0)) != CRYPT_OK)                                            { goto done; }
  
   /* find the montgomery mp */
   if ((err = mp_montgomery_setup(m, &mp)) != CRYPT_OK)                                                 { goto error; }
   /* add them */
   if (ltc_mp.ecc_ptadd != NULL) {
      if ((err = ltc_mp.ecc_ptadd(mQ, mG, mG, m, mp)) != CRYPT_OK)                                      { goto done; }
   } else {
      if ((err = ltc_ecc_add_point(mQ, mG, mG, m, mp)) != CRYPT_OK)                                     { goto done; }
   }
   
   /* reduce */
   if (ltc_mp.ecc_map != NULL) {
      if ((err = ltc_mp.ecc_map(mG, m, mp)) != CRYPT_OK)                                                { goto done; }
   } else {
      if ((err = ltc_ecc_map(mG, m, mp)) != CRYPT_OK)                                                   { goto done; }
   }

   /* v = X_x1 mod n */
   if ((err = mp_mod(mG->x, p, v)) != CRYPT_OK)                                                         { goto done; }

   /* does v == r */
   if (mp_cmp(v, r) == LTC_MP_EQ) {
      *stat = 1;
   }

   /* clear up and return */
   err = CRYPT_OK;
   goto done;
error:
done:
   ltc_ecc_del_point(mG);
   ltc_ecc_del_point(mQ);
   mp_clear_multi(r, s, v, w, u1, u2, p, e, m, NULL);
   if (mp != NULL) { 
      mp_montgomery_free(mp);
   }
   return err;
}


/* $Source$ */
/* $Revision$ */
/* $Date$ */
