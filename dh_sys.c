int dh_encrypt_key(const unsigned char *inkey, unsigned long keylen,
                         unsigned char *out,  unsigned long *len,
                         prng_state *prng, int wprng, int hash,
                         dh_key *key)
{
    unsigned char pub_expt[1536], dh_shared[1536], skey[MAXBLOCKSIZE];
    dh_key pubkey;
    unsigned long x, y, z, hashsize, pubkeysize;
    int errno;

    _ARGCHK(inkey != NULL);
    _ARGCHK(out != NULL);
    _ARGCHK(len != NULL);
    _ARGCHK(key != NULL);

    /* check that wprng/hash are not invalid */
    if ((errno = prng_is_valid(wprng)) != CRYPT_OK) {
       return errno;
    }

    if ((errno = hash_is_valid(hash)) != CRYPT_OK) {
       return errno;
    }

    if (keylen > hash_descriptor[hash].hashsize)  {
        return CRYPT_INVALID_ARG;
    }

    /* make a random key and export the public copy */
    if ((errno = dh_make_key(prng, wprng, dh_get_size(key), &pubkey)) != CRYPT_OK) {
       return errno;
    }

    pubkeysize = sizeof(pub_expt);
    if ((errno = dh_export(pub_expt, &pubkeysize, PK_PUBLIC, &pubkey)) != CRYPT_OK) {
       dh_free(&pubkey);
       return errno;
    }

    /* now check if the out buffer is big enough */
    if (*len < (9 + PACKET_SIZE + pubkeysize + keylen)) {
       dh_free(&pubkey);
       return CRYPT_BUFFER_OVERFLOW;
    }

    /* make random key */
    hashsize  = hash_descriptor[hash].hashsize;

    x = sizeof(dh_shared);
    if ((errno = dh_shared_secret(&pubkey, key, dh_shared, &x)) != CRYPT_OK) {
       dh_free(&pubkey);
       return errno;
    }
    dh_free(&pubkey);

    z = sizeof(skey);
    if ((errno = hash_memory(hash, dh_shared, x, skey, &z)) != CRYPT_OK) {
       return errno;
    }

    /* output header */
    y = PACKET_SIZE;

    /* size of hash name and the name itself */
    out[y++] = hash_descriptor[hash].ID;

    /* length of DH pubkey and the key itself */
    STORE32L(pubkeysize, out+y);
    y += 4;
    for (x = 0; x < pubkeysize; x++, y++) {
        out[y] = pub_expt[x];
    }

    /* Store the encrypted key */
    STORE32L(keylen, out+y);
    y += 4;

    for (x = 0; x < keylen; x++, y++) {
      out[y] = skey[x] ^ inkey[x];
    }

    /* store header */
    packet_store_header(out, PACKET_SECT_DH, PACKET_SUB_ENC_KEY, y);

#ifdef CLEAN_STACK
    /* clean up */
    zeromem(pub_expt, sizeof(pub_expt));
    zeromem(dh_shared, sizeof(dh_shared));
    zeromem(skey, sizeof(skey));
#endif

    *len = y;
    return CRYPT_OK;
}

int dh_decrypt_key(const unsigned char *in, unsigned char *outkey, 
                         unsigned long *keylen, dh_key *key)
{
   unsigned char shared_secret[1536], skey[MAXBLOCKSIZE];
   unsigned long x, y, z, res, hashsize, keysize;
   int hash, errno;
   dh_key pubkey;

   _ARGCHK(in != NULL);
   _ARGCHK(outkey != NULL);
   _ARGCHK(keylen != NULL);
   _ARGCHK(key != NULL);

   /* right key type? */
   if (key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* is header correct? */
   if ((errno = packet_valid_header((unsigned char *)in, PACKET_SECT_DH, PACKET_SUB_ENC_KEY)) != CRYPT_OK)  {
      return errno;
   }

   /* now lets get the hash name */
   y = PACKET_SIZE;
   hash = find_hash_id(in[y++]);
   if (hash == -1) {
      return CRYPT_INVALID_HASH;
   }

   /* common values */
   hashsize  = hash_descriptor[hash].hashsize;

   /* get public key */
   LOAD32L(x, in+y);
   y += 4;
   if ((errno = dh_import(in+y, x, &pubkey)) != CRYPT_OK) {
      return errno;
   }
   y += x;

   /* make shared key */
   x = sizeof(shared_secret);
   if ((errno = dh_shared_secret(key, &pubkey, shared_secret, &x)) != CRYPT_OK) {
      dh_free(&pubkey);
      return errno;
   }
   dh_free(&pubkey);

   z = sizeof(skey);
   if ((errno = hash_memory(hash, shared_secret, x, skey, &z)) != CRYPT_OK) {
      return errno;
   }

   /* load in the encrypted key */
   LOAD32L(keysize, in+y);
   if (keysize > *keylen) {
       res = CRYPT_BUFFER_OVERFLOW;
       goto done;
   }
   y += 4;

   *keylen = keysize;

   for (x = 0; x < keysize; x++, y++) {
      outkey[x] = skey[x] ^ in[y];
   }

   res = CRYPT_OK;
done:
#ifdef CLEAN_STACK
   zeromem(shared_secret, sizeof(shared_secret));
   zeromem(skey, sizeof(skey));
#endif
   return res;
}


int dh_sign_hash(const unsigned char *in,  unsigned long inlen,
                       unsigned char *out, unsigned long *outlen,
                       prng_state *prng, int wprng, dh_key *key)
{
   mp_int a, b, k, m, g, p, p1, tmp;
   unsigned char buf[1536], md[MAXBLOCKSIZE];
   unsigned long x, y;
   int res, errno;

   _ARGCHK(in != NULL);
   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);
   _ARGCHK(key != NULL);

   /* check parameters */
   if (key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   if ((errno = prng_is_valid(wprng)) != CRYPT_OK) {
      return errno;
   }

   /* is the IDX valid ?  */
   if (!is_valid_idx(key->idx)) {
      return CRYPT_PK_INVALID_TYPE;
   }

   /* hash the message */
   md[0] = 0;
   memcpy(md+1, in, MIN(sizeof(md) - 1, inlen));

   /* make up a random value k,
    * since the order of the group is prime
    * we need not check if gcd(k, r) is 1 
    */
   buf[0] = 0;
   if (prng_descriptor[wprng].read(buf+1, sets[key->idx].size-1, prng) != 
       (unsigned long)(sets[key->idx].size-1)) {
      return CRYPT_ERROR_READPRNG;
   }

   /* init bignums */
   if (mp_init_multi(&a, &b, &k, &m, &p, &g, &p1, &tmp, NULL) != MP_OKAY) { 
      return CRYPT_MEM;
   }

   /* load k and m */
   if (mp_read_raw(&m, md,  1+MIN(sizeof(md) - 1, inlen)) != MP_OKAY)       { goto error; }
   if (mp_read_raw(&k, buf, sets[key->idx].size) != MP_OKAY)                { goto error; }

   /* load g, p and p1 */
   if (mp_read_radix(&g, sets[key->idx].base, 10) != MP_OKAY)               { goto error; }
   if (mp_read_radix(&p, sets[key->idx].prime, 10) != MP_OKAY)              { goto error; }
   if (mp_sub_d(&p, 1, &p1) != MP_OKAY)                                     { goto error; }
   if (mp_div_2(&p1, &p1) != MP_OKAY)                                       { goto error; } /* p1 = (p-1)/2 */

   /* now get a = g^k mod p */
   if (mp_exptmod(&g, &k, &p, &a) != MP_OKAY)                               { goto error; }

   /* now find M = xa + kb mod p1 or just b = (M - xa)/k mod p1 */
   if (mp_invmod(&k, &p1, &k) != MP_OKAY)                                   { goto error; } /* k = 1/k mod p1 */
   if (mp_mulmod(&a, &key->x, &p1, &tmp) != MP_OKAY)                        { goto error; } /* tmp = xa */
   if (mp_submod(&m, &tmp, &p1, &tmp) != MP_OKAY)                           { goto error; } /* tmp = M - xa */
   if (mp_mulmod(&k, &tmp, &p1, &b) != MP_OKAY)                             { goto error; } /* b = (M - xa)/k */

   /* store header  */
   y = PACKET_SIZE;

   /* now store them both (a,b) */
   x = mp_raw_size(&a);
   STORE32L(x, buf+y);  y += 4;
   mp_toraw(&a, buf+y); y += x;

   x = mp_raw_size(&b);
   STORE32L(x, buf+y);  y += 4;
   mp_toraw(&b, buf+y); y += x;

   /* check if size too big */
   if (*outlen < y) {
      res = CRYPT_BUFFER_OVERFLOW;
      goto done;
   }

   /* store header */
   packet_store_header(buf, PACKET_SECT_DH, PACKET_SUB_SIGNED, y);

   /* store it */
   memcpy(out, buf, y);
   *outlen = y;
#ifdef CLEAN_STACK
   zeromem(md, sizeof(md));
   zeromem(buf, sizeof(buf));
#endif

   res = CRYPT_OK;
   goto done;
error:
   res = CRYPT_MEM;
done:
   mp_clear_multi(&tmp, &p1, &g, &p, &m, &k, &b, &a, NULL);
   return res;
}

int dh_verify_hash(const unsigned char *sig, const unsigned char *hash, 
                         unsigned long inlen, int *stat, 
                         dh_key *key)
{
   mp_int a, b, p, g, m, tmp;
   unsigned char md[MAXBLOCKSIZE];
   unsigned long x, y;
   int res, errno;

   _ARGCHK(sig != NULL);
   _ARGCHK(hash != NULL);
   _ARGCHK(stat != NULL);
   _ARGCHK(key != NULL);

   /* default to invalid */
   *stat = 0;

   /* header ok? */
   if ((errno = packet_valid_header((unsigned char *)sig, PACKET_SECT_DH, PACKET_SUB_SIGNED)) != CRYPT_OK) {
      return errno;
   }

   /* get hash out of packet */
   y = PACKET_SIZE;

   /* hash the message */
   md[0] = 0;
   memcpy(md+1, hash, MIN(sizeof(md) - 1, inlen));

   /* init all bignums */
   if (mp_init_multi(&a, &p, &b, &g, &m, &tmp, NULL) != MP_OKAY) { 
      return CRYPT_MEM;
   }

   /* load a and b */
   LOAD32L(x, sig+y);
   y += 4;
   if (mp_read_raw(&a, (unsigned char *)sig+y, x) != MP_OKAY)            { goto error; }
   y += x;

   LOAD32L(x, sig+y);
   y += 4;
   if (mp_read_raw(&b, (unsigned char *)sig+y, x) != MP_OKAY)            { goto error; }
   y += x;

   /* load p and g */
   if (mp_read_radix(&p, sets[key->idx].prime, 10) != MP_OKAY)           { goto error; }
   if (mp_read_radix(&g, sets[key->idx].base, 10) != MP_OKAY)            { goto error; }

   /* load m */
   if (mp_read_raw(&m, md, 1+MIN(sizeof(md)-1, inlen)) != MP_OKAY)       { goto error; }

   /* find g^m mod p */
   if (mp_exptmod(&g, &m, &p, &m) != MP_OKAY)                            { goto error; } /* m = g^m mod p */

   /* find y^a * a^b */
   if (mp_exptmod(&key->y, &a, &p, &tmp) != MP_OKAY)                     { goto error; } /* tmp = y^a mod p */
   if (mp_exptmod(&a, &b, &p, &a) != MP_OKAY)                            { goto error; } /* a = a^b mod p */
   if (mp_mulmod(&a, &tmp, &p, &a) != MP_OKAY)                           { goto error; } /* a = y^a * a^b mod p */

   /* y^a * a^b == g^m ??? */
   if (mp_cmp(&a, &m) == 0) {
      *stat = 1;
   }

   /* clean up */
   res = CRYPT_OK;
   goto done;
error:
   res = CRYPT_MEM;
done:
   mp_clear_multi(&tmp, &m, &g, &p, &b, &a, NULL);
#ifdef CLEAN_STACK
   zeromem(md, sizeof(md));
#endif
   return res;
}

