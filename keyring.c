/* Provides keyring functionality for libtomcrypt, Tom St Denis */
#include <mycrypt.h>

#ifdef KR

static const unsigned char key_magic[4]  = { 0x12, 0x34, 0x56, 0x78 };
static const unsigned char file_magic[4] = { 0x9A, 0xBC, 0xDE, 0xF0 };
static const unsigned char sign_magic[4] = { 0x87, 0x56, 0x43, 0x21 };
static const unsigned char enc_magic[4]  = { 0x0F, 0xED, 0xCB, 0xA9 };

static const unsigned long crc_table[256] = {
  0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
  0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
  0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
  0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
  0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
  0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
  0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
  0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
  0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
  0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
  0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
  0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
  0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
  0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
  0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
  0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
  0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
  0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
  0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
  0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
  0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
  0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
  0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
  0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
  0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
  0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
  0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
  0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
  0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
  0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
  0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
  0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
  0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
  0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
  0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
  0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
  0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
  0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
  0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
  0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
  0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
  0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
  0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
  0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
  0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
  0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
  0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
  0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
  0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
  0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
  0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
  0x2d02ef8dL
};

#define DO1(buf) crc = crc_table[((int)crc ^ (*buf++)) & 0xff] ^ (crc >> 8);
#define DO2(buf)  DO1(buf); DO1(buf);
#define DO4(buf)  DO2(buf); DO2(buf);
#define DO8(buf)  DO4(buf); DO4(buf);

static unsigned long crc32 (unsigned long crc, const unsigned char *buf, unsigned long len)
{
  crc = crc ^ 0xffffffffL;
  while (len >= 8) {
      DO8 (buf);
      len -= 8;
  }
  if (len) {
    do {
	   DO1 (buf);
    } while (--len);
  }    
  return crc ^ 0xffffffffUL;
}

int kr_init(pk_key **pk)
{
   _ARGCHK(pk != NULL);

   *pk = XCALLOC(1, sizeof(pk_key));
   if (*pk == NULL) {
      return CRYPT_MEM;
   }
   (*pk)->system = NON_KEY;
   return CRYPT_OK;
}

unsigned long kr_crc(const unsigned char *name, const unsigned char *email, const unsigned char *description)
{
   unsigned long crc;
   _ARGCHK(name != NULL);
   _ARGCHK(email != NULL);
   _ARGCHK(description != NULL);
   crc = crc32(0, NULL, 0);
   crc = crc32(crc, name,  MIN(MAXLEN, strlen((char *)name)));
   crc = crc32(crc, email, MIN(MAXLEN, strlen((char *)email)));
   return crc32(crc, description, MIN(MAXLEN, strlen((char *)description)));
}

pk_key *kr_find(pk_key *pk, unsigned long ID)
{
   _ARGCHK(pk != NULL);

   while (pk != NULL) {
        if (pk->system != NON_KEY && pk->ID == ID) {
           return pk;
        }
        pk = pk->next;
   }
   return NULL;
}

pk_key *kr_find_name(pk_key *pk, const char *name)
{
   _ARGCHK(pk != NULL);
   _ARGCHK(name != NULL);

   while (pk != NULL) {
        if (pk->system != NON_KEY && !strncmp((char *)pk->name, (char *)name, sizeof(pk->name)-1)) {
           return pk;
        }
        pk = pk->next;
   }
   return NULL;
}
 

int kr_add(pk_key *pk, int key_type, int system, const unsigned char *name, 
           const unsigned char *email, const unsigned char *description, const _pk_key *key)
{
   _ARGCHK(pk != NULL);
   _ARGCHK(name != NULL);
   _ARGCHK(email != NULL);
   _ARGCHK(description != NULL);
   _ARGCHK(key != NULL);

   /* check parameters */
   if (key_type != PK_PRIVATE && key_type != PK_PRIVATE_OPTIMIZED && key_type != PK_PUBLIC) {
      return CRYPT_PK_INVALID_TYPE;
   }
 
   if (system != RSA_KEY && system != DH_KEY && system != ECC_KEY) {
      return CRYPT_PK_INVALID_SYSTEM;
   }

   /* see if its a dupe  */
   if (kr_find(pk, kr_crc(name, email, description)) != NULL) {
      return CRYPT_PK_DUP;
   }
   
   /* find spot in key ring */
   while (pk->system != NON_KEY) {
         if (pk->next == NULL) {
            return CRYPT_ERROR;
         }
         pk = pk->next;
   }

   /* now we have a spot make a next spot */
   pk->next = XCALLOC(1, sizeof(pk_key));
   if (pk->next == NULL) {
      return CRYPT_MEM;
   }
   pk->next->system = NON_KEY;

   /* now add this new data to this ring spot */
   pk->key_type = key_type;
   pk->system   = system;
   strncpy((char *)pk->name, (char *)name, sizeof(pk->name)-1);
   strncpy((char *)pk->email, (char *)email, sizeof(pk->email)-1);
   strncpy((char *)pk->description, (char *)description, sizeof(pk->description)-1);
   pk->ID       = kr_crc(pk->name, pk->email, pk->description);

   /* clear the memory area */
   zeromem(&(pk->key), sizeof(pk->key));

   /* copy the key */
   switch (system) {
         case RSA_KEY:
              memcpy(&(pk->key.rsa), &(key->rsa), sizeof(key->rsa));
              break;
         case DH_KEY:
              memcpy(&(pk->key.dh), &(key->dh), sizeof(key->dh));
              break;
         case ECC_KEY:
              memcpy(&(pk->key.ecc), &(key->ecc), sizeof(key->ecc));
              break;
   }
   return CRYPT_OK;
}

int kr_del(pk_key **_pk, unsigned long ID)
{
   pk_key *ppk, *pk;

   _ARGCHK(_pk != NULL);

   pk  = *_pk;
   ppk = NULL;
   while (pk->system != NON_KEY && pk->ID != ID) {
        ppk = pk;
        pk  = pk->next;
        if (pk == NULL) {
           return CRYPT_PK_NOT_FOUND;
        }
   }

   switch (pk->system) {
        case RSA_KEY:
            rsa_free(&(pk->key.rsa));
            break;
        case DH_KEY:
            dh_free(&(pk->key.dh));
            break;
        case ECC_KEY:
            ecc_free(&(pk->key.ecc));
            break;
   }

   if (ppk == NULL) {       /* the first element matches the ID */
      ppk = pk->next;       /* get the 2nd element */
      XFREE(pk);             /* free the first */
      *_pk = ppk;           /* make the first element the second */
   } else {                 /* (not) first element matches the ID */
      ppk->next = pk->next; /* make the previous'es next point to the current next */
      XFREE(pk);             /* free the element */
   }
   return CRYPT_OK;
}

int kr_clear(pk_key **pk)
{
   int errno;
   _ARGCHK(pk != NULL);

   while ((*pk)->system != NON_KEY) {
       if ((errno = kr_del(pk, (*pk)->ID)) != CRYPT_OK) { 
          return errno;
       }
   }       
   XFREE(*pk);
   *pk = NULL;
   return CRYPT_OK;
}

static unsigned long _write(unsigned char *buf, unsigned long len, FILE *f, symmetric_CTR *ctr)
{
#ifdef NO_FILE
   return 0;
#else
   _ARGCHK(buf != NULL);
   _ARGCHK(f   != NULL);
   if (ctr != NULL) {
      if (ctr_encrypt(buf, buf, len, ctr) != CRYPT_OK) {
         return 0;
      }
   }
   return fwrite(buf, 1, len, f);
#endif
}

static unsigned long _read(unsigned char *buf, unsigned long len, FILE *f, symmetric_CTR *ctr)
{
#ifdef NO_FILE
    return 0;
#else
   unsigned long y;
   _ARGCHK(buf != NULL);
   _ARGCHK(f   != NULL);
   y = fread(buf, 1, len, f);
   if (ctr != NULL) {
      if (ctr_decrypt(buf, buf, y, ctr) != CRYPT_OK) {
         return 0;
      }
   }
   return y;
#endif
}

int kr_export(pk_key *pk, unsigned long ID, int key_type, unsigned char *out, unsigned long *outlen)
{
   unsigned char buf[8192], *obuf;
   pk_key *ppk;
   unsigned long len;
   int errno;

   _ARGCHK(pk != NULL);
   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);

   /* find the desired key */
   ppk = kr_find(pk, ID);
   if (ppk == NULL) {
      return CRYPT_PK_NOT_FOUND;
   }

   if (ppk->key_type == PK_PUBLIC && key_type != PK_PUBLIC) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* this makes PK_PRIVATE an alias for PK_PRIVATE_OPTIMIZED type */
   if (ppk->key_type == PK_PRIVATE_OPTIMIZED && key_type == PK_PRIVATE) {
      key_type = PK_PRIVATE_OPTIMIZED;
   }

   /* now copy the header and various other details */
   memcpy(buf, key_magic, 4);                              /* magic info */
   buf[4] = key_type;                                      /* key type */
   buf[5] = ppk->system;                                   /* system */
   STORE32L(ppk->ID, buf+6);                               /* key ID */
   memcpy(buf+10, ppk->name, MAXLEN);                      /* the name */
   memcpy(buf+10+MAXLEN, ppk->email, MAXLEN);              /* the email */
   memcpy(buf+10+MAXLEN+MAXLEN, ppk->description, MAXLEN); /* the description */
   
   /* export key */
   len = sizeof(buf) - (6 + 4 + MAXLEN*3);
   obuf = buf+6+4+MAXLEN*3;
   switch (ppk->system) {
       case RSA_KEY:
           if ((errno = rsa_export(obuf, &len, key_type, &(ppk->key.rsa))) != CRYPT_OK) {
              return errno;
           }
           break;
       case DH_KEY:
           if ((errno = dh_export(obuf, &len, key_type, &(ppk->key.dh))) != CRYPT_OK) {
              return errno;
           }
           break;
       case ECC_KEY:
           if ((errno = ecc_export(obuf, &len, key_type, &(ppk->key.ecc))) != CRYPT_OK) {
              return errno;
           }
           break;
   }

   /* get the entire length of the packet */
   len += 6 + 4 + 3*MAXLEN;

   if (*outlen < len) {
      #ifdef CLEAN_STACK
          zeromem(buf, sizeof(buf));
      #endif
      return CRYPT_BUFFER_OVERFLOW;
   } else {
      *outlen = len;
      memcpy(out, buf, len);
      #ifdef CLEAN_STACK
          zeromem(buf, sizeof(buf));
      #endif
      return CRYPT_OK;
   }
}

int kr_import(pk_key *pk, const unsigned char *in, unsigned long inlen)
{
   _pk_key key;
   int system, key_type, errno;
   unsigned long ID;

   _ARGCHK(pk != NULL);
   _ARGCHK(in != NULL);

   if (inlen < 10) {
      return CRYPT_INVALID_PACKET;
   }

   if (memcmp(in, key_magic, 4)) {
      return CRYPT_INVALID_PACKET;
   }
   key_type = in[4];                                 /* get type */
   system   = in[5];                                 /* get system */
   LOAD32L(ID,in+6);                                 /* the ID */

   if (ID != kr_crc(in+10, in+10+MAXLEN, in+10+MAXLEN+MAXLEN)) {
      return CRYPT_INVALID_PACKET;
   }

   zeromem(&key, sizeof(key));
   
   /* size of remaining packet */
   inlen -= 10 + 3*MAXLEN;
   
   switch (system) {
        case RSA_KEY:
            if ((errno = rsa_import(in+10+3*MAXLEN, inlen, &(key.rsa))) != CRYPT_OK) {
               return errno;
            }
            break;
        case DH_KEY:
            if ((errno = dh_import(in+10+3*MAXLEN, inlen, &(key.dh))) != CRYPT_OK) {
               return errno;
            }
            break;
        case ECC_KEY:
            if ((errno = ecc_import(in+10+3*MAXLEN, inlen, &(key.ecc))) != CRYPT_OK) {
               return errno;
            }
            break;
   }
   return kr_add(pk, key_type, system, 
                 in+10,                           /* the name */
                 in+10+MAXLEN,                    /* email address */
                 in+10+MAXLEN+MAXLEN,             /* description */
                 &key);
}


int kr_load(pk_key **pk, FILE *in, symmetric_CTR *ctr)
{
   unsigned char buf[8192], blen[4];
   unsigned long len;
   int res, errno;

   _ARGCHK(pk != NULL);
   _ARGCHK(in != NULL);

   /* init keyring */
   if ((errno = kr_init(pk)) != CRYPT_OK) { 
      return errno; 
   }

   /* read in magic bytes */
   if (_read(buf, 6, in, ctr) != 6)           { goto done2; }

   if (memcmp(buf, file_magic, 4)) {
      return CRYPT_INVALID_PACKET;
   }

   len = (unsigned long)buf[4] | ((unsigned long)buf[5] << 8);
   if (len > CRYPT) {
      return CRYPT_INVALID_PACKET;
   }

   /* while there are lengths to read... */
   while (_read(blen, 4, in, ctr) == 4) {
      /* get length */
      LOAD32L(len, blen);

      if (len > sizeof(buf)) {
         return CRYPT_INVALID_PACKET;
      }

      if (_read(buf, len, in, ctr) != len)           { goto done2; }
      if ((errno = kr_import(*pk, buf, len)) != CRYPT_OK) { 
         return errno; 
      }
   }

   res = CRYPT_OK;
   goto done;
done2:
   res = CRYPT_ERROR;
done:
#ifdef CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif
   return res;
}

int kr_save(pk_key *pk, FILE *out, symmetric_CTR *ctr)
{
   unsigned char buf[8192], blen[4];
   unsigned long len;
   int res, errno;

   _ARGCHK(pk != NULL);
   _ARGCHK(out != NULL);

   /* write out magic bytes */
   memcpy(buf, file_magic, 4);
   buf[4] = CRYPT&255;
   buf[5] = (CRYPT>>8)&255;
   if (_write(buf, 6, out, ctr) != 6)           { goto done2; }

   while (pk->system != NON_KEY) {
         len = sizeof(buf);
         if ((errno = kr_export(pk, pk->ID, pk->key_type, buf, &len)) != CRYPT_OK) { 
            return errno;
         }
          
         STORE32L(len, blen);
         if (_write(blen, 4, out, ctr) != 4)    { goto done2; }
         if (_write(buf, len, out, ctr) != len) { goto done2; }

         pk = pk->next;
   }
         
   res = CRYPT_OK;
   goto done;
done2:
   res = CRYPT_ERROR;
done:
#ifdef CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif
   return res;
}

int kr_make_key(pk_key *pk, prng_state *prng, int wprng, 
                int system, int keysize, const unsigned char *name,
                const unsigned char *email, const unsigned char *description)
{
   _pk_key key;
   int key_type, errno;

   _ARGCHK(pk != NULL);
   _ARGCHK(name != NULL);
   _ARGCHK(email != NULL);
   _ARGCHK(description != NULL);

   /* valid PRNG? */
   if ((errno = prng_is_valid(wprng)) != CRYPT_OK) {
      return errno;
   }

   /* make the key first */
   zeromem(&key, sizeof(key));
   switch (system) {
      case RSA_KEY: 
          if ((errno = rsa_make_key(prng, wprng, keysize, 65537, &(key.rsa))) != CRYPT_OK) {
             return errno;
          }
          key_type = key.rsa.type;
          break;
      case DH_KEY: 
          if ((errno = dh_make_key(prng, wprng, keysize, &(key.dh))) != CRYPT_OK) {
             return errno;
          }
          key_type = key.dh.type;
          break;
      case ECC_KEY: 
          if ((errno = ecc_make_key(prng, wprng, keysize, &(key.ecc))) != CRYPT_OK) {
             return errno;
          }
          key_type = key.ecc.type;
          break;
      default:
          return CRYPT_PK_INVALID_SYSTEM;
   }

   /* now add the key */
   if ((errno = kr_add(pk, key_type, system, name, email, description, &key)) != CRYPT_OK) {
      return errno;
   }

#ifdef CLEAN_STACK
   zeromem(&key, sizeof(key));
#endif
   return CRYPT_OK;
}

int kr_encrypt_key(pk_key *pk, unsigned long ID, 
                   const unsigned char *in, unsigned long inlen,
                   unsigned char *out, unsigned long *outlen,
                   prng_state *prng, int wprng, int hash)
{
   unsigned char buf[8192];
   unsigned long len;
   pk_key *kr;
   int errno;

   _ARGCHK(pk != NULL);
   _ARGCHK(in != NULL);
   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);

   /* find the key */
   kr = kr_find(pk, ID);
   if (kr == NULL) {
      return CRYPT_PK_NOT_FOUND;
   }

   /* store the header */
   memcpy(buf, enc_magic, 4);

   /* now store the ID */
   STORE32L(kr->ID,buf+4);

   /* now encrypt it */
   len = sizeof(buf)-8;
   switch (kr->system) {
        case RSA_KEY:
            if ((errno = rsa_encrypt_key(in, inlen, buf+8, &len, prng, wprng, &(kr->key.rsa))) != CRYPT_OK) {
               return errno;
            }
            break;
        case DH_KEY:
            if ((errno = dh_encrypt_key(in, inlen, buf+8, &len, prng, wprng, hash, &(kr->key.dh))) != CRYPT_OK) {
               return errno;
            }
            break;
        case ECC_KEY:
            if ((errno = ecc_encrypt_key(in, inlen, buf+8, &len, prng, wprng, hash, &(kr->key.ecc))) != CRYPT_OK) {
               return errno;
            }
            break;
    }
    len += 8;

    if (len > *outlen) {
       #ifdef CLEAN_STACK
           zeromem(buf, sizeof(buf));
       #endif
       return CRYPT_BUFFER_OVERFLOW;
    } else {
       memcpy(out, buf, len);
       #ifdef CLEAN_STACK
           zeromem(buf, sizeof(buf));
       #endif
       *outlen = len;
       return CRYPT_OK;
    }
}

int kr_decrypt_key(pk_key *pk, const unsigned char *in,
                   unsigned char *out, unsigned long *outlen)
{
   unsigned char buf[8192];
   unsigned long len, ID;
   pk_key *kr;
   int errno;

   _ARGCHK(pk != NULL);
   _ARGCHK(in != NULL);
   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);

   /* check magic header */
   if (memcmp(in, enc_magic, 4)) {
      return CRYPT_INVALID_PACKET;
   }

   /* now try to find key */
   LOAD32L(ID,in+4);
   kr = kr_find(pk, ID);
   if (kr == NULL) {
      return CRYPT_PK_NOT_FOUND;
   }

   /* is it public? */
   if (kr->key_type == PK_PUBLIC) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* now try and decrypt it */
   len = sizeof(buf);
   switch (kr->system) {
       case RSA_KEY:
           if ((errno = rsa_decrypt_key(in+8, buf, &len, &(kr->key.rsa))) != CRYPT_OK) {
              return errno;
           }
           break;
       case DH_KEY:
           if ((errno = dh_decrypt_key(in+8, buf, &len, &(kr->key.dh))) != CRYPT_OK) {
              return errno;
           }
           break;
       case ECC_KEY:
           if ((errno = ecc_decrypt_key(in+8, buf, &len, &(kr->key.ecc))) != CRYPT_OK) {
              return errno;
           }
           break;
   }

    if (len > *outlen) {
       #ifdef CLEAN_STACK
           zeromem(buf, sizeof(buf));
       #endif
       return CRYPT_BUFFER_OVERFLOW;
    } else {
       memcpy(out, buf, len);
       #ifdef CLEAN_STACK
           zeromem(buf, sizeof(buf));
       #endif
       *outlen = len;
       return CRYPT_OK;
    }
}

int kr_sign_hash(pk_key *pk, unsigned long ID, 
                 const unsigned char *in, unsigned long inlen,
                 unsigned char *out, unsigned long *outlen,
                 prng_state *prng, int wprng)
{
   unsigned char buf[8192];
   unsigned long len;
   pk_key *kr;
   int errno;

   _ARGCHK(pk != NULL);
   _ARGCHK(in != NULL);
   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);

   /* find the key */
   kr = kr_find(pk, ID);
   if (kr == NULL) {
      return CRYPT_PK_NOT_FOUND;
   }

   /* is it public? */
   if (kr->key_type == PK_PUBLIC) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* store the header */
   memcpy(buf, sign_magic, 4);

   /* now store the ID */
   STORE32L(kr->ID,buf+4);

   /* now sign it */
   len = sizeof(buf)-12;
   switch (kr->system) {
        case RSA_KEY:
            if ((errno = rsa_sign_hash(in, inlen, buf+12, &len, &(kr->key.rsa))) != CRYPT_OK) {
               return errno;
            }
            break;
        case DH_KEY:
            if ((errno = dh_sign_hash(in, inlen, buf+12, &len, prng, wprng, &(kr->key.dh))) != CRYPT_OK) {
               return errno;
            }
            break;
        case ECC_KEY:
            if ((errno = ecc_sign_hash(in, inlen, buf+12, &len, prng, wprng, &(kr->key.ecc))) != CRYPT_OK) {
               return errno;
            }
            break;
    }
    STORE32L(inlen,buf+8);
    len += 12;

    if (len > *outlen) {
       #ifdef CLEAN_STACK
           zeromem(buf, sizeof(buf));
       #endif
       return CRYPT_BUFFER_OVERFLOW;
    } else {
       memcpy(out, buf, len);
       #ifdef CLEAN_STACK
           zeromem(buf, sizeof(buf));
       #endif
       *outlen = len;
       return CRYPT_OK;
    }
}

int kr_verify_hash(pk_key *pk, const unsigned char *in, const unsigned char *hash, 
                   unsigned long hashlen, int *stat)
{
   unsigned long inlen, ID;
   pk_key *kr;
   int errno;

   _ARGCHK(pk != NULL);
   _ARGCHK(in != NULL);
   _ARGCHK(hash != NULL);
   _ARGCHK(stat != NULL);

   /* default to not match */
   *stat = 0;

   /* check magic header */
   if (memcmp(in, sign_magic, 4)) {
      return CRYPT_INVALID_PACKET;
   }

   /* now try to find key */
   LOAD32L(ID,in+4);
   kr = kr_find(pk, ID);
   if (kr == NULL) {
      return CRYPT_PK_NOT_FOUND;
   }

   /* now try and verify it */
   LOAD32L(inlen,in+8);         /* this is the length of the original inlen */
   if (inlen != hashlen) {      /* size doesn't match means the signature is invalid */
      return CRYPT_OK;
   }

   switch (kr->system) {
       case RSA_KEY:
           if ((errno = rsa_verify_hash(in+12, hash, stat, &(kr->key.rsa))) != CRYPT_OK) {
              return errno;
           }
           break;
       case DH_KEY:
           if ((errno = dh_verify_hash(in+12, hash, inlen, stat, &(kr->key.dh))) != CRYPT_OK) {
              return errno;
           }
           break;
       case ECC_KEY:
           if ((errno = ecc_verify_hash(in+12, hash, inlen, stat, &(kr->key.ecc))) != CRYPT_OK) {
              return errno;
           }
           break;
   }
   return CRYPT_OK;
}

int kr_fingerprint(pk_key *pk, unsigned long ID, int hash,
                   unsigned char *out, unsigned long *outlen)
{
   unsigned char buf[8192];
   unsigned long len;
   int errno;

   _ARGCHK(pk != NULL);
   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);

   /* valid hash? */
   if ((errno = hash_is_valid(hash)) != CRYPT_OK) {
      return errno;
   }

   len = sizeof(buf);
   if ((errno = kr_export(pk, ID, PK_PUBLIC, buf, &len)) != CRYPT_OK) {
      return errno;
   }
   
   /* now hash it */
   if ((errno = hash_memory(hash, buf, len, out, outlen)) != CRYPT_OK) {
      return errno;
   }

#ifdef CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif
   return CRYPT_OK;
}

#endif


