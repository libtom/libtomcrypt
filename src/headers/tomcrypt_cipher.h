/* ---- SYMMETRIC KEY STUFF -----
 *
 * We put each of the ciphers scheduled keys in their own structs then we put all of 
 * the key formats in one union.  This makes the function prototypes easier to use.
 */
#ifdef BLOWFISH
struct blowfish_key {
   ulong32 S[4][256];
   ulong32 K[18];
};
#endif

#ifdef RC5
struct rc5_key {
   int rounds;
   ulong32 K[50];
};
#endif

#ifdef RC6
struct rc6_key {
   ulong32 K[44];
};
#endif

#ifdef SAFERP
struct saferp_key {
   unsigned char K[33][16];
   long rounds;
};
#endif

#ifdef RIJNDAEL
struct rijndael_key {
   ulong32 eK[64], dK[64];
   int Nr;
};
#endif

#ifdef XTEA
struct xtea_key {
   unsigned long A[32], B[32];
};
#endif

#ifdef TWOFISH
#ifndef TWOFISH_SMALL
   struct twofish_key {
      ulong32 S[4][256], K[40];
   };
#else
   struct twofish_key {
      ulong32 K[40];
      unsigned char S[32], start;
   };
#endif
#endif

#ifdef SAFER
#define SAFER_K64_DEFAULT_NOF_ROUNDS     6
#define SAFER_K128_DEFAULT_NOF_ROUNDS   10
#define SAFER_SK64_DEFAULT_NOF_ROUNDS    8
#define SAFER_SK128_DEFAULT_NOF_ROUNDS  10
#define SAFER_MAX_NOF_ROUNDS            13
#define SAFER_BLOCK_LEN                  8
#define SAFER_KEY_LEN     (1 + SAFER_BLOCK_LEN * (1 + 2 * SAFER_MAX_NOF_ROUNDS))
typedef unsigned char safer_block_t[SAFER_BLOCK_LEN];
typedef unsigned char safer_key_t[SAFER_KEY_LEN];
struct safer_key { safer_key_t key; };
#endif

#ifdef RC2
struct rc2_key { unsigned xkey[64]; };
#endif

#ifdef DES
struct des_key {
    ulong32 ek[32], dk[32];
};

struct des3_key {
    ulong32 ek[3][32], dk[3][32];
};
#endif

#ifdef CAST5
struct cast5_key {
    ulong32 K[32], keylen;
};
#endif

#ifdef NOEKEON
struct noekeon_key {
    ulong32 K[4], dK[4];
};
#endif

#ifdef SKIPJACK 
struct skipjack_key {
    unsigned char key[10];
};
#endif

#ifdef KHAZAD
struct khazad_key {
   ulong64 roundKeyEnc[8 + 1]; 
   ulong64 roundKeyDec[8 + 1]; 
};
#endif

#ifdef ANUBIS
struct anubis_key { 
   int keyBits; 
   int R; 
   ulong32 roundKeyEnc[18 + 1][4]; 
   ulong32 roundKeyDec[18 + 1][4]; 
}; 
#endif

typedef union Symmetric_key {
#ifdef DES
   struct des_key des;
   struct des3_key des3;
#endif
#ifdef RC2
   struct rc2_key rc2;
#endif
#ifdef SAFER
   struct safer_key safer;
#endif
#ifdef TWOFISH
   struct twofish_key  twofish;
#endif
#ifdef BLOWFISH
   struct blowfish_key blowfish;
#endif
#ifdef RC5
   struct rc5_key      rc5;
#endif
#ifdef RC6
   struct rc6_key      rc6;
#endif
#ifdef SAFERP
   struct saferp_key   saferp;
#endif
#ifdef RIJNDAEL
   struct rijndael_key rijndael;
#endif
#ifdef XTEA
   struct xtea_key     xtea;
#endif
#ifdef CAST5
   struct cast5_key    cast5;
#endif
#ifdef NOEKEON
   struct noekeon_key  noekeon;
#endif   
#ifdef SKIPJACK
   struct skipjack_key skipjack;
#endif
#ifdef KHAZAD
   struct khazad_key   khazad;
#endif
#ifdef ANUBIS
   struct anubis_key   anubis;
#endif
} symmetric_key;

/* A block cipher ECB structure */
typedef struct {
   /** The index of the cipher chosen */
   int                 cipher, 
   /** The block size of the given cipher */
                       blocklen;
   /** The scheduled key */                       
   symmetric_key       key;
} symmetric_ECB;

/* A block cipher CFB structure */
typedef struct {
   /** The index of the cipher chosen */
   int                 cipher, 
   /** The block size of the given cipher */                        
                       blocklen, 
   /** The padding offset */
                       padlen;
   /** The current IV */
   unsigned char       IV[MAXBLOCKSIZE], 
   /** The pad used to encrypt/decrypt */ 
                       pad[MAXBLOCKSIZE];
   /** The scheduled key */
   symmetric_key       key;
} symmetric_CFB;

/* A block cipher OFB structure */
typedef struct {
   /** The index of the cipher chosen */
   int                 cipher, 
   /** The block size of the given cipher */                        
                       blocklen, 
   /** The padding offset */
                       padlen;
   /** The current IV */
   unsigned char       IV[MAXBLOCKSIZE];
   /** The scheduled key */
   symmetric_key       key;
} symmetric_OFB;

/* A block cipher CBC structure */
typedef struct {
   /** The index of the cipher chosen */
   int                 cipher, 
   /** The block size of the given cipher */                        
                       blocklen;
   /** The current IV */
   unsigned char       IV[MAXBLOCKSIZE];
   /** The scheduled key */
   symmetric_key       key;
} symmetric_CBC;

/* A block cipher CTR structure */
typedef struct {
   /** The index of the cipher chosen */
   int                 cipher,
   /** The block size of the given cipher */                        
                       blocklen, 
   /** The padding offset */
                       padlen, 
   /** The mode (endianess) of the CTR, 0==little, 1==big */                       
                       mode;
   /** The counter */                       
   unsigned char       ctr[MAXBLOCKSIZE], 
   /** The pad used to encrypt/decrypt */                       
                       pad[MAXBLOCKSIZE];
   /** The scheduled key */
   symmetric_key       key;
} symmetric_CTR;

/* cipher descriptor table, last entry has "name == NULL" to mark the end of table */
extern struct ltc_cipher_descriptor {
   /** name of cipher */
   char *name;
   /** internal ID */
   unsigned char ID;
   /** min keysize (octets) */
   int  min_key_length, 
   /** max keysize (octets) */
        max_key_length, 
   /** block size (octets) */
        block_length, 
   /** default number of rounds */
        default_rounds;
   /** Setup the cipher 
      @param key         The input symmetric key
      @param keylen      The length of the input key (octets)
      @param num_rounds  The requested number of rounds (0==default)
      @param skey        [out] The destination of the scheduled key
      @return CRYPT_OK if successful
   */
   int  (*setup)(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
   /** Encrypt a block
      @param pt      The plaintext
      @param ct      [out] The ciphertext
      @param skey    The scheduled key
   */
   void (*ecb_encrypt)(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
   /** Decrypt a block
      @param ct      The ciphertext
      @param pt      [out] The plaintext
      @param skey    The scheduled key
   */
   void (*ecb_decrypt)(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
   /** Test the block cipher
       @return CRYPT_OK if successful, CRYPT_NOP if self-testing has been disabled
   */
   int (*test)(void);
   /** Determine a key size
       @param keysize    [in/out] The size of the key desired and the suggested size
       @return CRYPT_OK if successful
   */
   int  (*keysize)(int *keysize);
} cipher_descriptor[];

#ifdef BLOWFISH
int blowfish_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
void blowfish_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
void blowfish_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
int blowfish_test(void);
int blowfish_keysize(int *keysize);
extern const struct ltc_cipher_descriptor blowfish_desc;
#endif

#ifdef RC5
int rc5_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
void rc5_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
void rc5_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
int rc5_test(void);
int rc5_keysize(int *keysize);
extern const struct ltc_cipher_descriptor rc5_desc;
#endif

#ifdef RC6
int rc6_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
void rc6_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
void rc6_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
int rc6_test(void);
int rc6_keysize(int *keysize);
extern const struct ltc_cipher_descriptor rc6_desc;
#endif

#ifdef RC2
int rc2_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
void rc2_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
void rc2_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
int rc2_test(void);
int rc2_keysize(int *keysize);
extern const struct ltc_cipher_descriptor rc2_desc;
#endif

#ifdef SAFERP
int saferp_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
void saferp_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
void saferp_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
int saferp_test(void);
int saferp_keysize(int *keysize);
extern const struct ltc_cipher_descriptor saferp_desc;
#endif

#ifdef SAFER
int safer_k64_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
int safer_sk64_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
int safer_k128_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
int safer_sk128_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
void safer_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key);
void safer_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key);
int safer_k64_test(void);
int safer_sk64_test(void);
int safer_sk128_test(void);
int safer_64_keysize(int *keysize);
int safer_128_keysize(int *keysize);
extern const struct ltc_cipher_descriptor safer_k64_desc, safer_k128_desc, safer_sk64_desc, safer_sk128_desc;
#endif

#ifdef RIJNDAEL

/* make aes an alias */
#define aes_setup           rijndael_setup
#define aes_ecb_encrypt     rijndael_ecb_encrypt
#define aes_ecb_decrypt     rijndael_ecb_decrypt
#define aes_test            rijndael_test
#define aes_keysize         rijndael_keysize

#define aes_enc_setup           rijndael_enc_setup
#define aes_enc_ecb_encrypt     rijndael_enc_ecb_encrypt
#define aes_enc_keysize         rijndael_enc_keysize

int rijndael_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
void rijndael_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
void rijndael_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
int rijndael_test(void);
int rijndael_keysize(int *keysize);
int rijndael_enc_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
void rijndael_enc_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
int rijndael_enc_keysize(int *keysize);
extern const struct ltc_cipher_descriptor rijndael_desc, aes_desc;
extern const struct ltc_cipher_descriptor rijndael_enc_desc, aes_enc_desc;
#endif

#ifdef XTEA
int xtea_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
void xtea_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
void xtea_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
int xtea_test(void);
int xtea_keysize(int *keysize);
extern const struct ltc_cipher_descriptor xtea_desc;
#endif

#ifdef TWOFISH
int twofish_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
void twofish_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
void twofish_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
int twofish_test(void);
int twofish_keysize(int *keysize);
extern const struct ltc_cipher_descriptor twofish_desc;
#endif

#ifdef DES
int des_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
void des_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
void des_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
int des_test(void);
int des_keysize(int *keysize);
int des3_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
void des3_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
void des3_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
int des3_test(void);
int des3_keysize(int *keysize);
extern const struct ltc_cipher_descriptor des_desc, des3_desc;
#endif

#ifdef CAST5
int cast5_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
void cast5_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
void cast5_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
int cast5_test(void);
int cast5_keysize(int *keysize);
extern const struct ltc_cipher_descriptor cast5_desc;
#endif

#ifdef NOEKEON
int noekeon_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
void noekeon_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
void noekeon_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
int noekeon_test(void);
int noekeon_keysize(int *keysize);
extern const struct ltc_cipher_descriptor noekeon_desc;
#endif

#ifdef SKIPJACK
int skipjack_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
void skipjack_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
void skipjack_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
int skipjack_test(void);
int skipjack_keysize(int *keysize);
extern const struct ltc_cipher_descriptor skipjack_desc;
#endif

#ifdef KHAZAD
int khazad_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
void khazad_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
void khazad_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
int khazad_test(void);
int khazad_keysize(int *keysize);
extern const struct ltc_cipher_descriptor khazad_desc;
#endif

#ifdef ANUBIS
int anubis_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
void anubis_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
void anubis_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
int anubis_test(void);
int anubis_keysize(int *keysize);
extern const struct ltc_cipher_descriptor anubis_desc;
#endif

#ifdef ECB
int ecb_start(int cipher, const unsigned char *key, 
              int keylen, int num_rounds, symmetric_ECB *ecb);
int ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_ECB *ecb);
int ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_ECB *ecb);
#endif

#ifdef CFB
int cfb_start(int cipher, const unsigned char *IV, const unsigned char *key, 
              int keylen, int num_rounds, symmetric_CFB *cfb);
int cfb_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_CFB *cfb);
int cfb_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_CFB *cfb);
int cfb_getiv(unsigned char *IV, unsigned long *len, symmetric_CFB *cfb);
int cfb_setiv(const unsigned char *IV, unsigned long len, symmetric_CFB *cfb);
#endif

#ifdef OFB
int ofb_start(int cipher, const unsigned char *IV, const unsigned char *key, 
              int keylen, int num_rounds, symmetric_OFB *ofb);
int ofb_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_OFB *ofb);
int ofb_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_OFB *ofb);
int ofb_getiv(unsigned char *IV, unsigned long *len, symmetric_OFB *ofb);
int ofb_setiv(const unsigned char *IV, unsigned long len, symmetric_OFB *ofb);
#endif

#ifdef CBC
int cbc_start(int cipher, const unsigned char *IV, const unsigned char *key,
               int keylen, int num_rounds, symmetric_CBC *cbc);
int cbc_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_CBC *cbc);
int cbc_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_CBC *cbc);
int cbc_getiv(unsigned char *IV, unsigned long *len, symmetric_CBC *cbc);
int cbc_setiv(const unsigned char *IV, unsigned long len, symmetric_CBC *cbc);
#endif

#ifdef CTR
int ctr_start(int cipher, const unsigned char *IV, const unsigned char *key, 
              int keylen, int num_rounds, symmetric_CTR *ctr);
int ctr_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_CTR *ctr);
int ctr_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_CTR *ctr);
int ctr_getiv(unsigned char *IV, unsigned long *len, symmetric_CTR *ctr);
int ctr_setiv(const unsigned char *IV, unsigned long len, symmetric_CTR *ctr);
#endif
    
int find_cipher(const char *name);
int find_cipher_any(const char *name, int blocklen, int keylen);
int find_cipher_id(unsigned char ID);

int register_cipher(const struct ltc_cipher_descriptor *cipher);
int unregister_cipher(const struct ltc_cipher_descriptor *cipher);

int cipher_is_valid(int idx);

