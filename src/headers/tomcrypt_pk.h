/* ---- NUMBER THEORY ---- */

enum {
   PK_PUBLIC=0,
   PK_PRIVATE=1
};

int rand_prime(void *N, long len, prng_state *prng, int wprng);

/* ---- RSA ---- */
#ifdef MRSA

/* Min and Max RSA key sizes (in bits) */
#define MIN_RSA_SIZE 1024
#define MAX_RSA_SIZE 4096

/** RSA PKCS style key */
typedef struct Rsa_key {
    /** Type of key, PK_PRIVATE or PK_PUBLIC */
    int type;
    /** The public exponent */
    void *e; 
    /** The private exponent */
    void *d; 
    /** The modulus */
    void *N; 
    /** The p factor of N */
    void *p; 
    /** The q factor of N */
    void *q; 
    /** The 1/q mod p CRT param */
    void *qP; 
    /** The d mod (p - 1) CRT param */
    void *dP; 
    /** The d mod (q - 1) CRT param */
    void *dQ;
} rsa_key;

int rsa_make_key(prng_state *prng, int wprng, int size, long e, rsa_key *key);

int rsa_exptmod(const unsigned char *in,   unsigned long inlen,
                      unsigned char *out,  unsigned long *outlen, int which,
                      rsa_key *key);

void rsa_free(rsa_key *key);

/* These use PKCS #1 v2.0 padding */
int rsa_encrypt_key(const unsigned char *in,     unsigned long inlen,
                          unsigned char *out,    unsigned long *outlen,
                    const unsigned char *lparam, unsigned long lparamlen,
                    prng_state *prng, int prng_idx, int hash_idx, rsa_key *key);
                                        
int rsa_decrypt_key(const unsigned char *in,       unsigned long inlen,
                          unsigned char *out,      unsigned long *outlen, 
                    const unsigned char *lparam,   unsigned long lparamlen,
                          int            hash_idx, int *stat,
                          rsa_key       *key);

int rsa_sign_hash(const unsigned char *in,     unsigned long  inlen, 
                        unsigned char *out,    unsigned long *outlen, 
                        prng_state    *prng,     int            prng_idx,
                        int            hash_idx, unsigned long  saltlen,
                        rsa_key *key);

int rsa_verify_hash(const unsigned char *sig,      unsigned long siglen,
                    const unsigned char *hash,     unsigned long hashlen,
                          int            hash_idx, unsigned long saltlen,
                          int           *stat,     rsa_key      *key);

/* PKCS #1 import/export */
int rsa_export(unsigned char *out, unsigned long *outlen, int type, rsa_key *key);
int rsa_import(const unsigned char *in, unsigned long inlen, rsa_key *key);
                        
#endif

/* ---- Katja ---- */
#ifdef MKAT

/* Min and Max KAT key sizes (in bits) */
#define MIN_KAT_SIZE 1024
#define MAX_KAT_SIZE 4096

/** Katja PKCS style key */
typedef struct KAT_key {
    /** Type of key, PK_PRIVATE or PK_PUBLIC */
    int type;
    /** The private exponent */
    void *d; 
    /** The modulus */
    void *N; 
    /** The p factor of N */
    void *p; 
    /** The q factor of N */
    void *q; 
    /** The 1/q mod p CRT param */
    void *qP; 
    /** The d mod (p - 1) CRT param */
    void *dP; 
    /** The d mod (q - 1) CRT param */
    void *dQ;
    /** The pq param */
    void *pq;
} katja_key;

int katja_make_key(prng_state *prng, int wprng, int size, katja_key *key);

int katja_exptmod(const unsigned char *in,   unsigned long inlen,
                        unsigned char *out,  unsigned long *outlen, int which,
                        katja_key *key);

void katja_free(katja_key *key);

/* These use PKCS #1 v2.0 padding */
int katja_encrypt_key(const unsigned char *in,     unsigned long inlen,
                            unsigned char *out,    unsigned long *outlen,
                      const unsigned char *lparam, unsigned long lparamlen,
                      prng_state *prng, int prng_idx, int hash_idx, katja_key *key);
                                        
int katja_decrypt_key(const unsigned char *in,       unsigned long inlen,
                            unsigned char *out,      unsigned long *outlen, 
                      const unsigned char *lparam,   unsigned long lparamlen,
                            int            hash_idx, int *stat,
                            katja_key       *key);

/* PKCS #1 import/export */
int katja_export(unsigned char *out, unsigned long *outlen, int type, katja_key *key);
int katja_import(const unsigned char *in, unsigned long inlen, katja_key *key);
                        
#endif

/* ---- ECC Routines ---- */
#ifdef MECC

/* size of our temp buffers for exported keys */
#define ECC_BUF_SIZE 256

/* max private key size */
#define ECC_MAXSIZE  66

/** Structure defines a NIST GF(p) curve */
typedef struct {
   /** The size of the curve in octets */
   int size;

   /** name of curve */
   char *name; 

   /** The prime that defines the field the curve is in (encoded in base-64) */
   char *prime;

   /** The fields B param (base64) */
   char *B;

   /** The order of the curve (base64) */
   char *order;
  
   /** The x co-ordinate of the base point on the curve (base64) */
   char *Gx;
 
   /** The y co-ordinate of the base point on the curve (base64) */
   char *Gy;
} ltc_ecc_set_type;

/** A point on a ECC curve, stored in Jacbobian format such that (x,y,z) => (x/z^2, y/z^3, 1) when interpretted as affine */
typedef struct {
    /** The x co-ordinate */
    void *x;

    /** The y co-ordinate */
    void *y;

    /** The z co-ordinate */
    void *z;
} ecc_point;

/** An ECC key */
typedef struct {
    /** Type of key, PK_PRIVATE or PK_PUBLIC */
    int type;

    /** Index into the ltc_ecc_sets[] for the parameters of this curve */
    int idx;

    /** The public key */
    ecc_point pubkey;

    /** The private key */
    void *k;
} ecc_key;

/** the ECC params provided */
extern const ltc_ecc_set_type ltc_ecc_sets[];

int  ecc_test(void);
void ecc_sizes(int *low, int *high);
int  ecc_get_size(ecc_key *key);

int  ecc_make_key(prng_state *prng, int wprng, int keysize, ecc_key *key);
void ecc_free(ecc_key *key);

int  ecc_export(unsigned char *out, unsigned long *outlen, int type, ecc_key *key);
int  ecc_import(const unsigned char *in, unsigned long inlen, ecc_key *key);

int  ecc_shared_secret(ecc_key *private_key, ecc_key *public_key, 
                       unsigned char *out, unsigned long *outlen);

int  ecc_encrypt_key(const unsigned char *in,   unsigned long inlen,
                           unsigned char *out,  unsigned long *outlen, 
                           prng_state *prng, int wprng, int hash, 
                           ecc_key *key);

int  ecc_decrypt_key(const unsigned char *in,  unsigned long  inlen,
                           unsigned char *out, unsigned long *outlen, 
                           ecc_key *key);

int  ecc_sign_hash(const unsigned char *in,  unsigned long inlen, 
                         unsigned char *out, unsigned long *outlen, 
                         prng_state *prng, int wprng, ecc_key *key);

int  ecc_verify_hash(const unsigned char *sig,  unsigned long siglen,
                     const unsigned char *hash, unsigned long hashlen, 
                     int *stat, ecc_key *key);

/* low level functions */
ecc_point *ltc_ecc_new_point(void);
void       ltc_ecc_del_point(ecc_point *p);
int        ltc_ecc_is_valid_idx(int n);


/* point ops (mp == montgomery digit) */
/* R = 2P */
int ltc_ecc_projective_dbl_point(ecc_point *P, ecc_point *R, void *modulus, void *mp);

/* R = P + Q */
int ltc_ecc_projective_add_point(ecc_point *P, ecc_point *Q, ecc_point *R, void *modulus, void *mp);

/* R = kG */
int ltc_ecc_mulmod(void *k, ecc_point *G, ecc_point *R, void *modulus, int map);

/* map P to affine from projective */
int ltc_ecc_map(ecc_point *P, void *modulus, void *mp);

#endif

#ifdef MDSA

/** DSA key structure */
typedef struct {
   /** The key type, PK_PRIVATE or PK_PUBLIC */
   int type; 

   /** The order of the sub-group used in octets */
   int qord;

   /** The generator  */
   void *g;

   /** The prime used to generate the sub-group */
   void *q;

   /** The large prime that generats the field the contains the sub-group */
   void *p;

   /** The private key */
   void *x;

   /** The public key */
   void *y;
} dsa_key;

int dsa_make_key(prng_state *prng, int wprng, int group_size, int modulus_size, dsa_key *key);
void dsa_free(dsa_key *key);

int dsa_sign_hash_raw(const unsigned char *in,  unsigned long inlen,
                                   void *r,   void *s,
                               prng_state *prng, int wprng, dsa_key *key);

int dsa_sign_hash(const unsigned char *in,  unsigned long inlen,
                        unsigned char *out, unsigned long *outlen,
                        prng_state *prng, int wprng, dsa_key *key);

int dsa_verify_hash_raw(         void *r,          void *s,
                    const unsigned char *hash, unsigned long hashlen, 
                                    int *stat,      dsa_key *key);

int dsa_verify_hash(const unsigned char *sig,  unsigned long siglen,
                    const unsigned char *hash, unsigned long hashlen, 
                          int           *stat, dsa_key       *key);

int dsa_encrypt_key(const unsigned char *in,   unsigned long inlen,
                          unsigned char *out,  unsigned long *outlen, 
                          prng_state *prng, int wprng, int hash, 
                          dsa_key *key);
                      
int dsa_decrypt_key(const unsigned char *in,  unsigned long  inlen,
                          unsigned char *out, unsigned long *outlen, 
                          dsa_key *key);
                          
int dsa_import(const unsigned char *in, unsigned long inlen, dsa_key *key);
int dsa_export(unsigned char *out, unsigned long *outlen, int type, dsa_key *key);
int dsa_verify_key(dsa_key *key, int *stat);



int dsa_shared_secret(void          *private_key, void *base,
                      dsa_key       *public_key,
                      unsigned char *out,         unsigned long *outlen);
#endif

#ifdef LTC_DER
/* DER handling */

enum {
 LTC_ASN1_EOL,
 LTC_ASN1_INTEGER,
 LTC_ASN1_SHORT_INTEGER,
 LTC_ASN1_BIT_STRING,
 LTC_ASN1_OCTET_STRING,
 LTC_ASN1_NULL,
 LTC_ASN1_OBJECT_IDENTIFIER,
 LTC_ASN1_IA5_STRING,
 LTC_ASN1_PRINTABLE_STRING,
 LTC_ASN1_UTCTIME,

 LTC_ASN1_CHOICE,
 LTC_ASN1_SEQUENCE
};

/** A LTC ASN.1 list type */
typedef struct ltc_asn1_list_ {
   /** The LTC ASN.1 enumerated type identifier */
   int           type;
   /** The data to encode or place for decoding */
   void         *data;
   /** The size of the input or resulting output */
   unsigned long size;
   /** The used flag, this is used by the CHOICE ASN.1 type to indicate which choice was made */
   int           used;
   /** prev/next entry in the list */
   struct ltc_asn1_list_ *prev, *next, *child, *parent;
} ltc_asn1_list;

#define LTC_SET_ASN1(list, index, Type, Data, Size)  \
   do {                                              \
      int LTC_MACRO_temp            = (index);       \
      ltc_asn1_list *LTC_MACRO_list = (list);        \
      LTC_MACRO_list[LTC_MACRO_temp].type = (Type);  \
      LTC_MACRO_list[LTC_MACRO_temp].data = (Data);  \
      LTC_MACRO_list[LTC_MACRO_temp].size = (Size);  \
      LTC_MACRO_list[LTC_MACRO_temp].used = 0;       \
   } while (0);

/* SEQUENCE */
int der_encode_sequence(ltc_asn1_list *list, unsigned long inlen,
                        unsigned char *out,  unsigned long *outlen);

int der_decode_sequence(const unsigned char *in,   unsigned long  inlen,
                              ltc_asn1_list *list, unsigned long  outlen);

int der_length_sequence(ltc_asn1_list *list, unsigned long inlen,
                        unsigned long *outlen);

/* VA list handy helpers with triplets of <type, size, data> */
int der_encode_sequence_multi(unsigned char *out, unsigned long *outlen, ...);
int der_decode_sequence_multi(const unsigned char *in, unsigned long inlen, ...);

/* handle unknown list decoder */
int  der_decode_sequence_flexi(const unsigned char *in, unsigned long *inlen, ltc_asn1_list **out);
void der_free_sequence_flexi(ltc_asn1_list *list);

void der_sequence_free(ltc_asn1_list *in);

/* INTEGER */
int der_encode_integer(void *num, unsigned char *out, unsigned long *outlen);
int der_decode_integer(const unsigned char *in, unsigned long inlen, void *num);
int der_length_integer(void *num, unsigned long *len);

/* INTEGER -- handy for 0..2^32-1 values */
int der_decode_short_integer(const unsigned char *in, unsigned long inlen, unsigned long *num);
int der_encode_short_integer(unsigned long num, unsigned char *out, unsigned long *outlen);
int der_length_short_integer(unsigned long num, unsigned long *outlen);

/* BIT STRING */
int der_encode_bit_string(const unsigned char *in, unsigned long inlen,
                                unsigned char *out, unsigned long *outlen);
int der_decode_bit_string(const unsigned char *in, unsigned long inlen,
                                unsigned char *out, unsigned long *outlen);
int der_length_bit_string(unsigned long nbits, unsigned long *outlen);

/* OCTET STRING */
int der_encode_octet_string(const unsigned char *in, unsigned long inlen,
                                  unsigned char *out, unsigned long *outlen);
int der_decode_octet_string(const unsigned char *in, unsigned long inlen,
                                  unsigned char *out, unsigned long *outlen);
int der_length_octet_string(unsigned long noctets, unsigned long *outlen);

/* OBJECT IDENTIFIER */
int der_encode_object_identifier(unsigned long *words, unsigned long  nwords,
                                 unsigned char *out,   unsigned long *outlen);
int der_decode_object_identifier(const unsigned char *in,    unsigned long  inlen,
                                       unsigned long *words, unsigned long *outlen);
int der_length_object_identifier(unsigned long *words, unsigned long nwords, unsigned long *outlen);
unsigned long der_object_identifier_bits(unsigned long x);

/* IA5 STRING */
int der_encode_ia5_string(const unsigned char *in, unsigned long inlen,
                                unsigned char *out, unsigned long *outlen);
int der_decode_ia5_string(const unsigned char *in, unsigned long inlen,
                                unsigned char *out, unsigned long *outlen);
int der_length_ia5_string(const unsigned char *octets, unsigned long noctets, unsigned long *outlen);

int der_ia5_char_encode(int c);
int der_ia5_value_decode(int v);

/* Printable STRING */
int der_encode_printable_string(const unsigned char *in, unsigned long inlen,
                                unsigned char *out, unsigned long *outlen);
int der_decode_printable_string(const unsigned char *in, unsigned long inlen,
                                unsigned char *out, unsigned long *outlen);
int der_length_printable_string(const unsigned char *octets, unsigned long noctets, unsigned long *outlen);

int der_printable_char_encode(int c);
int der_printable_value_decode(int v);

/* CHOICE */
int der_decode_choice(const unsigned char *in,   unsigned long *inlen,
                            ltc_asn1_list *list, unsigned long  outlen);

/* UTCTime */
typedef struct {
   unsigned YY, /* year */
            MM, /* month */
            DD, /* day */
            hh, /* hour */
            mm, /* minute */
            ss, /* second */
            off_dir, /* timezone offset direction 0 == +, 1 == - */
            off_hh, /* timezone offset hours */
            off_mm; /* timezone offset minutes */
} ltc_utctime;

int der_encode_utctime(ltc_utctime *utctime, 
                       unsigned char *out,   unsigned long *outlen);

int der_decode_utctime(const unsigned char *in, unsigned long *inlen,
                             ltc_utctime   *out);

int der_length_utctime(ltc_utctime *utctime, unsigned long *outlen);


#endif

/* $Source$ */
/* $Revision$ */
/* $Date$ */
