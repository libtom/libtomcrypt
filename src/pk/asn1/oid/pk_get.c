/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

#ifdef LTC_DER

typedef struct {
   enum ltc_oid_id id;
   enum ltc_pka_id pka;
   const char* oid;
} oid_table_entry;

static const oid_table_entry pka_oids[] = {
                                              { LTC_OID_UNDEF,     LTC_PKA_UNDEF,      NULL },
                                              { LTC_OID_RSA,       LTC_PKA_RSA,        "1.2.840.113549.1.1.1" },
                                              { LTC_OID_DSA,       LTC_PKA_DSA,        "1.2.840.10040.4.1" },
                                              { LTC_OID_EC,        LTC_PKA_EC,         "1.2.840.10045.2.1" },
                                              { LTC_OID_EC_PRIMEF, LTC_PKA_EC,         "1.2.840.10045.1.1" },
                                              { LTC_OID_X25519,    LTC_PKA_X25519,     "1.3.101.110" },
                                              { LTC_OID_ED25519,   LTC_PKA_ED25519,    "1.3.101.112" },
                                              { LTC_OID_DH,        LTC_PKA_DH,         "1.2.840.113549.1.3.1" },
};

static LTC_INLINE const oid_table_entry* s_get_entry(enum ltc_oid_id id)
{
   if (id < LTC_OID_NUM)
      return &pka_oids[id];
   return NULL;
}

/*
   Returns the OID requested.
   @return CRYPT_OK if valid
*/
int pk_get_oid(enum ltc_oid_id id, const char **st)
{
   const oid_table_entry* e = s_get_entry(id);
   LTC_ARGCHK(st != NULL);
   if (e != NULL) {
      *st = e->oid;
      return CRYPT_OK;
   }
   return CRYPT_INVALID_ARG;
}

/*
   Returns the PKA ID requested.
   @return CRYPT_OK if valid
*/
int pk_get_pka_id(enum ltc_oid_id id, enum ltc_pka_id *pka)
{
   const oid_table_entry* e = s_get_entry(id);
   LTC_ARGCHK(pka != NULL);
   if (e != NULL) {
      *pka = e->pka;
      return CRYPT_OK;
   }
   return CRYPT_INVALID_ARG;
}

/*
   Returns the OID ID requested.
   @return CRYPT_OK if valid
*/
int pk_get_oid_id(enum ltc_pka_id pka, enum ltc_oid_id *oid)
{
   unsigned int i;
   LTC_ARGCHK(oid != NULL);
   for (i = 1; i < sizeof(pka_oids)/sizeof(pka_oids[0]); ++i) {
      if (pka_oids[i].pka == pka) {
         *oid = pka_oids[i].id;
         return CRYPT_OK;
      }
   }
   return CRYPT_INVALID_ARG;
}

/*
   Returns the PKA ID of an OID.
   @return CRYPT_OK if valid
*/
int pk_get_oid_from_asn1(const ltc_asn1_list *oid, enum ltc_oid_id *id)
{
   unsigned long i;
   char tmp[LTC_OID_MAX_STRLEN] = { 0 };
   int err;

   LTC_ARGCHK(oid != NULL);
   LTC_ARGCHK(id != NULL);

   if (oid->type != LTC_ASN1_OBJECT_IDENTIFIER) return CRYPT_INVALID_ARG;

   i = sizeof(tmp);
   if ((err = pk_oid_num_to_str(oid->data, oid->size, tmp, &i)) != CRYPT_OK) {
      return err;
   }

   for (i = 1; i < sizeof(pka_oids)/sizeof(pka_oids[0]); ++i) {
      if (XSTRCMP(pka_oids[i].oid, tmp) == 0) {
         *id = pka_oids[i].id;
         return CRYPT_OK;
      }
   }
   return CRYPT_INVALID_ARG;
}
#endif
