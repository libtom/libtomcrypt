/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_test.h"

#ifdef LTC_CURVE448

typedef struct {
   const char *secret_key;
   const char *public_key;
   const char *message;
   const char *signature;
   const char *context;
} rfc_8032_t;

static int s_ed448_keygen_sign_verify(void)
{
   curve448_key key, pubkey;
   const unsigned char msg[] = "test message";
   unsigned char sig[114], pk_buf[57];
   unsigned long siglen, pklen;
   int stat, prng_idx;

   prng_idx = find_prng("yarrow");

   /* keygen */
   DO(ed448_make_key(&yarrow_prng, prng_idx, &key));
   ENSURE(key.type == PK_PRIVATE);
   ENSURE(key.pka == LTC_PKA_ED448);

   /* sign */
   siglen = sizeof(sig);
   DO(ed448_sign(msg, sizeof(msg), sig, &siglen, &key));
   ENSURE(siglen == 114);

   /* export/import public key */
   pklen = sizeof(pk_buf);
   DO(ed448_export(pk_buf, &pklen, PK_PUBLIC, &key));
   DO(ed448_import_raw(pk_buf, pklen, PK_PUBLIC, &pubkey));

   /* verify */
   stat = 0;
   DO(ed448_verify(msg, sizeof(msg), sig, siglen, &stat, &pubkey));
   ENSURE(stat == 1);

   /* corrupted sig must fail */
   sig[0] ^= 1;
   stat = 1;
   DO(ed448_verify(msg, sizeof(msg), sig, siglen, &stat, &pubkey));
   ENSURE(stat == 0);

   /* sign with context */
   siglen = sizeof(sig);
   DO(ed448ctx_sign(msg, sizeof(msg), sig, &siglen,
                    (const unsigned char *)"ctx", 3, &key));
   stat = 0;
   DO(ed448ctx_verify(msg, sizeof(msg), sig, siglen,
                      (const unsigned char *)"ctx", 3, &stat, &pubkey));
   ENSURE(stat == 1);

   /* wrong context must fail */
   stat = 1;
   DO(ed448ctx_verify(msg, sizeof(msg), sig, siglen,
                      (const unsigned char *)"bad", 3, &stat, &pubkey));
   ENSURE(stat == 0);

   return CRYPT_OK;
}

/* RFC 8032 Section 5.2.6 - Ed448 (pure, no context) */
static int s_rfc_8032_5_2_6_pure_test(void)
{
   const rfc_8032_t vectors[] = {
      {
         /* 1: empty message */
         "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3"
         "528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
         "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778"
         "edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
         "",
         "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f"
         "2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a"
         "9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4db"
         "b61149f05a7363268c71d95808ff2e652600",
         NULL
      },
      {
         /* 2: 1 byte message */
         "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a"
         "fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
         "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086"
         "6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
         "03",
         "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435"
         "2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cb"
         "cee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0f"
         "f3348ab21aa4adafd1d234441cf807c03a00",
         NULL
      },
      {
         /* 4: 11 byte message */
         "cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffd"
         "f60500553abc0e05cd02184bdb89c4ccd67e187951267eb328",
         "dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e3"
         "65fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400",
         "0c3e544074ec63b0265e0c",
         "1f0a8888ce25e8d458a21130879b840a9089d999aaba039eaf3e3afa090a09d3"
         "89dba82c4ff2ae8ac5cdfb7c55e94d5d961a29fe0109941e00b8dbdeea6d3b05"
         "1068df7254c0cdc129cbe62db2dc957dbb47b51fd3f213fb8698f064774250a5"
         "028961c9bf8ffd973fe5d5c206492b140e00",
         NULL
      },
      {
         /* 5: 12 byte message */
         "258cdd4ada32ed9c9ff54e63756ae582fb8fab2ac721f2c8e676a72768513d93"
         "9f63dddb55609133f29adf86ec9929dccb52c1c5fd2ff7e21b",
         "3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc"
         "24d8e968b6e46e6f94d19b945361726bd75e149ef09817f580",
         "64a65f3cdedcdd66811e2915",
         "7eeeab7c4e50fb799b418ee5e3197ff6bf15d43a14c34389b59dd1a7b1b85b4a"
         "e90438aca634bea45e3a2695f1270f07fdcdf7c62b8efeaf00b45c2c96ba457e"
         "b1a8bf075a3db28e5c24f6b923ed4ad747c3c9e03c7079efb87cb110d3a99861"
         "e72003cbae6d6b8b827e4e6c143064ff3c00",
         NULL
      },
      {
         /* 6: 13 byte message */
         "7ef4e84544236752fbb56b8f31a23a10e42814f5f55ca037cdcc11c64c9a3b29"
         "49c1bb60700314611732a6c2fea98eebc0266a11a93970100e",
         "b3da079b0aa493a5772029f0467baebee5a8112d9d3a22532361da294f7bb381"
         "5c5dc59e176b4d9f381ca0938e13c6c07b174be65dfa578e80",
         "64a65f3cdedcdd66811e2915e7",
         "6a12066f55331b6c22acd5d5bfc5d71228fbda80ae8dec26bdd306743c5027cb"
         "4890810c162c027468675ecf645a83176c0d7323a2ccde2d80efe5a1268e8aca"
         "1d6fbc194d3f77c44986eb4ab4177919ad8bec33eb47bbb5fc6e28196fd1caf5"
         "6b4e7e0ba5519234d047155ac727a1053100",
         NULL
      },
      {
         /* 7: 64 byte message */
         "d65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bf"
         "f21f99e68ca6968f3cca6dfe0fb9f4fab4fa135d5542ea3f01",
         "df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a"
         "39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00",
         "bd0f6a3747cd561bdddf4640a332461a4a30a12a434cd0bf40d766d9c6d458e5"
         "512204a30c17d1f50b5079631f64eb3112182da3005835461113718d1a5ef944",
         "554bc2480860b49eab8532d2a533b7d578ef473eeb58c98bb2d0e1ce488a98b1"
         "8dfde9b9b90775e67f47d4a1c3482058efc9f40d2ca033a0801b63d45b3b722e"
         "f552bad3b4ccb667da350192b61c508cf7b6b5adadc2c8d9a446ef003fb05cba"
         "5f30e88e36ec2703b349ca229c2670833900",
         NULL
      },
      {
         /* 8: 256 byte message */
         "2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d3756"
         "9b7e766ba74a19bd6162343a21c8590aa9cebca9014c636df5",
         "79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9b"
         "fe12402b08ae65798a3d81e22e9ec80e7690862ef3d4ed3a00",
         "15777532b0bdd0d1389f636c5f6b9ba734c90af572877e2d272dd078aa1e567c"
         "fa80e12928bb542330e8409f3174504107ecd5efac61ae7504dabe2a602ede89"
         "e5cca6257a7c77e27a702b3ae39fc769fc54f2395ae6a1178cab4738e543072f"
         "c1c177fe71e92e25bf03e4ecb72f47b64d0465aaea4c7fad372536c8ba516a60"
         "39c3c2a39f0e4d832be432dfa9a706a6e5c7e19f397964ca4258002f7c0541b5"
         "90316dbc5622b6b2a6fe7a4abffd96105eca76ea7b98816af0748c10df048ce0"
         "12d901015a51f189f3888145c03650aa23ce894c3bd889e030d565071c59f409"
         "a9981b51878fd6fc110624dcbcde0bf7a69ccce38fabdf86f3bef6044819de11",
         "c650ddbb0601c19ca11439e1640dd931f43c518ea5bea70d3dcde5f4191fe53f"
         "00cf966546b72bcc7d58be2b9badef28743954e3a44a23f880e8d4f1cfce2d7a"
         "61452d26da05896f0a50da66a239a8a188b6d825b3305ad77b73fbac0836ecc6"
         "0987fd08527c1a8e80d5823e65cafe2a3d00",
         NULL
      },
      {
         /* 9: 1023 byte message */
         "872d093780f5d3730df7c212664b37b8a0f24f56810daa8382cd4fa3f77634ec"
         "44dc54f1c2ed9bea86fafb7632d8be199ea165f5ad55dd9ce8",
         "a81b2e8a70a5ac94ffdbcc9badfc3feb0801f258578bb114ad44ece1ec0e799d"
         "a08effb81c5d685c0c56f64eecaef8cdf11cc38737838cf400",
         "6ddf802e1aae4986935f7f981ba3f0351d6273c0a0c22c9c0e8339168e675412"
         "a3debfaf435ed651558007db4384b650fcc07e3b586a27a4f7a00ac8a6fec2cd"
         "86ae4bf1570c41e6a40c931db27b2faa15a8cedd52cff7362c4e6e23daec0fbc"
         "3a79b6806e316efcc7b68119bf46bc76a26067a53f296dafdbdc11c77f7777e9"
         "72660cf4b6a9b369a6665f02e0cc9b6edfad136b4fabe723d2813db3136cfde9"
         "b6d044322fee2947952e031b73ab5c603349b307bdc27bc6cb8b8bbd7bd32321"
         "9b8033a581b59eadebb09b3c4f3d2277d4f0343624acc817804728b25ab79717"
         "2b4c5c21a22f9c7839d64300232eb66e53f31c723fa37fe387c7d3e50bdf9813"
         "a30e5bb12cf4cd930c40cfb4e1fc622592a49588794494d56d24ea4b40c89fc0"
         "596cc9ebb961c8cb10adde976a5d602b1c3f85b9b9a001ed3c6a4d3b1437f520"
         "96cd1956d042a597d561a596ecd3d1735a8d570ea0ec27225a2c4aaff26306d1"
         "526c1af3ca6d9cf5a2c98f47e1c46db9a33234cfd4d81f2c98538a09ebe76998"
         "d0d8fd25997c7d255c6d66ece6fa56f11144950f027795e653008f4bd7ca2dee"
         "85d8e90f3dc315130ce2a00375a318c7c3d97be2c8ce5b6db41a6254ff264fa6"
         "155baee3b0773c0f497c573f19bb4f4240281f0b1f4f7be857a4e59d416c06b4"
         "c50fa09e1810ddc6b1467baeac5a3668d11b6ecaa901440016f389f80acc4db9"
         "77025e7f5924388c7e340a732e554440e76570f8dd71b7d640b3450d1fd5f041"
         "0a18f9a3494f707c717b79b4bf75c98400b096b21653b5d217cf3565c9597456"
         "f70703497a078763829bc01bb1cbc8fa04eadc9a6e3f6699587a9e75c94e5bab"
         "0036e0b2e711392cff0047d0d6b05bd2a588bc109718954259f1d86678a579a3"
         "120f19cfb2963f177aeb70f2d4844826262e51b80271272068ef5b3856fa8535"
         "aa2a88b2d41f2a0e2fda7624c2850272ac4a2f561f8f2f7a318bfd5caf969614"
         "9e4ac824ad3460538fdc25421beec2cc6818162d06bbed0c40a387192349db67"
         "a118bada6cd5ab0140ee273204f628aad1c135f770279a651e24d8c14d75a605"
         "9d76b96a6fd857def5e0b354b27ab937a5815d16b5fae407ff18222c6d1ed263"
         "be68c95f32d908bd895cd76207ae726487567f9a67dad79abec316f683b17f2d"
         "02bf07e0ac8b5bc6162cf94697b3c27cd1fea49b27f23ba2901871962506520c"
         "392da8b6ad0d99f7013fbc06c2c17a569500c8a7696481c1cd33e9b14e40b82e"
         "79a5f5db82571ba97bae3ad3e0479515bb0e2b0f3bfcd1fd33034efc6245eddd"
         "7ee2086ddae2600d8ca73e214e8c2b0bdb2b047c6a464a562ed77b73d2d841c4"
         "b34973551257713b753632efba348169abc90a68f42611a40126d7cb21b58695"
         "568186f7e569d2ff0f9e745d0487dd2eb997cafc5abf9dd102e62ff66cba87",
         "e301345a41a39a4d72fff8df69c98075a0cc082b802fc9b2b6bc503f926b65bd"
         "df7f4c8f1cb49f6396afc8a70abe6d8aef0db478d4c6b2970076c6a0484fe76d"
         "76b3a97625d79f1ce240e7c576750d295528286f719b413de9ada3e8eb78ed57"
         "3603ce30d8bb761785dc30dbc320869e1a00",
         NULL
      }
   };
   unsigned int n;
   unsigned long mlen, slen, plen, siglen, buflen;
   unsigned char msg[1024], sec[57], pub[57], sig[114], buf[114];
   curve448_key key, key2;
   int ret;
   const int should = 1;

   for (n = 0; n < sizeof(vectors)/sizeof(vectors[0]); ++n) {
      slen = sizeof(sec);
      DO(base16_decode(vectors[n].secret_key, XSTRLEN(vectors[n].secret_key), sec, &slen));
      plen = sizeof(pub);
      DO(base16_decode(vectors[n].public_key, XSTRLEN(vectors[n].public_key), pub, &plen));
      if (XSTRLEN(vectors[n].message) > 0) {
         mlen = sizeof(msg);
         DO(base16_decode(vectors[n].message, XSTRLEN(vectors[n].message), msg, &mlen));
      } else {
         mlen = 0;
      }
      siglen = sizeof(sig);
      DO(base16_decode(vectors[n].signature, XSTRLEN(vectors[n].signature), sig, &siglen));

      /* sign with private key and compare */
      DO(ed448_import_raw(sec, slen, PK_PRIVATE, &key));
      buflen = sizeof(buf);
      DO(ed448_sign(msg, mlen, buf, &buflen, &key));
      COMPARE_TESTVECTOR(buf, buflen, sig, siglen, "Ed448 RFC8032 5.2.6 - sign", n);

      /* verify with private key */
      DO(ed448_verify(msg, mlen, sig, siglen, &ret, &key));
      COMPARE_TESTVECTOR(&ret, sizeof(ret), &should, sizeof(should), "Ed448 RFC8032 5.2.6 - verify w/ privkey", n);

      /* verify with public key only */
      DO(ed448_import_raw(pub, plen, PK_PUBLIC, &key2));
      DO(ed448_verify(msg, mlen, sig, siglen, &ret, &key2));
      COMPARE_TESTVECTOR(&ret, sizeof(ret), &should, sizeof(should), "Ed448 RFC8032 5.2.6 - verify w/ pubkey", n);

      zeromem(&key, sizeof(key));
      zeromem(&key2, sizeof(key2));
   }
   return CRYPT_OK;
}

/* RFC 8032 Section 5.2.6 - Ed448 with context (vector 3) */
static int s_rfc_8032_5_2_6_ctx_test(void)
{
   const rfc_8032_t vectors[] = {
      {
         /* 3: 1 byte message, context "foo" */
         "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a"
         "fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
         "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086"
         "6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
         "03",
         "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2"
         "151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da"
         "1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d"
         "5428407e85dcbc98a49155c13764e66c3c00",
         "666f6f"
      }
   };
   unsigned int n;
   unsigned long mlen, slen, plen, siglen, buflen, ctxlen;
   unsigned char msg[1024], sec[57], pub[57], sig[114], buf[114], ctx[64];
   curve448_key key, key2;
   int ret;
   const int should = 1;

   for (n = 0; n < sizeof(vectors)/sizeof(vectors[0]); ++n) {
      slen = sizeof(sec);
      DO(base16_decode(vectors[n].secret_key, XSTRLEN(vectors[n].secret_key), sec, &slen));
      plen = sizeof(pub);
      DO(base16_decode(vectors[n].public_key, XSTRLEN(vectors[n].public_key), pub, &plen));
      mlen = sizeof(msg);
      DO(base16_decode(vectors[n].message, XSTRLEN(vectors[n].message), msg, &mlen));
      siglen = sizeof(sig);
      DO(base16_decode(vectors[n].signature, XSTRLEN(vectors[n].signature), sig, &siglen));
      ctxlen = sizeof(ctx);
      DO(base16_decode(vectors[n].context, XSTRLEN(vectors[n].context), ctx, &ctxlen));

      /* sign with context and compare */
      DO(ed448_import_raw(sec, slen, PK_PRIVATE, &key));
      buflen = sizeof(buf);
      DO(ed448ctx_sign(msg, mlen, buf, &buflen, ctx, ctxlen, &key));
      COMPARE_TESTVECTOR(buf, buflen, sig, siglen, "Ed448ctx RFC8032 5.2.6 - sign", n);

      /* verify with private key */
      DO(ed448ctx_verify(msg, mlen, sig, siglen, ctx, ctxlen, &ret, &key));
      COMPARE_TESTVECTOR(&ret, sizeof(ret), &should, sizeof(should), "Ed448ctx RFC8032 5.2.6 - verify w/ privkey", n);

      /* verify with public key only */
      DO(ed448_import_raw(pub, plen, PK_PUBLIC, &key2));
      DO(ed448ctx_verify(msg, mlen, sig, siglen, ctx, ctxlen, &ret, &key2));
      COMPARE_TESTVECTOR(&ret, sizeof(ret), &should, sizeof(should), "Ed448ctx RFC8032 5.2.6 - verify w/ pubkey", n);

      zeromem(&key, sizeof(key));
      zeromem(&key2, sizeof(key2));
   }
   return CRYPT_OK;
}

/* RFC 8032 Section 5.2.6 - Ed448ph (prehash) */
static int s_rfc_8032_5_2_6_ph_test(void)
{
   const rfc_8032_t vectors[] = {
      {
         /* Ed448ph without context */
         "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
         "ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49",
         "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743"
         "c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880",
         "616263",
         "822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae38"
         "1f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd"
         "433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3"
         "ad203df7dc7ce360c3cd3696d9d9fab90f00",
         NULL
      },
      {
         /* Ed448ph with context "foo" */
         "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
         "ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49",
         "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743"
         "c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880",
         "616263",
         "c32299d46ec8ff02b54540982814dce9a05812f81962b649d528095916a2aa48"
         "1065b1580423ef927ecf0af5888f90da0f6a9a85ad5dc3f280d91224ba9911a3"
         "653d00e484e2ce232521481c8658df304bb7745a73514cdb9bf3e15784ab7128"
         "4f8d0704a608c54a6b62d97beb511d132100",
         "666f6f"
      }
   };
   unsigned int n;
   unsigned long mlen, slen, plen, siglen, buflen, ctxlen;
   unsigned char msg[1024], sec[57], pub[57], sig[114], buf[114], ctx[64];
   curve448_key key;
   int ret;
   const int should = 1;

   for (n = 0; n < sizeof(vectors)/sizeof(vectors[0]); ++n) {
      slen = sizeof(sec);
      DO(base16_decode(vectors[n].secret_key, XSTRLEN(vectors[n].secret_key), sec, &slen));
      plen = sizeof(pub);
      DO(base16_decode(vectors[n].public_key, XSTRLEN(vectors[n].public_key), pub, &plen));
      mlen = sizeof(msg);
      DO(base16_decode(vectors[n].message, XSTRLEN(vectors[n].message), msg, &mlen));
      siglen = sizeof(sig);
      DO(base16_decode(vectors[n].signature, XSTRLEN(vectors[n].signature), sig, &siglen));

      if (vectors[n].context != NULL) {
         ctxlen = sizeof(ctx);
         DO(base16_decode(vectors[n].context, XSTRLEN(vectors[n].context), ctx, &ctxlen));
      } else {
         ctxlen = 0;
      }

      DO(ed448_import_raw(sec, slen, PK_PRIVATE, &key));
      buflen = sizeof(buf);
      DO(ed448ph_sign(msg, mlen, buf, &buflen, ctx, ctxlen, &key));
      COMPARE_TESTVECTOR(buf, buflen, sig, siglen, "Ed448ph RFC8032 5.2.6 - sign", n);

      DO(ed448ph_verify(msg, mlen, sig, siglen, ctx, ctxlen, &ret, &key));
      COMPARE_TESTVECTOR(&ret, sizeof(ret), &should, sizeof(should), "Ed448ph RFC8032 5.2.6 - verify", n);

      zeromem(&key, sizeof(key));
   }
   return CRYPT_OK;
}

/* Wycheproof ed448_test.json tcId=63/64/65 signature malleability vectors */
static int s_signature_malleability_test(void)
{
   static const struct {
      int tc_id;
      const char *sig;
   } test_cases[] = {
      { 63,
        "5db94c53101f521f6c1f43b60ea4d7e06fbd49c2e8afaf4fcc289e645e0880a87b8e55858df4cf2291a7303ffda446b82a117b4dd408cff2811adf92201088e0"
        "51ee48b57aecf46edfc68e5baeed5ae4910ba5681d370f75ab593811e18293ef0808581c254196bcbf2b4c454136a6711b00"
      },
      { 64,
        "5db94c53101f521f6c1f43b60ea4d7e06fbd49c2e8afaf4fcc289e645e0880a87b8e55858df4cf2291a7303ffda446b82a117b4dd408cff2825e06c3999e8308"
        "be439c40940b0075d3e4f65147c1608cbe6e9c432e33bed6686f9393ae2568f0ad60febcb4b6179c0d90d034e7c3c4681000"
      },
      { 65,
        "5db94c53101f521f6c1f43b60ea4d7e06fbd49c2e8afaf4fcc289e645e0880a87b8e55858df4cf2291a7303ffda446b82a117b4dd408cff2c02456bbd141df04"
        "8dbf1843be6d5fef402483314c2af547b361a09f3319489eaede43404df9faf634c1298d678b5261c808b0be3726013e3900"
      },
   };
   const char *public_key = "419610a534af127f583b04818cdb7f0ff300b025f2e01682bcae33fd691cee039511df0cddc690ee978426e8b38e50ce5af7dcfba50f704c00";
   const char *message = "313233343030";
   unsigned long n, mlen, plen, siglen;
   unsigned char msg[8], pub[57], sig[114];
   curve448_key key;
   int ret;
   const int should = 0;

   plen = sizeof(pub);
   DO(base16_decode(public_key, XSTRLEN(public_key), pub, &plen));
   mlen = sizeof(msg);
   DO(base16_decode(message, XSTRLEN(message), msg, &mlen));
   DO(ed448_import_raw(pub, plen, PK_PUBLIC, &key));

   for (n = 0; n < LTC_ARRAY_SIZE(test_cases); ++n) {
      siglen = sizeof(sig);
      DO(base16_decode(test_cases[n].sig, XSTRLEN(test_cases[n].sig), sig, &siglen));
      DO(ed448_verify(msg, mlen, sig, siglen, &ret, &key));
      COMPARE_TESTVECTOR(&ret, sizeof(ret), &should, sizeof(should), "Ed448 malleability rejection", test_cases[n].tc_id);
   }

   zeromem(&key, sizeof(key));
   return CRYPT_OK;
}

/* Export/import round-trip for Ed448 (requires MPI for DER/PKCS8) */
static int s_ed448_compat_test(void)
{
   curve448_key priv, pub, imported;
   unsigned char buf[1024];
   unsigned long buflen;
   int prng_idx = find_prng("yarrow");

   XMEMSET(&priv, 0, sizeof(priv));
   XMEMSET(&pub, 0, sizeof(pub));
   XMEMSET(&imported, 0, sizeof(imported));

   DO(ed448_make_key(&yarrow_prng, prng_idx, &priv));

   /* private PKCS#8 export -> import */
   buflen = sizeof(buf);
   DO(ed448_export(buf, &buflen, PK_PRIVATE | PK_STD, &priv));
   DO(ed448_import_pkcs8(buf, buflen, NULL, &imported));
   COMPARE_TESTVECTOR(&priv, sizeof(priv), &imported, sizeof(imported), "Ed448 priv pkcs8 round-trip", __LINE__);
   XMEMSET(&imported, 0, sizeof(imported));

   /* public raw export -> import */
   buflen = sizeof(buf);
   DO(ed448_export(buf, &buflen, PK_PUBLIC, &priv));
   DO(ed448_import_raw(buf, buflen, PK_PUBLIC, &pub));

   /* public DER export -> import */
   buflen = sizeof(buf);
   DO(ed448_export(buf, &buflen, PK_PUBLIC | PK_STD, &priv));
   DO(ed448_import(buf, buflen, &imported));
   COMPARE_TESTVECTOR(&pub, sizeof(pub), &imported, sizeof(imported), "Ed448 pub DER round-trip", __LINE__);

   return CRYPT_OK;
}

int ed448_test(void)
{
   DO(s_ed448_keygen_sign_verify());
   DO(s_rfc_8032_5_2_6_pure_test());
   DO(s_rfc_8032_5_2_6_ctx_test());
   DO(s_rfc_8032_5_2_6_ph_test());
   DO(s_signature_malleability_test());
   return CRYPT_OK;
}

static int s_ed448_short_key_test(void)
{
   /* PrivateKeyInfo and SubjectPublicKeyInfo with a 1 byte key */
   const unsigned char p8[] = { 0x30, 0x0f, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71,
                                0x04, 0x03, 0x04, 0x01, 0x01 };
   const unsigned char spki[] = { 0x30, 0x0b, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x02, 0x00, 0x01 };
   unsigned char buf[58] = { 0 };
   curve448_key key;

   SHOULD_FAIL_WITH(ed448_import_pkcs8(p8, sizeof(p8), NULL, &key), CRYPT_PK_INVALID_SIZE);
   SHOULD_FAIL_WITH(ed448_import(spki, sizeof(spki), &key), CRYPT_PK_INVALID_SIZE);
   SHOULD_FAIL_WITH(ed448_import_raw(buf, 56, PK_PUBLIC, &key), CRYPT_PK_INVALID_SIZE);
   SHOULD_FAIL_WITH(ed448_import_raw(buf, 58, PK_PRIVATE, &key), CRYPT_PK_INVALID_SIZE);
   return CRYPT_OK;
}

int ed448_mpi_test(void)
{
   if (ltc_mp.name == NULL) return CRYPT_NOP;
   DO(s_ed448_short_key_test());
   DO(s_ed448_compat_test());
   return CRYPT_OK;
}

#else
LTC_NOP_TEST(ed448_test)
LTC_NOP_TEST(ed448_mpi_test)
#endif
