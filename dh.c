#include "mycrypt.h"

#ifdef MDH

/* This holds the key settings.  ***MUST*** be organized by size from smallest to largest. */
static const struct {
    int size;
    char *name, *base, *prime;
} sets[] = {
#ifdef DH768
{
   96,
   "DH-768",
   "2",
   "2893527720709661239493896562339544088620375736490408468011883030469939904368"
   "0860923364582982212457078989335831907131881773994018526277492109945959747917"
   "8279025394653904396221302707492255957231214118178743427870878320796645901947"
   "9487"
},
#endif
#ifdef DH1024
{
   128,
   "DH-1024",
   "2",
   "3477431594398766260792527967974222231775354473882066076071816639030459075912"
   "0194047822362172211817327089848758298713770865641434468581617942085516098634"
   "0457973820182883508387588163122354089264395604796675278966117567294812714812"
   "7968205965648764507160662831267200108590414847865290564578963676831229604111"
   "36319"
},
#endif
#ifdef DH1280
{
   160,
   "DH-1280",
   "2",
   "2618298020488323341377089635550383393554460131909411928885489146533597039863"
   "5379029297773089246854323581071445272213255646852180580463169755159411503866"
   "4190218001872082125570169842848154404911652982668791288605239288293106162305"
   "7236093554796242806887062958692596037823904832542385180840218330924392268465"
   "0197244314233248991982159235832322194332167923655574170280697353556560854901"
   "280047"
},
#endif
#ifdef DH1536
{
   192,
   "DH-1536",
   "3",
   "2992593690703251306835100868059076484222548092264611010748654597096560864537"
   "1704684310938824733433085888971827086341295918925237859522548192211945291282"
   "1170570153374563548621496076860061698150233114892317627457427359445435608693"
   "5625000902194809114890745455404045166957722404567939575618007347432055137282"
   "3291711752537781447636541738638119983678441628437171377508654097130147131310"
   "9209393805685590941710151477648542896503595482724205166251069428524927527085"
   "2602467"
},
#endif
#ifdef DH1792
{
   224,
   "DH-1792",
   "2",
   "3210090394251532205679207425273650879078185529033544241951292722086520015900"
   "0402371844205168176419829949232601235193754977706171541009393172204470047690"
   "6659627844880912479392592056697278305733615369406596661203184035142652643118"
   "1379603333858737848321053048184938839622944591194935387992479717305577175500"
   "2554620614907177847128950276247571809502831255425929468853285490357704941968"
   "3407102520889651917659577334897408316217748346860775479727332331727022096550"
   "7718799868459391361770854814013613619048768630587629568449528005570971478547"
   "34960319"
},
#endif
#ifdef DH2048
{
   256,
   "DH-2048",
   "2",
   "4726642895635639316469736509812041897640060270607231273592407174543853221823"
   "7979333351774907308168340693326687317443721193266215155735814510792148768576"
   "4984911991227443513994894535335532038333186916782632419417062569961974604240"
   "2901241901263467186228353234265630967717360250949841797609150915436003989316"
   "5037637034737020327399910409885798185771003505320583967737293415979917317338"
   "9858373857347474783642420203804168920566508414708692945275435973492502995396"
   "8243060517332102902655554683247304860032703684578197028928889831788842751736"
   "4945316709081173840186150794397479045034008257793436817683392375274635794835"
   "245695887"
},
#endif
#ifdef DH2560
{
   320,
   "DH-2560",
   "3",
   "4364638085059577685748948703943497396233464406019459611612544400721432981520"
   "4010567649104824811014627875285783993051576616744140702150122992472133564455"
   "7342265864606569000117714935185566842453630868849121480179691838399545644365"
   "5711067577313173717585579907818806913366955847993133136872874688941488237617"
   "8558298254958618375680644901754262226787427510387748147553499120184991222267"
   "0102069951687572917937634467778042874315463238062009202992087620963771759666"
   "4482665328580794026699200252242206134194410697184828373996126449788399252071"
   "0987084027819404215874884544513172913711709852902888677006373648742061314404"
   "5836803985635654192482395882603511950547826439092832800532152534003936926017"
   "6124466061356551464456206233957889787267447285030586700468858762515271223502"
   "75750995227"
},
#endif
#ifdef DH3072
{
   384,
   "DH-3072",
   "2",
   "1142416747335183639807830604262436227795642944052113706188970261176634876069"
   "2206243140413411077394583180726863277012016602279290144126785129569474909173"
   "5847898223419867427192303319460727303195559844849117167970588759054009995043"
   "0587724584911968750902323279027363746682105257685923245298206183100977078603"
   "1785669030271542286603956118755585683996118896215213488875253101894663403069"
   "6777459483058938495054342017637452328957807119724320113448575216910178963168"
   "6140320644942133224365885545343578400651720289418164056243357539082138421096"
   "0117518650374602256601091379644034244332285065935413233557998331562749140202"
   "9658442193362989700115138825649355387042894469683222814519074873620465114612"
   "2132979989735099337056069750580968643878203623537213701573130477907243026098"
   "6460269894522159103008260495503005267165927542949439526272736586626709581721"
   "0321895327263896436255906801057848442461527026701693042037830722750891947548"
   "89511973916207"
},
#endif
#ifdef DH4096
{
   512,
   "DH-4096", 
   "3",
   "1214855636816562637502584060163403830270705000634713483015101384881871978446"
   "8012247985361554068958233050354675916325310675478909486951171720769542207270"
   "7568804875102242119871203284889005635784597424656074834791863005085393369779"
   "2254955890439720297560693579400297062396904306270145886830719309296352765295"
   "7121830407731464190228751653827780070401099576097395898755908857011261979060"
   "6362013395489321661267883850754077713843779770560245371955901763398648664952"
   "3611975865005712371194067612263330335590526176087004421363598470302731349138"
   "7732059014477046821815179040647356365184624522427916765417252923789255682968"
   "5801015185232631677751193503753101741391050692192245066693320227848902452126"
   "3798482237150056835746454842662048692127173834433089016107854491097456725016"
   "3277096631997382384421648431471327891537255132571679155551620949708535844479"
   "9312548860769600816980737473671129700747381225627224548940589847029717873802"
   "9484459690836250560495461579533254473316340608217876781986188705928270735695"
   "7528308255279638383554197625162460286802809880204019145518254873499903069763"
   "0409310938445143881325121105159739212749146489879740678917545306796007200859"
   "0614886532333015881171367104445044718144312416815712216611576221546455968770"
   "801413440778423979"
},
#endif
{   
   0,
   NULL,
   NULL,
   NULL
}
};

static int is_valid_idx(int n)
{
   int x;

   for (x = 0; sets[x].size; x++);
   if ((n < 0) || (n >= x)) {
      return 0;
   }
   return 1;
}

int dh_test(void)
{
    mp_int p, g, tmp;
    int x, res, primality;

    if (mp_init_multi(&p, &g, &tmp, NULL) != MP_OKAY)                 { goto error; }

    for (x = 0; sets[x].size; x++) {
#if 0
        printf("dh_test():testing size %d-bits\n", sets[x].size * 8);
#endif
        /* see if g^((p-1)/2) == 1 mod p. */
        if (mp_read_radix(&g, sets[x].base, 10) != MP_OKAY)           { goto error; }
        if (mp_read_radix(&p, sets[x].prime, 10) != MP_OKAY)          { goto error; }

        /* ensure p is prime */
        if ((res = is_prime(&p, &primality)) != CRYPT_OK)             { goto done; }
        if (primality == 0) { 
           res = CRYPT_FAIL_TESTVECTOR;
           goto done;
        }

        if (mp_sub_d(&p, 1, &tmp) != MP_OKAY)                         { goto error; }
        if (mp_div_2(&tmp, &tmp) != MP_OKAY)                          { goto error; }

        /* ensure (p-1)/2 is prime */
        if ((res = is_prime(&tmp, &primality)) != CRYPT_OK)           { goto done; }
        if (primality == 0) {
           res = CRYPT_FAIL_TESTVECTOR;
           goto done;
        }

        /* now see if g^((p-1)/2) mod p is in fact 1 */
        if (mp_exptmod(&g, &tmp, &p, &tmp) != MP_OKAY)                { goto error; }
        if (mp_cmp_d(&tmp, 1)) {
           res = CRYPT_FAIL_TESTVECTOR;
           goto done;
        }
    }
    res = CRYPT_OK;
    goto done;
error:
    res = CRYPT_MEM;
done:
    mp_clear_multi(&tmp, &g, &p, NULL);
    return res;
}

void dh_sizes(int *low, int *high)
{
   int x;
   _ARGCHK(low != NULL);
   _ARGCHK(high != NULL);
   *low  = INT_MAX;
   *high = 0;
   for (x = 0; sets[x].size; x++) {
       if (*low > sets[x].size)  *low  = sets[x].size;
       if (*high < sets[x].size) *high = sets[x].size;
   }
}

int dh_get_size(dh_key *key)
{
    _ARGCHK(key != NULL);
    if (is_valid_idx(key->idx)) 
        return sets[key->idx].size;
    else
        return INT_MAX; /* large value that would cause dh_make_key() to fail */
}
  
int dh_make_key(prng_state *prng, int wprng, int keysize, dh_key *key)
{
   unsigned char buf[768];
   unsigned long x;
   mp_int p, g;
   int res, errno;

   _ARGCHK(key  != NULL);

   /* good prng? */
   if ((errno = prng_is_valid(wprng)) != CRYPT_OK) {
      return errno;
   }

   /* find key size */
   for (x = 0; (keysize > sets[x].size) && (sets[x].size); x++);
#ifdef FAST_PK
   keysize = MIN(sets[x].size, 32);
#else  
   keysize = sets[x].size;
#endif

   if (sets[x].size == 0) {
      return CRYPT_INVALID_KEYSIZE;
   }
   key->idx = x;

   /* make up random string */
   buf[0] = 0;
   if (prng_descriptor[wprng].read(buf+1, keysize, prng) != (unsigned long)keysize) {
      return CRYPT_ERROR_READPRNG;
   }

   /* init parameters */
   if (mp_init_multi(&g, &p, &key->x, &key->y, NULL) != MP_OKAY) {
      return CRYPT_MEM;
   }
   if (mp_read_radix(&g, sets[x].base, 10) != MP_OKAY)             { goto error2; }
   if (mp_read_radix(&p, sets[x].prime, 10) != MP_OKAY)            { goto error2; }

   /* load the x value */
   mp_read_raw(&key->x, buf, keysize+1);
   if (mp_exptmod(&g, &key->x, &p, &key->y) != MP_OKAY)            { goto error2; }
   key->type = PK_PRIVATE;

   /* free up ram */
   res = CRYPT_OK;
   goto done2;
error2:
   res = CRYPT_MEM;
   mp_clear_multi(&key->x, &key->y, NULL);
done2:
   mp_clear_multi(&p, &g, NULL);
   zeromem(buf, sizeof(buf));
   return res;
}

void dh_free(dh_key *key)
{
   _ARGCHK(key != NULL);
   mp_clear_multi(&key->x, &key->y, NULL);
}

#define OUTPUT_BIGNUM(num, buf2, y, z)         \
{                                              \
      z = mp_raw_size(num);                    \
      STORE32L(z, buf2+y);                     \
      y += 4;                                  \
      mp_toraw(num, buf2+y);                   \
      y += z;                                  \
}


#define INPUT_BIGNUM(num, in, x, y)                              \
{                                                                \
     /* load value */                                            \
     LOAD32L(x, in+y);                                           \
     y += 4;                                                     \
                                                                 \
     /* sanity check... */                                       \
     if (x > 1024) {                                             \
        errno = CRYPT_ERROR;                                     \
        goto error;                                              \
     }                                                           \
                                                                 \
     /* load it */                                               \
     if (mp_read_raw(num, (unsigned char *)in+y, x) != MP_OKAY) {\
        return CRYPT_MEM;                                        \
        goto error;                                              \
     }                                                           \
     y += x;                                                     \
}


int dh_export(unsigned char *out, unsigned long *outlen, int type, dh_key *key)
{
   unsigned char buf2[1536];
   unsigned long y, z;

   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);
   _ARGCHK(key != NULL);

   if (type == PK_PRIVATE && key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* header */
   y = PACKET_SIZE;

   /* header */
   buf2[y++] = type;
   buf2[y++] = sets[key->idx].size / 8;

   /* export y */
   OUTPUT_BIGNUM(&key->y, buf2, y, z);

   if (type == PK_PRIVATE) { 
      /* export x */
      OUTPUT_BIGNUM(&key->x, buf2, y, z);
   }
   
   /* check for overflow */
   if (*outlen < y) {
      #ifdef CLEAN_STACK
         zeromem(buf2, sizeof(buf2));
      #endif
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* store header */
   packet_store_header(buf2, PACKET_SECT_DH, PACKET_SUB_KEY, y);

   /* output it */
   *outlen = y;
   memcpy(out, buf2, y);

   /* clear mem */
   zeromem(buf2, sizeof(buf2));
   return CRYPT_OK;
}

int dh_import(const unsigned char *in, dh_key *key)
{
   long x, y, s;
   int errno;

   _ARGCHK(in != NULL);
   _ARGCHK(key != NULL);

   /* check type byte */
   if ((errno = packet_valid_header((unsigned char *)in, PACKET_SECT_DH, PACKET_SUB_KEY)) != CRYPT_OK) {
      return errno;
   }

   /* init */
   if (mp_init_multi(&key->x, &key->y, NULL) != MP_OKAY) { 
      return CRYPT_MEM;
   }

   y = PACKET_SIZE;
   key->type = in[y++];
   s  = (long)in[y++] * 8;
   
   for (x = 0; (s > sets[x].size) && (sets[x].size); x++);
   if (sets[x].size == 0) {
      errno = CRYPT_INVALID_KEYSIZE;
      goto error;
   }
   key->idx = x;

   /* type check both values */
   if ((key->type != PK_PUBLIC) && (key->type != PK_PRIVATE))  {
      errno = CRYPT_PK_TYPE_MISMATCH;
      goto error;
   }

   /* is the key idx valid? */
   if (!is_valid_idx(key->idx)) {
      errno = CRYPT_PK_TYPE_MISMATCH;
      goto error;
   }

   /* load public value g^x mod p*/
   INPUT_BIGNUM(&key->y, in, x, y);

   if (key->type == PK_PRIVATE) {
      INPUT_BIGNUM(&key->x, in, x, y);
   }
   return CRYPT_OK;
error:
   mp_clear_multi(&key->y, &key->x, NULL);
   return errno;
}

int dh_shared_secret(dh_key *private_key, dh_key *public_key, 
                     unsigned char *out, unsigned long *outlen)
{
   mp_int tmp, p;
   unsigned long x;
   int res;

   _ARGCHK(private_key != NULL);
   _ARGCHK(public_key  != NULL);
   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);

   /* types valid? */
   if (private_key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* same idx? */
   if (private_key->idx != public_key->idx) {
      return CRYPT_PK_TYPE_MISMATCH;
   }

   /* compute y^x mod p */
   if (mp_init_multi(&tmp, &p, NULL) != MP_OKAY) { 
      return CRYPT_MEM;
   }

   if (mp_read_radix(&p, sets[private_key->idx].prime, 10) != MP_OKAY)     { goto error; }
   if (mp_exptmod(&public_key->y, &private_key->x, &p, &tmp) != MP_OKAY)   { goto error; }

   /* enough space for output? */
   x = mp_raw_size(&tmp);
   if (*outlen < x) {
      res = CRYPT_BUFFER_OVERFLOW;
      goto done;
   }
   mp_toraw(&tmp, out);
   *outlen = x;
   res = CRYPT_OK;
   goto done;
error:
   res = CRYPT_MEM;
done:
   mp_clear_multi(&p, &tmp, NULL);
   return res;
}

#include "dh_sys.c"

#endif

