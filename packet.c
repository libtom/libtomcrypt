#include "mycrypt.h"

#ifdef PACKET

void packet_store_header(unsigned char *dst, int section, int subsection)
{
   _ARGCHK(dst != NULL);

   /* store version number */
   dst[0] = CRYPT&255;
   dst[1] = (CRYPT>>8)&255;

   /* store section and subsection */
   dst[2] = section & 255;
   dst[3] = subsection & 255;

}

int packet_valid_header(unsigned char *src, int section, int subsection)
{
   unsigned long ver;

   _ARGCHK(src != NULL);

   /* check version */
   ver = ((unsigned long)src[0]) | ((unsigned long)src[1] << 8);
   if (CRYPT < ver) {
      return CRYPT_INVALID_PACKET;
   }

   /* check section and subsection */
   if (section != src[2] || subsection != src[3]) {
      return CRYPT_INVALID_PACKET;
   }

   return CRYPT_OK;
}

#endif

 
