#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <stdlib.h>
#include <libintl.h>

/* #if twofish  */
#include "aes.h"
#include "twofish2.c"

typedef struct cryptstate {
  keyInstance ki;
  cipherInstance ci;
} *Apache__PApp__Twofish;
/* #endif twofish */

/* #if lzv1 */
#include "lzv1.h"
#include "lzv1.c"
/* #endif lzv1 */

static char lclang[6] = "C";

MODULE = Apache::PApp		PACKAGE = Apache::PApp

PROTOTYPES: ENABLE

BOOT:
{
	/* we torture the gettext system _really_ hard */
	/* but it's faster and more reliable in this, wrong, way */
        setenv ("LANG", "fluffball", 1);
        setenv ("LC_MESSAGES", "fluffball", 1);
	setlocale (LC_ALL, "");
        setlocale (LC_MESSAGES, "");
}

void
setmsglang(locale)
	char *	locale
        PROTOTYPE: $
	CODE:
        if (!locale[2] || !locale[5])
          {
            if (strcmp (locale, lclang))
              {
                strncpy (lclang, locale, 5); lclang[5] = 0;
                bindtextdomain(lclang, "/fluffball/locale");
                textdomain(lclang);
              }
          }
        else
          croak ("locale value '%s' malformed", locale);

char *
bindtextdomain(d,dir)
	char *	d
	char *	dir
        PROTOTYPE: $$

char *
textdomain(d)
	char *	d
        PROTOTYPE: $

char *
dgettext(d,s)
	char *	d
	char *	s
        PROTOTYPE: $$

char *
gettext(s)
	char *	s
        PROTOTYPE: $
        ALIAS:
        	__ = 0
        CODE:
        RETVAL = s[0] ? gettext(s) : s;
	OUTPUT:
        RETVAL

SV *
lzv1_compress(data)
        SV *	data
        PROTOTYPE: $
        CODE:
        {
          STRLEN usize, csize;
          void *src = SvPV(data, usize);
          unsigned char *dst;
          unsigned short heap[HSIZ]; /* need not be initialized */

          if (usize)
            {
              RETVAL = NEWSV (0, usize + 1);
              SvPOK_only (RETVAL);
              dst = (unsigned char *)SvPV_nolen (RETVAL);

              /* compress  */
              csize = LZV1_compress ((uch *)src, (uch *)(dst + 4), heap, usize, usize - 5);
              if (csize)
                {
                  dst[0] = 'L'; /* compressed flag */
                  dst[1] = usize >> 16;
                  dst[2] = usize >>  8;
                  dst[3] = usize >>  0;

                  SvCUR_set (RETVAL, csize + 4);
                }
              else
                {
                  dst[0] = 'U';
                  Move ((void *)src, (void *)(dst + 1), usize, unsigned char);
                  SvCUR_set (RETVAL, usize + 1);
                }
            }
          else
            RETVAL = newSVpv ("", 0);
        }
	OUTPUT:
        RETVAL

SV *
lzv1_decompress(data)
        SV *	data
        PROTOTYPE: $
        CODE:
        {
          STRLEN usize, csize;
          unsigned char *src = (unsigned char *)SvPV(data, csize);
          void *dst;

          if (csize)
            {
              switch (src[0]) {
                case 'U':
                  usize = csize - 1;
                  RETVAL = NEWSV (0, usize);
                  SvPOK_only (RETVAL);
                  dst = SvPV_nolen (RETVAL);

                  Move ((void *)(src + 1), (void *)dst, usize, unsigned char);
                  break;
                case 'L':
                  usize = (src[1] << 16)
                        | (src[2] <<  8)
                        | (src[3] <<  0);
                  RETVAL = NEWSV (0, usize);
                  SvPOK_only (RETVAL);
                  dst = SvPV_nolen (RETVAL);

                  if (LZV1_decompress ((uch *)(src + 4), (uch *)dst, csize - 4, usize) != usize)
                    croak ("LZV1: compressed data corrupted (2)");
                  break;
                default:
                  croak ("LZV1: compressed data corrupted (1)");
              }

              SvCUR_set (RETVAL, usize);
            }
          else
            RETVAL = newSVpv ("", 0);
        }
	OUTPUT:
        RETVAL

MODULE = Apache::PApp		PACKAGE = Apache::PApp::Twofish

Apache::PApp::Twofish
new(class, key, mode=MODE_ECB)
	SV *	class
	SV *	key
        int	mode
        CODE:
        {
          STRLEN keysize = SvCUR(key);

          if (keysize != 16 && keysize != 24 && keysize != 32)
            croak ("wrong key length: key must be 128, 192 or 256 bits long");
          if (mode != MODE_ECB && mode != MODE_CBC && mode != MODE_CFB1)
            croak ("illegal mode: mode must be MODE_ECB, MODE_CBC or MODE_CFB1");

          Newz(0, RETVAL, 1, struct cryptstate);
          
          if (makeKey (&RETVAL->ki, DIR_ENCRYPT, keysize*8, SvPV_nolen(key)) != TRUE)
            croak ("Apache::PApp::Twofish: makeKey failed, please report!\n");
          if (cipherInit (&RETVAL->ci, mode, 0) != TRUE) /* no IV supported (yet) */
            croak ("Apache::PApp::Twofish: makeKey failed, please report!\n");
        }         
	OUTPUT:
        RETVAL

SV *
encrypt(self, data)
 	Apache::PApp::Twofish self
        SV *	data
        ALIAS:
        	decrypt = 1
        CODE:
        {
          SV *res;
          STRLEN size;
          void *rawbytes = SvPV(data,size);

          if (size)
            {
              if ((size << 3) % BLOCK_SIZE)
                croak ("encrypt: datasize not multiple of blocksize (%d bits)", BLOCK_SIZE);

              RETVAL = NEWSV (0, size);
              SvPOK_only (RETVAL);
              SvCUR_set (RETVAL, size);

              if ((ix ? blockDecrypt : blockEncrypt)
                    (&self->ci, &self->ki, rawbytes, size << 3, SvPV_nolen(RETVAL)) < 0)
                croak ("block(De|En)crypt: unknown error, please report\n");
            }
          else
            RETVAL = newSVpv ("", 0);
        }
	OUTPUT:
        RETVAL

void
DESTROY(self)
        Apache::PApp::Twofish self
        CODE:
        Safefree(self);

