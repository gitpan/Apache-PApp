#ifndef LZV1_H
#define LZV1_H

#define HSIZE	0x4000
#define HMASK	0x3fff
#define HSHIFT	5

#define	MLL	32		/*        Maximum len of chain of literals        */
#define	MML	(8+256)		/*        Maximum len of match                    */
#define	MOFF	8191		/*        Maximum offset                          */
#define	HSIZ	16384		/*        Size of Hashtable                       */

typedef	unsigned char	uch;
typedef	unsigned short	ush;
typedef	unsigned int	uit;

int LZV1_compress (uch *in, uch *out, ush *heap, int len, int out_len);
int LZV1_decompress (uch const *const in, uch * const out, int ilen, int len);

#endif

