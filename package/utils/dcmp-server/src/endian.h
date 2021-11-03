/*
** endian.h
** the big-endian or little-endian swap.
*/

#ifndef _ENDIAN_H_
#define _ENDIAN_H_

/* The macro SWAP for chip swap, NETS for packet swap*/
#if 1
/* #define __BIG_ENDIAN__  already defined in linux kernel */
#ifdef __BIG_ENDIAN__

#ifndef le16_to_cpu
#define le16_to_cpu(x)  (((x & 0x00ff) << 8) | ((x & 0xff00) >> 8))
#define cpu_to_le16(x)  le16_to_cpu(x)
#define le32_to_cpu(x)  (((x & 0x000000ff) << 24) | ((x & 0xff000000) >> 24)| ((x & 0x00ff0000) >> 8)| ((x & 0x0000ff00) << 8))
#define cpu_to_le32(x)  le32_to_cpu(x)
#endif /* le16_to_cpu */

#ifndef ntohs
#define ntohs(x)    (x)
#define ntohl(x)    (x)
#define htons(x)    (x)
#define htonl(x)    (x)
#endif /* ntohs */

#else /* __LITTLE_ENDIAN__ */

#ifndef le16_to_cpu
#define le16_to_cpu(x)  (x)
#define cpu_to_le16(x)  (x)
#define le32_to_cpu(x)  (x)
#define cpu_to_le32(x)  (x)
#endif /* le16_to_cpu */

#ifndef ntohs
#define ntohs(x)    (((x & 0x00ff) << 8) | ((x & 0xff00) >> 8))
#define ntohl(x)    (((x & 0x000000ff) << 24) | ((x & 0xff000000) >> 24)| ((x & 0x00ff0000) >> 8)| ((x & 0x0000ff00) << 8))
#define htons(x)    ntohs(x)
#define htonl(x)    ntohl(x)
#endif /* ntohs */

#endif /* __BIG_ENDIAN__ */
#endif

/* The bitfield of linux-i386-gcc is LSB to MSB. */
/* If not swapped, the e_bit will be the LSB.    */
#ifdef __LITTLE_ENDIAN_BITFIELD
#define LC_BIG_ENDIAN_BITFIELD
#endif

#if defined(LC_BIG_ENDIAN_BITFIELD)
#define X(a,b)  b,a
#else
#define X(a,b)  a,b
#endif

#endif /* _ENDIAN_H_ */

/* vi:set ts=4 sw=4: */
