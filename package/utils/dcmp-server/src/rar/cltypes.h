#ifndef CL_TYPES_H
#define CL_TYPES_H

#if 1
typedef unsigned char u8_t;
typedef char i8_t;
typedef unsigned short u16_t;
typedef short i16_t;
typedef unsigned int u32_t;
typedef int i32_t;
#endif

#ifdef RAR_DEBUG
#define rar_dbgmsg(fmt, args...) printf(fmt, ## args)
#define rar_errmsg(fmt, args...) printf(fmt, ## args)
#else
#define rar_dbgmsg(fmt, args...)
#define rar_errmsg(fmt, args...)
#endif

#endif
