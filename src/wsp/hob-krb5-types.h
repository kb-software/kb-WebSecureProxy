#ifndef __HOB_KRB5_TYPES
  #define __HOB_KRB5_TYPES
   #ifdef _WIN32
#pragma once
#endif
#include <stddef.h>
#include "hob-krb5-defines.h"

  #ifndef	_BITS_TYPESIZES_H
  #define	_BITS_TYPESIZES_H	1
  /* See <bits/types.h> for the meaning of these macros.  This file exists so
     that <bits/types.h> need not vary across different GNU platforms.  */
  #define __DEV_T_TYPE			__UQUAD_TYPE
  #define __UID_T_TYPE			__U32_TYPE
  #define __GID_T_TYPE			__U32_TYPE
  #define __INO_T_TYPE			__ULONGWORD_TYPE
  #define __INO64_T_TYPE		__UQUAD_TYPE
  #define __MODE_T_TYPE			__U32_TYPE
  #define __NLINK_T_TYPE		__UWORD_TYPE
  #define __OFF_T_TYPE			__SLONGWORD_TYPE
  #define __OFF64_T_TYPE		__SQUAD_TYPE
  #define __PID_T_TYPE			__S32_TYPE
  #define __RLIM_T_TYPE			__ULONGWORD_TYPE
  #define __RLIM64_T_TYPE		__UQUAD_TYPE
  #define __BLKCNT_T_TYPE		__SLONGWORD_TYPE
  #define __BLKCNT64_T_TYPE		__SQUAD_TYPE
  #define __FSBLKCNT_T_TYPE		__ULONGWORD_TYPE
  #define __FSBLKCNT64_T_TYPE		__UQUAD_TYPE
  #define __FSFILCNT_T_TYPE		__ULONGWORD_TYPE
  #define __FSFILCNT64_T_TYPE		__UQUAD_TYPE
  #define __ID_T_TYPE			__U32_TYPE
  #define __CLOCK_T_TYPE		__SLONGWORD_TYPE
  #define __TIME_T_TYPE			__SLONGWORD_TYPE
  #define __USECONDS_T_TYPE		__U32_TYPE
  #define __SUSECONDS_T_TYPE		__SLONGWORD_TYPE
  #define __DADDR_T_TYPE		__S32_TYPE
  #define __SWBLK_T_TYPE		__SLONGWORD_TYPE
  #define __KEY_T_TYPE			__S32_TYPE
  #define __CLOCKID_T_TYPE		__S32_TYPE
  #define __TIMER_T_TYPE		__S32_TYPE
  #define __BLKSIZE_T_TYPE		__SLONGWORD_TYPE
  #define __FSID_T_TYPE			struct { int __val[2]; }
  #define __SSIZE_T_TYPE		__SWORD_TYPE

  #define	__FD_SETSIZE		1024
  #endif

  #ifndef _BITS_TYPES_H
  #define _BITS_TYPES_H 1                         

  typedef unsigned char __u_char;
  typedef unsigned short int __u_short;
  typedef unsigned int __u_int;
  typedef unsigned long int __u_long;

  typedef struct
  {
    long __val[2];
  } __quad_t;
  typedef struct
  {
    __u_long __val[2];
  } __u_quad_t;

  #define __S16_TYPE    short int
  #define __U16_TYPE    unsigned short int
  #define __S32_TYPE    int
  #define __U32_TYPE    unsigned int
  #define __SLONGWORD_TYPE  long int
  #define __ULONGWORD_TYPE  unsigned long int

  # define __SQUAD_TYPE   __quad_t
  # define __UQUAD_TYPE   __u_quad_t
  # define __SWORD_TYPE   int
  # define __UWORD_TYPE   unsigned int
  # define __SLONG32_TYPE long int
  # define __ULONG32_TYPE unsigned long int
  # define __S64_TYPE     __quad_t
  # define __U64_TYPE     __u_quad_t
          
  /* We want __extension__ before typedef's that use nonstandard base types
     such as `long long' in C89 mode.  */
  #define __STD_TYPE __extension__ typedef
  __STD_TYPE __DEV_T_TYPE __dev_t;  
  __STD_TYPE __UID_T_TYPE __uid_t;  
  __STD_TYPE __GID_T_TYPE __gid_t;  

  __STD_TYPE __MODE_T_TYPE 		__mode_t;  
  __STD_TYPE __NLINK_T_TYPE 		__nlink_t;  
  __STD_TYPE __OFF_T_TYPE 		__off_t;  
  __STD_TYPE __OFF64_T_TYPE			__off64_t;  
  __STD_TYPE __PID_T_TYPE 		__pid_t;  
  __STD_TYPE __FSID_T_TYPE 		__fsid_t;
  __STD_TYPE __CLOCK_T_TYPE 		__clock_t;  
  
  __STD_TYPE __TIME_T_TYPE 		__time_t;  
  __STD_TYPE __USECONDS_T_TYPE 	__useconds_t; 
  __STD_TYPE __SUSECONDS_T_TYPE 	__suseconds_t; 

  __STD_TYPE __SSIZE_T_TYPE		__ssize_t; 
  /* These few don't really vary by system, they always correspond
     to one of the other defined types.  */
  
  typedef __off64_t __loff_t;
   
  __STD_TYPE __U32_TYPE __socklen_t;
  #undef __STD_TYPE
  #endif 

   /*
   *  POSIX Standard: 2.6 Primitive System Data Types <sys/types.h>
   */
  #ifndef _SYS_TYPES_H
  #define _SYS_TYPES_H  1
                              
  #ifndef __u_char_defined
  typedef __u_char u_char;
  typedef __u_short u_short;
  typedef __u_int u_int;
  typedef __u_long u_long;
  typedef __quad_t quad_t;
  typedef __u_quad_t u_quad_t;
  typedef __fsid_t fsid_t;
  #define __u_char_defined
  #endif

  typedef __loff_t loff_t;

  #ifndef __dev_t_defined
  typedef __dev_t dev_t;
  #define __dev_t_defined
  #endif
  #ifndef __gid_t_defined
  typedef __gid_t gid_t;
  #define __gid_t_defined
  #endif
  #ifndef __mode_t_defined
  typedef __mode_t mode_t;
  #define __mode_t_defined
  #endif
  #ifndef __nlink_t_defined
  typedef __nlink_t nlink_t;
  # define __nlink_t_defined
  #endif
  #ifndef __uid_t_defined
  typedef __uid_t uid_t;
  #define __uid_t_defined
  #endif

  #ifndef __off_t_defined
  #ifndef __USE_FILE_OFFSET64
  typedef __off_t off_t;
  #else
  typedef __off64_t off_t;
  #endif
  #define __off_t_defined
  #endif

  #ifndef __pid_t_defined
  typedef __pid_t pid_t;
  #define __pid_t_defined
  #endif

  #ifndef __ssize_t_defined
  typedef __ssize_t ssize_t;
  #define __ssize_t_defined
  #endif

  #ifndef __int8_t_defined
  #define __int8_t_defined
  typedef char int8_t;
  typedef short int int16_t;
  typedef int int32_t;
  #endif

  typedef unsigned char u_int8_t;
  typedef unsigned short int u_int16_t;
  typedef unsigned int u_int32_t;

  #define __BIT_TYPES_DEFINED__ 1
  #endif 

  #ifndef __uint32_t_defined
  typedef unsigned int    uint32_t;
  #define __uint32_t_defined
  #endif

  #define O_RDONLY       00
  #define O_WRONLY       01
  #define O_RDWR         02
  #define O_CREAT      0100 
  #define O_EXCL       0200 
  #define O_APPEND    02000

#endif
