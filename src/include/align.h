#ifndef ALIGN_H
#define ALIGN_H

#define ALIGN_SIZE sizeof(void*)
#define ALIGN_CAST (long long)
#if 0
#ifndef HL_LINUX_ARM
    #define ALIGN_SIZE 8
    #define ALIGN_CAST (long long)
#else 
    #define ALIGN_SIZE 4
    #define ALIGN_CAST (int)
#endif
#endif

#if defined _IA64_ || defined __HOB_ALIGN__
    #define DO_ALIGN(a)   (char*)(( ALIGN_CAST&(((char*)av_start)[0]) + (ALIGN_SIZE-1)) & ALIGN_CAST(~(ALIGN_SIZE-1)))
#else // do nothing; just a dummy
    #define DO_ALIGN(a)   av_start
#endif

#define ALIGN_INT(in_align) ((in_align + (ALIGN_SIZE-1)) & (~(ALIGN_SIZE-1)))

#endif
