#ifndef SOLARIS_INC
#define SOLARIS_INC
// G.Oed, 22.02.2007, SOLARIS confuses Xercesc includes with linux !!!
//#define SOLARIS
#include <string.h>
#include <stdarg.h>
#define _OPEN_THREADS                      /* enable threads          */
#include <pthread.h>
#define TerminateThread(hThread,e) pthread_cancel((unsigned)hThread)
#define ODBCVER  0x0300
#define TRUE    1
#define FALSE 0
#define far
#define __cdecl
#define GetLastError() errno
#define WSAGetLastError() errno
#define closesocket(s) close(s)
#define _MAX_PATH 255
#define LPSTR char *
#define WINAPI
#define SOCKET_ERROR            (-1)
#define WSABASEERR              10000
/*
 * Windows Sockets definitions of regular Berkeley error constants
 */
#define WSAEWOULDBLOCK          (WSABASEERR+35)
#define WSAEINPROGRESS          (WSABASEERR+36)
#define WSAEALREADY             (WSABASEERR+37)
#define WSAENOTSOCK             (WSABASEERR+38)
#define WSAEDESTADDRREQ         (WSABASEERR+39)
#define WSAEMSGSIZE             (WSABASEERR+40)
#define WSAEPROTOTYPE           (WSABASEERR+41)
#define WSAENOPROTOOPT          (WSABASEERR+42)
#define WSAEPROTONOSUPPORT      (WSABASEERR+43)
#define WSAESOCKTNOSUPPORT      (WSABASEERR+44)
#define WSAEOPNOTSUPP           (WSABASEERR+45)
#define WSAEPFNOSUPPORT         (WSABASEERR+46)
#define WSAEAFNOSUPPORT         (WSABASEERR+47)
#define WSAEADDRINUSE           (WSABASEERR+48)
#define WSAEADDRNOTAVAIL        (WSABASEERR+49)
#define WSAENETDOWN             (WSABASEERR+50)
#define WSAENETUNREACH          (WSABASEERR+51)
#define WSAENETRESET            (WSABASEERR+52)
#define WSAECONNABORTED         (WSABASEERR+53)
#define WSAECONNRESET           2
#define WSAENOBUFS              (WSABASEERR+55)
#define WSAEISCONN              (WSABASEERR+56)
#define WSAENOTCONN             (WSABASEERR+57)
#define WSAESHUTDOWN            (WSABASEERR+58)
#define WSAETOOMANYREFS         (WSABASEERR+59)
#define WSAETIMEDOUT            (WSABASEERR+60)
#define WSAECONNREFUSED         (WSABASEERR+61)
#define WSAELOOP                (WSABASEERR+62)
#define WSAENAMETOOLONG         (WSABASEERR+63)
#define WSAEHOSTDOWN            (WSABASEERR+64)
#define WSAEHOSTUNREACH         (WSABASEERR+65)
#define WSAENOTEMPTY            (WSABASEERR+66)
#define WSAEPROCLIM             (WSABASEERR+67)
#define WSAEUSERS               (WSABASEERR+68)
#define WSAEDQUOT               (WSABASEERR+69)
#define WSAESTALE               (WSABASEERR+70)
#define WSAEREMOTE              (WSABASEERR+71)

#ifndef ULONG
typedef unsigned long int ULONG;
#endif
#ifndef WCHAR
typedef unsigned short int WCHAR;
#endif
#ifndef UINT
typedef unsigned int UINT;
#endif
#ifndef BYTE
typedef char BYTE;
#endif
#define VOID void
#define WORD short
#define DWORD unsigned int
#define LPWSTR char *
#define BOOL int
#define PUCHAR unsigned char *
#define SHORT short
#define CHAR char
#define PVOID void *
#define UNSIG_MED unsigned int
typedef PVOID HANDLE;
#define SOCKET int
#define __declspec(dllexport)
#define CreateFile(name,a,b,c,d,e,f) fopen(name,"rt")
#define INVALID_HANDLE_VALUE 0
#define CloseHandle(handle) (fclose((FILE*)handle)==0)
#ifdef FUCHS
#ifdef _STDIO_H
long GetFileSize(HANDLE stream,void * par2) {
long act_pos,len;
   act_pos = ftell((FILE*)stream);
   fseek((FILE*)stream,0,SEEK_END);
   len = ftell((FILE*)stream);
   fseek((FILE*)stream,act_pos,SEEK_SET);
   return len;
}
BOOL ReadFile(HANDLE hfi1,PVOID ap1,ULONG iplenb,ULONG* aiplenr, int par5) {
    *aiplenr = fread(ap1,1,iplenb,(FILE*)hfi1);
    if (*aiplenr == 0) {
        return FALSE;
    }
    return TRUE;
}
#endif
#endif
#endif

