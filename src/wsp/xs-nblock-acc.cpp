#if defined(WIN32) || defined(WIN64)
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <process.h>
#endif
#ifdef HL_UNIX
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stropts.h>
#include <poll.h>
#include <unistd.h>

#include <fcntl.h>

#include <pthread.h>
#include <netdb.h>
#include <sys/socket.h>
#include <string.h>

#include <hob-hunix01.h>
#endif
#include "hob-nblock_acc.hpp"

dsd_nblock_acc::dsd_tcpthread_p dsd_nblock_acc::ads_thranc = NULL;      // anchor for tcp threads
#if defined(WIN32) || defined(WIN64)
CRITICAL_SECTION
#else
pthread_mutex_t
#endif
					dsd_nblock_acc::ds_critsect;           // critical section for safe access to ressources
