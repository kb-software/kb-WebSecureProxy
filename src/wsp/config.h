/*_JF_Die Datei C:/Kerberos/auto_analyse_log_TGT/dateien/header/config.h wurde automatisch veraendert! Phase 7*/

#ifdef BUILD_KRB5_LIB
#ifndef KRB5_LIB_FUNCTION
#ifdef _WIN32_
#define KRB5_LIB_FUNCTION _export _stdcall
#else
#define KRB5_LIB_FUNCTION
#endif
#endif
#endif

#ifdef BUILD_ROKEN_LIB
#ifndef ROKEN_LIB_FUNCTION
#ifdef _WIN32_
#define ROKEN_LIB_FUNCTION _export _stdcall
#else
#define ROKEN_LIB_FUNCTION
#endif
#endif
#endif

#ifndef RCSID
#define RCSID(msg) \
static /**/const char *const rcsid[] = { (const char *)rcsid, "@(#)" msg }
#endif

#define MaxHostNameLen (64+4)
#define MaxPathLen (1024+4)

#define AUTHENTICATION 1

#define BINDIR "/usr/heimdal/bin"

#define DES_ENCRYPTION 1

#define DIAGNOSTICS 1

#define ENABLE_PTHREAD_SUPPORT 1

#define ENCRYPTION 1

#define ENDIANESS_IN_SYS_PARAM_H 1

/* define if prototype of gethostbyaddr is compatible with struct hostent
   *gethostbyaddr(const void *, size_t, int) */

/* define if prototype of gethostbyname is compatible with struct hostent
   *gethostbyname(const char *) */

/* define if prototype of getservbyname is compatible with struct servent
   *getservbyname(const char *, const char *) */

/* define if prototype of getsockname is compatible with int getsockname(int,
   struct sockaddr*, socklen_t*) */
#define GETSOCKNAME_PROTO_COMPATIBLE 1

#define HAVE_ARPA_FTP_H 1

#define HAVE_ARPA_NAMESER_H 1

#define HAVE_ARPA_TELNET_H 1

#define HAVE_CRYPT 1

#define HAVE_CURSES_H 1

#define HAVE_DB3 1

#define HAVE_DB4_DB_H 1

#define HAVE_DB_185_H 1

#define HAVE_DB_CREATE 1

#define HAVE_DB_H 1

/* Define to 1 if you have the declaration of `altzone', and to 0 if you
   don't. */

/* Define to 1 if you have the declaration of `environ', and to 0 if you
   don't. */
#define HAVE_DECL_ENVIRON 1

/* Define to 1 if you have the declaration of `h_errlist', and to 0 if you
   don't. */

/* Define to 1 if you have the declaration of `h_errno', and to 0 if you
   don't. */
#define HAVE_DECL_H_ERRNO 0

/* Define to 1 if you have the declaration of `h_nerr', and to 0 if you don't.
   */

/* Define to 1 if you have the declaration of `optarg', and to 0 if you don't.
   */
#define HAVE_DECL_OPTARG 1

/* Define to 1 if you have the declaration of `opterr', and to 0 if you don't.
   */
#define HAVE_DECL_OPTERR 1

/* Define to 1 if you have the declaration of `optind', and to 0 if you don't.
   */
#define HAVE_DECL_OPTIND 1

/* Define to 1 if you have the declaration of `optopt', and to 0 if you don't.
   */
#define HAVE_DECL_OPTOPT 1

/* Define to 1 if you have the declaration of `timezone', and to 0 if you
   don't. */
#define HAVE_DECL_TIMEZONE 1

/* Define to 1 if you have the declaration of `_res', and to 0 if you don't.
   */
#define HAVE_DECL__RES 1

/* Define to 1 if you have the declaration of `__progname', and to 0 if you
   don't. */
#define HAVE_DECL___PROGNAME 0

#define HAVE_DIRENT_H 1

#define HAVE_DLFCN_H 1

#define HAVE_DLOPEN 1

#define HAVE_FCNTL 1

#define HAVE_FCNTL_H 1

#define HAVE_FNMATCH 1

#define HAVE_FNMATCH_H 1

#define HAVE_GETCWD 1

#define HAVE_GETDTABLESIZE 1

#define HAVE_GETEGID 1

#define HAVE_GETEUID 1

#define HAVE_GETGID 1

#define HAVE_GETHOSTNAME 1

#define HAVE_GETLOGIN 1

#define HAVE_GETOPT 1

#define HAVE_GETPAGESIZE 1

#define HAVE_GETPWNAM_R 1

#define HAVE_GETRLIMIT 1

#define HAVE_GETSOCKOPT 1

#define HAVE_GETSPNAM 1

#define HAVE_GETUID 1

#define HAVE_GETUSERSHELL 1

/* define if you have a glob() that groks GLOB_BRACE, GLOB_NOCHECK,
   GLOB_QUOTE, GLOB_TILDE, and GLOB_LIMIT */

#define HAVE_GRANTPT 1

#define HAVE_GRP_H 1

#define HAVE_H_ERRNO 1

#define HAVE_IFADDRS_H 1

#define HAVE_INITGROUPS 1

#define HAVE_INITSTATE 1

#define HAVE_INNETGR 1

#define HAVE_INT16_T 1

#define HAVE_INT32_T 1

#define HAVE_INT64_T 1

#define HAVE_INT8_T 1

#define HAVE_INTTYPES_H 1

#define HAVE_IRUSEROK 1

#define HAVE_LIMITS_H 1

#define HAVE_LOCALTIME_R 1

#define HAVE_LOGOUT 1

#define HAVE_LOGWTMP 1

#define HAVE_LONG_LONG 1

#define HAVE_MEMMOVE 1

#define HAVE_MEMORY_H 1

#define HAVE_MKTIME 1

#define HAVE_MMAP 1

#define HAVE_NETDB_H 1

#define HAVE_NETINET_IP_H 1

#define HAVE_NETINET_TCP_H 1

#define HAVE_NET_IF_H 1

#define HAVE_OPENPTY 1

#define HAVE_PATHS_H 1

#define HAVE_POLL 1

#define HAVE_POLL_H 1

#define HAVE_PTHREAD_H 1

#define HAVE_PTSNAME 1

#define HAVE_PTY_H 1

#define HAVE_PUTENV 1

#define HAVE_PWD_H 1

#define HAVE_RAND 1

#define HAVE_RCMD 1

#define HAVE_READLINE 1

#define HAVE_READV 1

#define HAVE_RPCSVC_YPCLNT_H 1

#define HAVE_SA_FAMILY_T 1

#define HAVE_SELECT 1

#define HAVE_SETEGID 1

#define HAVE_SETENV 1

#define HAVE_SETEUID 1

#define HAVE_SETITIMER 1

#define HAVE_SETPGID 1

#define HAVE_SETREGID 1

#define HAVE_SETRESGID 1

#define HAVE_SETRESUID 1

#define HAVE_SETREUID 1

#define HAVE_SETSID 1

#define HAVE_SETSOCKOPT 1

#define HAVE_SETSTATE 1

#define HAVE_SETUTENT 1

#define HAVE_SGTTY_H 1

#define HAVE_SHADOW_H 1

#define HAVE_SIGACTION 1

#define HAVE_SIGNAL_H 1

#define HAVE_SOCKET 1

#define HAVE_SOCKLEN_T 1

#define HAVE_SSIZE_T 1

#define HAVE_STDINT_H 1

#define HAVE_STDLIB_H 1

#define HAVE_STRCASECMP 1

#define HAVE_STRDUP 1

#define HAVE_STRNCASECMP 1

#define HAVE_STRNDUP 1

#define HAVE_STRNLEN 1

#define HAVE_STRPTIME 1

#define HAVE_STRSEP 1

#define HAVE_STRSTR 1

#define HAVE_STRTOK_R 1

#define HAVE_STRUCT_ADDRINFO 1

#define HAVE_STRUCT_IFADDRS 1

#define HAVE_STRUCT_IOVEC 1

#define HAVE_STRUCT_MSGHDR 1

#define HAVE_STRUCT_SOCKADDR 1

#define HAVE_STRUCT_SOCKADDR_STORAGE 1

#define HAVE_STRUCT_SPWD 1

#define HAVE_STRUCT_TM_TM_GMTOFF 1

#define HAVE_STRUCT_TM_TM_ZONE 1

#define HAVE_STRUCT_UTMP_UT_ADDR 1

#define HAVE_STRUCT_UTMP_UT_HOST 1

#define HAVE_STRUCT_UTMP_UT_ID 1

#define HAVE_STRUCT_UTMP_UT_PID 1

#define HAVE_STRUCT_UTMP_UT_TYPE 1

#define HAVE_STRUCT_UTMP_UT_USER 1

#define HAVE_STRUCT_WINSIZE 1

#define HAVE_SWAB 1

#define HAVE_SYSCONF 1

#define HAVE_SYSCTL 1

#define HAVE_SYSLOG 1

#define HAVE_SYSLOG_H 1

#define HAVE_SYS_BITYPES_H 1

#define HAVE_SYS_CAPABILITY_H 1

#define HAVE_SYS_FILE_H 1

#define HAVE_SYS_IOCTL_H 1

#define HAVE_SYS_MMAN_H 1

#define HAVE_SYS_PARAM_H 1

#define HAVE_SYS_RESOURCE_H 1

#define HAVE_SYS_SELECT_H 1

#define HAVE_SYS_SOCKET_H 1

#define HAVE_SYS_STAT_H 1

#define HAVE_SYS_SYSCALL_H 1

#define HAVE_SYS_SYSCTL_H 1

#define HAVE_SYS_TIMEB_H 1

#define HAVE_SYS_TIMES_H 1

#define HAVE_SYS_TIME_H 1

#define HAVE_SYS_TYPES_H 1

#define HAVE_SYS_UIO_H 1

#define HAVE_SYS_UN_H 1

#define HAVE_SYS_UTSNAME_H 1

#define HAVE_SYS_WAIT_H 1

#define HAVE_TERMCAP_H 1

#define HAVE_TERMIOS_H 1

#define HAVE_TERMIO_H 1

#define HAVE_TERM_H 1

#define HAVE_TGETENT 1

#define HAVE_TIMEZONE 1

#define HAVE_TIME_H 1

#define HAVE_TTYNAME 1

#define HAVE_TTYSLOT 1

#define HAVE_UINT16_T 1

#define HAVE_UINT32_T 1

#define HAVE_UINT64_T 1

#define HAVE_UINT8_T 1

#define HAVE_UMASK 1

#define HAVE_UNAME 1

#define HAVE_UNISTD_H 1

#define HAVE_UNLOCKPT 1

#define HAVE_UNSETENV 1

#define HAVE_UTMPX_H 1

#define HAVE_UTMP_H 1

#define HAVE_U_INT16_T 1

#define HAVE_U_INT32_T 1

#define HAVE_U_INT64_T 1

#define HAVE_U_INT8_T 1

#define HAVE_VHANGUP 1

#define HAVE_VSYSLOG 1

#define HAVE_VWARNX 1

#define HAVE_WARNX 1

#define HAVE_WRITEV 1

#define HAVE__RES 1

#define HAVE___PROGNAME 1

#define KRB5 1

#define LIBDIR "/usr/heimdal/lib"

#define LIBEXECDIR "/usr/heimdal/libexec"

#define LOCALSTATEDIR "/var/heimdal"

#define NEED_ASNPRINTF_PROTO 1

#define NEED_MKSTEMP_PROTO 1

#define NEED_STRSVIS_PROTO 1

#define NEED_STRUNVIS_PROTO 1

#define NEED_STRVISX_PROTO 1

#define NEED_STRVIS_PROTO 1

#define NEED_SVIS_PROTO 1

#define NEED_UNVIS_PROTO 1

#define NEED_VASNPRINTF_PROTO 1

#define NEED_VIS_PROTO 1

#define OLD_ENVIRON 1

/* define if prototype of openlog is compatible with void openlog(const char
   *, int, int) */
#define OPENLOG_PROTO_COMPATIBLE 1

#define OTP 1

#define PACKAGE "heimdal"

#define PACKAGE_BUGREPORT "heimdal-bugs@pdc.kth.se"

#define PACKAGE_NAME "Heimdal"

#define PACKAGE_STRING "Heimdal 0.7.2"

#define PACKAGE_TARNAME "heimdal"

#define PACKAGE_VERSION "0.7.2"

#define POSIX_GETLOGIN 1

#define RETSIGTYPE void

#define SBINDIR "/usr/heimdal/sbin"

#define STDC_HEADERS 1

#define SYSCONFDIR "/etc"

#define TIME_WITH_SYS_TIME 1

#define VERSION "0.7.2"

#define VOID_RETSIGTYPE 1

#define X_DISPLAY_MISSING 1

/* Define to 1 if `lex' declares `yytext' as a `char *' by default, not a
   `char[]'. */
#define YYTEXT_POINTER 1

#define _GNU_SOURCE 1

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */

#if defined(HAVE_FOUR_VALUED_KRB_PUT_INT) || !defined(KRB4)
#define KRB_PUT_INT(F, T, L, S) krb_put_int((F), (T), (L), (S))
#else
#define KRB_PUT_INT(F, T, L, S) krb_put_int((F), (T), (S))
#endif

#if defined(ENCRYPTION) && !defined(AUTHENTICATION)
#define AUTHENTICATION 1
#endif

/* Set this to the default system lead string for telnetd
 * can contain %-escapes: %s=sysname, %m=machine, %r=os-release
 * %v=os-version, %t=tty, %h=hostname, %d=date and time
 */

#ifndef LOGIN_PATH
#define LOGIN_PATH BINDIR "/login"
#endif

#ifndef HAVE_KRB_KDCTIMEOFDAY
#define krb_kdctimeofday(X) gettimeofday((X), NULL)
#endif

#ifndef HAVE_KRB_GET_KDC_TIME_DIFF
#define krb_get_kdc_time_diff() (0)
#endif

#ifdef VOID_RETSIGTYPE
#define SIGRETURN(x) return
#else
#define SIGRETURN(x) return (RETSIGTYPE)(x)
#endif

#ifdef BROKEN_REALLOC
#define realloc(X, Y) rk_realloc((X), (Y))
#endif

#if _AIX
#define _ALL_SOURCE

struct ether_addr;
struct sockaddr;
struct sockaddr_dl;
struct sockaddr_in;
#endif

#if IRIX == 4 && !defined(__STDC__)
#define __STDC__ 0
#endif

