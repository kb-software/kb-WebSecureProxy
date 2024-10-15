#!/usr/bin/env bash

. ./functions.sh

COMPILATION_START=`date +%s`

DEBUG="-g"

#Define whether we are on FreeBSD or on Linux
SYSTEM=$(uname -s)

#Define system architecture
ARCH=$(uname -m)

echo "$0: Parse the arguments"
#parse the arguments. We have --debug (-g) and -x32 arguments till now
while [ $# -gt 0 ]
do
key="$1"

case $key in
    -g|--debug)
        OPTIMIZATION="-O0"
        shift # remove this argument from the script's argument list, shifting all the others over by one
        ;;
    -x32)
        BIT=32
        if [ "$SYSTEM" == "Linux" ]
            then ARCH=x86_32
        elif [ "$SYSTEM" == "FreeBSD" ]
            then ARCH=i386
        fi
        shift # remove argument
        ;;
    *)
    echo "Unknown option $key, please use --debug for debug or -x32 for x86_32 version"
        shift       # unknown option
        ;;
esac
done

#Call this script with a parameter --debug for a debug version without optimization
if [ -z $OPTIMIZATION ]
    then echo "We are building now a release version (optimized version with debug symbols in an extra file nbipgw20.debug), for a debug one without optimization please call this script with parameter --debug or -g."
         OPTIMIZATION="-O2 -fno-strict-aliasing"
fi

#For cross compilation use the -x32 flag
if [ -z $BIT ]
    then echo "Compiling for $SYSTEM on $ARCH. For 32 bit cross compilation please call this script with -x32 flag."
         BIT=64
fi

if [[ -n $XERCES_SRC ]]; then
    XERCES_INCLUDE="-I$XERCES_SRC"
fi

CFLAGS="-c $OPTIMIZATION $DEBUG -m$BIT -fsigned-char -pthread -DHL_UNIX -DHPPPT1_V21 -DD_INCL_HOB_TUN -DXH_INTERFACE -D_FILE_OFFSET_BITS=64 -I. $XERCES_INCLUDE"

case "$SYSTEM" in
    Linux)  CFLAGS="$CFLAGS -DHL_LINUX"
        CC=gcc
        LC=g++
        ;;
    FreeBSD) CFLAGS="$CFLAGS -DHL_FREEBSD"
        CC=clang
        LC=clang++
        ;;
esac

LFLAGS="-m$BIT $DEBUG -pthread"

#delete existing object files for clean compilation
if [[ -n $(find . -iname '*.o' -print -quit) ]]
    then rm *.o
    echo "Removing object files for clean build"
fi

echo "$0: Compile sources"
echo $CC $CFLAGS -Wno-invalid-offsetof -I/usr/local/include -D"HL_CPUTYPE=\"$SYSTEM-$ARCH\"" -D"MSG_CPU_TYPE=\"$SYSTEM-$ARCH \"" nbipgw20.cpp 
$CC $CFLAGS -Wno-invalid-offsetof -I/usr/local/include -D"HL_CPUTYPE=\"$SYSTEM-$ARCH\"" -D"MSG_CPU_TYPE=\"$SYSTEM-$ARCH \"" nbipgw20.cpp || m_echo_and_exit "Error compiling $FILE" 1
m_compile -I/usr/local/include -DHOB_CONTR_TIMER xsipgw08-conf.cpp
m_compile xsclibrdp1.cpp
m_compile xsavl03.cpp
m_compile xslnetw1.cpp
m_compile -DHOB_CONTR_TIMER xslcontr.cpp
m_compile nstcpco1.cpp
m_compile xs_nblock_acc.cpp
m_compile xs-gw-cluster.cpp
m_compile xs-gw-udp-gate-srtp.cpp
m_compile xs-gw-admin.cpp
m_compile xs-gw-l2tp.cpp
m_compile xs-gw-ppp.cpp
m_compile xsltime1.cpp
m_compile xsl-stor-big-n.cpp
m_compile xsl-tcp-sync-01.cpp
m_compile xsregex01.c


################
# SSL routines #
################

#for the compilation of the encry file by clang we should switch off the optimization
# TODO: add comment/explanation -> ask Crypto team
if [ "$SYSTEM" == "FreeBSD" ]
    then DEOPTIMIZE="-O0"
fi

echo "$0: Compile assembly"
#compile cpuaes86 or cpuaes32 if possible
if [ "$ARCH" == "x86_64" -o "$ARCH" == "amd64" ]
    then CFLAGS="$CFLAGS -DUSE_ASSEMBLER_SOURCES -DHL_PRFMAXSO_I=4 -DHL_PRFMAXSO_L=8 -DHL_PRFMAXSO_LL=8"
         AES="cpuaes$BIT"
         ENCRY="is-encry-2-x64"
         CAS="is-random-cas-02-64-nasm"
         ISLOCK="islock03-64-nasm"
         m_compile_asm $AES.s
         m_compile_asm $ENCRY.s
         m_compile_asm $CAS.s
         m_compile_asm $ISLOCK.s
elif [ "$ARCH" == "x86_32" -o "$ARCH" == "i386" ]
    then CFLAGS="$CFLAGS -DUSE_ASSEMBLER_SOURCES -DHL_PRFMAXSO_I=4 -DHL_PRFMAXSO_L=4 -DHL_PRFMAXSO_LL=8"
         AES="cpuaes86"
         CAS="is-random-cas-02-32-nasm"
         ISLOCK="islock03-32-nasm"
         m_compile_asm $AES.s
         m_compile_asm $CAS.s
         m_compile_asm $ISLOCK.s
elif [ "$ARCH" == "s390x" ]
    then ENCRY="is-encry-2-s390x"
         as -o $ENCRY.o $ENCRY.s
elif [ "$ARCH" == "arm64" ]
    then echo "In process"
         ENCRY="is-encry-2-arm64"
         m_compile_asm $ENCRY.s
else echo "No AES assembler sources availible for this architecture yet"
fi

m_compile xslunic1.cpp

if [ -f $AES.o ]
    then AES=$AES.o
else AES=""
fi

if [ -f $ENCRY.o ]
    then ENCRY=$ENCRY.o
else ENCRY=""
fi

if [ -f $CAS.o ]
    then CAS=$CAS.o
else CAS=""
fi

if [ -f $ISLOCK.o ]
    then ISLOCK=$ISLOCK.o
else ISLOCK=""
fi

# add this options to the compiler flags -fstack-protector-all -Wstack-protector -D_FORTIFY_SOURCE=2 -Wall
SSL_CFLAGS="$CFLAGS -fstack-protector-all -Wstack-protector -D_FORTIFY_SOURCE=2 -Wall"

#Mainframes are always big endian
if [ "$ARCH" == "s390x" ]
    then SSL_CFLAGS="$SSL_CFLAGS -DHL_BIG_ENDIAN"
fi

echo "$0: Compile SSL"
m_linking $SSL_CFLAGS $DEOPTIMIZE xs-encry-1.cpp
m_linking $SSL_CFLAGS xs-encry-2.cpp
m_linking $SSL_CFLAGS xs-ssl-1.cpp
m_linking $SSL_CFLAGS xs-cert-1.cpp


echo "$0: Compile sources"
m_compile xstuntapif.cpp
m_compile xshusip01.cpp
m_compile xshsstp01.cpp
m_compile xshsessutil01.cpp
m_compile xshpppi01.cpp
m_compile xs-htcp-01.cpp
m_compile xs-htcp-hdr-01.cpp
m_compile xs-htcp-htun-01.cpp
m_compile xsl-ntlm-01.cpp
m_compile xsllog01.cpp
m_compile xsl-http-header-1.cpp
m_compile xsrerrm1.cpp
m_compile xs-lbal-win-1.cpp
m_compile xs-gw-radius-01.cpp
m_compile -I/usr/local/include xs-gw-serv-vch-icap.cpp
m_compile xs-gw-udp-01.cpp
m_compile -DHOB_CONTR_TIMER xs-gw-cma1-02.cpp

#for -x32 version on linux use -march=i486 flag
#(to avoid error "undefined reference to `__sync_sub_and_fetch_4'" with -m32 on 64 bit machine and old gcc versions (here 4.3.4))
if [ "$ARCH" == "x86_32" ]
    then FLAG32="-march=i486"
fi
m_compile $FLAG32 xsldapco1.cpp

m_compile -DHOB_CONTR_TIMER xs-gw-krb5-lib-interface.c
m_compile -DHOB_CONTR_TIMER xs-gw-krb5-lib.c
m_compile -DHOB_CONTR_TIMER xs-gw-krb5-control.cpp

#this block is obsolete on standard architectures,
#if you want to compile for s390x or aarch64(arm64),
#please use ISLOCK_2 in the linking process instead of ISLOCK

#this file is always necessary; choose the correct architecture
if [ "$ARCH" == "x86_64" -o "$ARCH" == "amd64" ]
    then ISLOCK_2="islock02-64-gcc"
elif [ "$ARCH" == "x86_32" ]
    then ISLOCK_2="islock02-32-gcc"
elif [ "$ARCH" == "s390x" ]
    then ISLOCK_2="islock02-64-s390-gcc"
elif [ "$ARCH" == "aarch64" ]
    then ISLOCK_2="islock02-64-aarch64-gcc"
else echo "No locking routines (islock02) availible for this architecture yet"
     exit 1
fi

# specify "-no-integrated-as" to avoid usage of the internal clang assembler that does not support the --64/--32 options
if [ "$SYSTEM" == "Linux" -a "$ARCH" != "s390x" ]
    then echo "obsolete: changed to new islock-03 version." # $CC $CFLAGS -O -Wa,-L,--$BIT $ISLOCK_2.s 
elif [ "$SYSTEM" == "FreeBSD" ]
    then m_compile -no-integrated-as -Wa,-L,--$BIT $ISLOCK_2.s
else m_compile -O -Wa,-L $ISLOCK_2.s
fi


# libxerces-c-3.1.so is supposed to be available in one of the folliwing places; otherwise, change the -L option parameter below. Probably we should also add the architecture recognition.
if [[ "$SYSTEM" == "FreeBSD" ]]; then
    if [[ -n $XERCES_LIB ]]; then
        XERCESDIR=$XERCES_LIB
    else
        XERCESDIR=/usr/local/lib
    fi
elif [ "$ARCH" == "x86_64" ]
    then XERCESDIR=../../../binaries/wsp.lin_em64t
elif [ "$ARCH" == "x86_32" ]
    then XERCESDIR=../../../binaries/wsp.lin_x86
elif [ "$ARCH" == "s390x" ]
    then XERCESDIR=../../../binaries/wsp.lin_s390x
else echo "No Xerces library found, try to install one in a proper directory"
     exit 4
fi

LIB_FLAGS="-lrt -lxerces-c-3.1"

if [[ "$SYSTEM" == "FreeBSD" ]]; then
    LIB_FLAGS="$LIB_FLAGS -lkvm"
elif [[ "$SYSTEM" == "Linux" ]]; then
    LIB_FLAGS="$LIB_FLAGS -ldl"
fi

echo "$0: linking nbipgw20"
m_linking $LFLAGS nbipgw20.o \
    xsipgw08-conf.o xsclibrdp1.o \
    xstuntapif.o xshusip01.o xshsstp01.o xshsessutil01.o xshpppi01.o \
    xs-htcp-01.o xs-htcp-hdr-01.o xs-htcp-htun-01.o \
    xslunic1.o xslcontr.o xsavl03.o xslnetw1.o xs_nblock_acc.o nstcpco1.o xsl-tcp-sync-01.o xsl-ntlm-01.o \
    xs-gw-udp-01.o xs-gw-udp-gate-srtp.o xs-gw-l2tp.o xs-gw-ppp.o \
    xs-gw-radius-01.o xs-gw-cluster.o xs-gw-admin.o \
    xsl-stor-big-n.o xsltime1.o xsllog01.o xsregex01.o xs-encry-1.o xs-encry-2.o xs-ssl-1.o xs-cert-1.o $AES $ENCRY $ISLOCK $CAS xsl-http-header-1.o xs-gw-cma1-02.o \
    xs-lbal-win-1.o xsrerrm1.o \
    xs-gw-serv-vch-icap.o \
    xsldapco1.o \
    xs-gw-krb5-lib-interface.o xs-gw-krb5-lib.o xs-gw-krb5-control.o \
    -L$XERCESDIR $LIB_FLAGS \
    -o nbipgw20

        #$ISLOCK_2.o \
    
#strip the debug symbols after the linking, but save them in a separate file,
# which will not be delivered to the customer
#if [ $OPTIMIZATION == "-O2" ]
#    then objcopy --only-keep-debug nbipgw20 nbipgw20.debug
#         objcopy --strip-debug nbipgw20
#         objcopy --add-gnu-debuglink=nbipgw20.debug nbipgw20
#fi

#an alternative approach could be better, since we still have a fully executable file then
if [ "$OPTIMIZATION" == "-O2 -fno-strict-aliasing" ]
    then cp nbipgw20 nbipgw20.debug || exit 5
         strip --strip-debug nbipgw20 || exit 6
         objcopy --add-gnu-debuglink=nbipgw20.debug nbipgw20 || exit 7
fi

COMPILATION_END=`date +%s`
COMPILING_TIME=$(($COMPILATION_END - $COMPILATION_START))

case "$SYSTEM" in
    Linux)echo "Started compilation at $(date -d @$COMPILATION_START  +"%Y-%m-%d %H:%M:%S")"
          echo "Finished compilation at $(date -d @$COMPILATION_END +"%Y-%m-%d %H:%M:%S")"
          ;;
    FreeBSD)echo "Started compilation at $(date -r $COMPILATION_START  +"%Y-%m-%d %H:%M:%S")"
          echo "Finished compilation at $(date -r $COMPILATION_END +"%Y-%m-%d %H:%M:%S")"
          ;;
esac
echo "Compiling time: $COMPILING_TIME seconds"
echo "Success"
