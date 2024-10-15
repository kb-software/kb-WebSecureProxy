#!/usr/bin/env bash

. ./functions.sh

COMPILATION_START=`date +%s`

DEBUG="-g"

#Define whether we are on FreeBSD or on Linux
SYSTEM=$(uname -s)

#Define system architecture
ARCH=$(uname -m)

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

#is pthread optional?
#we should add -Wall some day
CFLAGS="-c -fsigned-char $OPTIMIZATION $DEBUG -m$BIT -pthread -I. -DHL_UNIX -DD_INCL_HOB_TUN -DXH_INTERFACE"

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

m_compile nbipgw19.cpp
m_compile xsavl03.cpp
m_compile nsl-tcpcomp-singthr.cpp

################
# SSL routines #
################

#for the compilation of the encry file by clang we should switch off the optimization
# TODO: add comment/explanation -> ask Crypto team
if [ "$SYSTEM" == "FreeBSD" ]
    then DEOPTIMIZE="-O0"
fi

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

m_linking $SSL_CFLAGS $DEOPTIMIZE xs-encry-1.cpp
m_linking $SSL_CFLAGS xs-encry-2.cpp
m_linking $SSL_CFLAGS xs-ssl-1.cpp
m_linking $SSL_CFLAGS xs-cert-1.cpp

LIB_FLAGS="-lrt"

echo "$0: linking nbipgw19"
m_linking $LFLAGS nbipgw19.o xsavl03.cpp xslunic1.o nsl-tcpcomp-singthr.o \
          xs-encry-1.o xs-encry-2.o xs-ssl-1.o xs-cert-1.o $AES $ENCRY $CAS $ISLOCK $LIB_FLAGS -o nbipgw19 
        
#strip the debug symbols after the linking, but save them in a separate file,
# which will not be delivered to the customer
#if [ $OPTIMIZATION == "-O2" ]
#    then objcopy --only-keep-debug nbipgw19 nbipgw19.debug
#         objcopy --strip-debug nbipgw19
#         objcopy --add-gnu-debuglink=nbipgw19.debug nbipgw19
#fi

#an alternative approach could be better, since we still have a fully executable file then
if [ "$OPTIMIZATION" == "-O2 -fno-strict-aliasing" ]
    then cp nbipgw19 nbipgw19.debug || m_echo_and_exit "Copy failed" 4
         strip --strip-debug nbipgw19 || m_echo_and_exit "Strip failed" 5
         objcopy --add-gnu-debuglink=nbipgw19.debug nbipgw19  || m_echo_and_exit "Objcopy failed" 6
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