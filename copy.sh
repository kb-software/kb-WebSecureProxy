#!/usr/bin/env bash

# Copy all WSP/SDH binaries on Linux and BSD
# from wsp-sdhs/bin/.. to binaries/wsp.*.
# No parameters needed.

SYSTEM=$(uname -s | tr "[:upper:]" "[:lower:]")

# copy of x86 binaries is deprecated and should be removed someday
# this will probably make the ARCH variable and the corresponding for loop obsolete
case "$SYSTEM" in
    linux)
        SYS=lin
        ARCH=( "em64t" "x86" )
        ;;
    freebsd)
        SYS=bsd
        ARCH="em64t"
        ;;
esac

for bits in "${ARCH[@]}"; 
do TARGET=../binaries/wsp."$SYS"_"$bits"
    for file in $(ls bin/release/$SYSTEM/$bits/plugins/*/*.so);
    do DIR=$(basename $(dirname $file))
        if [ -d $TARGET/plugins/$DIR ]
            then cp -pv $file $TARGET/plugins/$DIR/ || exit 1
            else cp -pv $file $TARGET/plugins/$DIR.*/ || exit 2
        fi ;
    done
done
exit 0
