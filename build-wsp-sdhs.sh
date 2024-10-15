#!/usr/bin/env bash

set -o pipefail

build_usage() {
    echo "Please enter your username for the subversion repository."
    echo "For building from the working copy, please use \"work\" as second argument"
    echo "Otherwise, use \"new\". Then RDVPN is built in the ~/wsp-sdhs-release directory."
    echo "Third argument could be trunk (default) or a special branch."
    echo "Optionally, you can also enter the revision number as a fourth argument."
}

if [ $# -lt 2 ]
  then build_usage
  exit 1
fi

if [ "$2" == "new" ] 
    then
    # handle case of existing dir wsp-sdhs-release
    if [ -d ~/wsp-sdhs-release ]
        then echo "The wsp-sdhs-release directory already exists. Please move or delete it."
        exit 2
    fi

    mkdir ~/wsp-sdhs-release && cd ~/wsp-sdhs-release

    if [ -z $3 ]; then BRANCH=trunk; else BRANCH=$3; fi
    #read Subversion password silent
    echo -n "Please enter your subversion password: "
    #read -s is unfortunately not POSIX compliant
    stty -echo
    read PASSWORD
    stty echo
    echo
    if [ -z $4 ]; then REV_PAR="head"; else REV_PAR=$4; fi
    # TODO: variable for build branch: either trunk or branches/RDVPN-2.2-2, etc.
    svn checkout --username $1 --password $PASSWORD -r $REV_PAR --depth empty "https://linux02.hob.de/repos/RDVPN_2/$BRANCH"
    cd $BRANCH
    REVISION=$(svnversion | tr -dc '0-9')
    svn update --username $1 --password $PASSWORD -r $REVISION --set-depth infinity wsp-sdhs
    svn update --username $1 --password $PASSWORD -r $REVISION --set-depth infinity binaries
    svn update --username $1 --password $PASSWORD -r $REVISION --set-depth infinity build-output
elif [ "$2" == "work" ] 
    then echo "Building from the working copy"
    cd ..
    REVISION=$(svnversion | tr -dc '0-9')
else build_usage
fi

TODAY=`date +'%b %d %Y'`
OLD_VERSION=`tail -n 1  binaries/wsp.lin_em64t/plugins/client-config/version.txt | awk -F "." '{print $NF}' `
SYSTEM=$(uname -s)

cd wsp-sdhs || exit 1
./update-version-headers.sh || exit 1

echo "#Build: compile SDHs"
cd src
case "$SYSTEM" in
    Linux)sys=lin
        make PLATFORM=LinX64 2>&1 | tee ../build-logs/build.log.lin_em64t
        if [ $? -ne 0 ]; then
            echo "Unable to compile the server data hooks"
        exit 3
        fi

        make PLATFORM=LinX86 2>&1 | tee ../build-logs/build.log.lin_x86
        ;;
    FreeBSD)sys=bsd
        gmake PLATFORM=BsdX64 2>&1 | tee ../build-logs/build.log.bsd_em64t
            if [ $? -ne 0 ]; then
            echo "Unable to compile the server data hooks"
            exit 3
            fi
            ;;
esac
echo "#Build: copy SDHs"
cd .. || exit 1
./copy.sh || exit 1
echo "#Build: compile WebSecureProxy and ListenGateWay"
cd src/wsp || exit 1
chmod +x comp-wsp.sh || exit 1
chmod +x comp-lgw.sh || exit 1
#compile 64-bit release
echo "#Build: comp-wsp.sh"
./comp-wsp.sh 2>&1 | tee build_wsp-$sys.log || exit 1

if [ $? -ne 0 ]; then
    echo "Unable to compile web secure proxy"
    exit 4
fi

echo "#Build: comp-lgw.sh"
./comp-lgw.sh 2>&1 | tee build_lgw-$sys.log || exit 1

if [ $? -ne 0 ]; then
    echo "Unable to compile listen gateway"
    exit 5
fi

echo "#Build: copy executables"
mkdir -p "$sys"64 || exit 1
mv -v nbipgw?? nbipgw??.debug build_* "$sys"64/ || exit 1
if [ "$SYSTEM" == "Linux" ]
    then
        #compile 32-bit release
        ./comp-wsp.sh -x32 2>&1 | tee build_wsp-lin32.log
        ./comp-lgw.sh -x32 2>&1 | tee build_lgw-lin32.log

        #copy executables
        mkdir -p lin32
        mv -v nbipgw?? nbipgw??.debug build_* lin32/
fi
#compile 64-bit debug
echo "#Build: comp-wsp.sh debug"
./comp-wsp.sh --debug 2>&1 | tee build_wsp-$sys-dbg.log || exit 1
echo "#Build: comp-lgw.sh debug"
./comp-lgw.sh --debug 2>&1 | tee build_lgw-$sys-dbg.log || exit 1
mkdir -p "$sys"64dbg || exit 1
mv -v nbipgw?? build_* "$sys"64dbg/ || exit 1

echo "#Build: delete object files"
rm *.o

cd ../../.. || exit 1

echo "#Build: copy WSPs"
cd binaries/wsp."$sys"_em64t || exit 1
cp -pv ../../wsp-sdhs/src/wsp/"$sys"64/nbipgw20 . || exit 1
cp -pv ../../wsp-sdhs/src/wsp/"$sys"64/nbipgw19 . || exit 1

if [[ "$SYSTEM" == "Linux" ]]; then
    echo "#Build: change version.txt.wsp"
    sed -i "s/VERSION=Version 2\.3.*/VERSION=Version 2.3 $TODAY/g" version.txt.wsp || exit 1

    echo "#Build: extract ./plugins/client-config/version.txt"
    #VERSION=2.3.203.7564
    grep -rl $OLD_VERSION . | xargs sed -i "s/VERSION=2.3.203.*/VERSION=2.3.203.$REVISION/g" || exit 1

    cd ../wsp.lin_x86 || exit 1
    cp -pv ../../wsp-sdhs/src/wsp/lin32/nbipgw20 . || exit 1
    cp -pv ../../wsp-sdhs/src/wsp/lin32/nbipgw19 . || exit 1
    sed -i "s/VERSION=Version 2\.3.*/VERSION=Version 2.3 $TODAY/g" version.txt.wsp || exit 1
    grep -rl $OLD_VERSION . | xargs sed -i "s/VERSION=2.3.204.*/VERSION=2.3.204.$REVISION/g" || exit 1

    echo "#Build: change RDVPN_Component_Info in build-output/DVD"
    cd ../../build-output || exit 1
    find -iname "RDVPN_Component_Info.txt" | xargs sed -i "s/$OLD_VERSION/$REVISION/g" || exit 1
fi
#TODO: add other architectures if needed
echo "$0 Success"
exit 0
