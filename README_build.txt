These are preliminary build instructions.  This will be turned into a
script, soon.


#Before building the SDHs, update all "sdh-version.h" headers to the
#current Subversion revision with the update-version-headers.sh script with Cygwin
#or on any Unix system to get the correct version information into the SDHs.
Newer Windows Systems(up from Windows 10's Anniversary Update) are able to execute bash scripts.
This step is also done by the powershell Change-Version-Number-SVN function.

cd wsp-sdhs
update-version-headers.sh


Windows
=======
For a succesful build, the Xerces directory is needed, for now we use files from D:\Xerces\xerces-c-3.1.0

especially

xerces\windows\include\xercesc is D:\Xerces\xerces-c-3.1.0\src\xercesc 
xerces\windows\lib64 is D:\Xerces\xerces-c-3.1.0\Build\windows\em64t\VC8\Release
xerces\windows\lib32 is D:\Xerces\xerces-c-3.1.0\Build\windows\x86\VC8\Release"

one could also link to any other Xerces directory $xerces_dir with corresponding structure. 
Default option is xerces\windows

#In Powershell without signing:
.\build-wsp-sdhs.ps1 -signing $false ($xerces_dir=<path>)
#with signing(default option)
.\build-wsp-sdhs.ps1 -signing $true ($xerces_dir=<path>)

=========

#if you want to do it manually:

cd wsp-sdhs\src\wsp

# create rc:
DO-GEN-RC-IBIPGW08.bat

# manually build WSP in Visual Studio 2012 (or create a MSBuild script); solution ibipgw08.sln

# sign WSP
DO-SIGN-IBIPGW08.bat <pw>
# or better 
..\..\sign-single.ps1 "ibipgw08-r-x86\ibipgw08.exe" "ibipgw08-r-EM64T\ibipgw08.exe"


#copy WSP
copy ibipgw08-r-x86\ibipgw08.exe ..\..\..\binaries\wsp.win_x86\ /Y
copy ibipgw08-r-EM64T\ibipgw08.exe ..\..\..\binaries\wsp.win_em64t\ /Y


# build, sign, copy SDHs
cd ..
build-win.ps1

#then sign and copy build libraries into ..\..\binaries\wsp.win_x86\ and ..\..\binaries\wsp.win_em64t

#check results
# build-logs\build.log.win_x86 
# build-logs\build.log.win_em64t


Linux
=====


* currently built from hobrc-51

# mount working copy from hobc03k
export MNT=/home/HOB01/finkml/mnt/ke
su -c "mount -t cifs -o username=finkml,dom=HOB01,uid=10025,gid=10010 //hobc03k.hob.de/DISK_E $MNT"
cd $MNT/finkml/projects/RDVPN_2/branch-2.2-2

./build-wsp-sdhs.sh 
#read the usage and complete the arguments accordingly, for example
./build-wsp-sdhs.sh drabkimm work

======

#manually:

# compile SDHs
cd wsp-sdhs/src
make PLATFORM=LinX64 > ../build-logs/build.log.lin_em64t 2>&1
make PLATFORM=LinX86 > ../build-logs/build.log.lin_x86 2>&1

#check results
# ../build-logs/build.log.lin_x86
# ../build-logs/build.log.lin_em64t

# copy SDHs
cd ..
./copy.sh

# compile WSPs
cd src/wsp
#compile 64-bit release
./comp-wsp.sh > build_wsp-lin.log 2>&1
./comp-lgw.sh > build_lgw-lin.log 2>&1

#check results
# build_wsp-lin.log
# build_lgw-lin.log

#copy executables
mkdir lin64
mv nbipgw?? nbipgw??.debug build_* lin64/

#compile 32-bit release
./comp-wsp.sh -x32 > build_wsp-lin32.log 2>&1
./comp-lgw.sh -x32 > build_lgw-lin32.log 2>&1

#check results
# build_wsp-lin32.log
# build_lgw-lin32.log

#copy executables
mkdir lin32
mv nbipgw?? nbipgw??.debug build_* lin32/

#compile 64-bit debug
./comp-wsp.sh --debug > build_wsp-lin-dbg.log 2>&1
./comp-lgw.sh --debug > build_lgw-lin-dbg.log 2>&1
mkdir lin64dbg
mv nbipgw?? build_* lin64dbg/

#delete object files
rm *.o

cd ../../..

# copy WSPs
cd binaries/wsp.lin_em64t
cp -pv ../../wsp-sdhs/src/wsp/lin64/nbipgw20 .
cp -pv ../../wsp-sdhs/src/wsp/lin64/nbipgw19 .
# change version.txt.wsp

cd ../wsp.lin_x86
cp -pv ../../wsp-sdhs/src/wsp/lin32/nbipgw20 .
cp -pv ../../wsp-sdhs/src/wsp/lin32/nbipgw19 .
# change version.txt.wsp

#update version.txt files in subfolders of binaries folder



FreeBSD
=======

* currently built from hobos-bsd-40

# mount working copy from hobc03k
export MNT=/home/HOB01/finkml/mnt/ke
sudo mount_smbfs -I hobc03k.hob.de -U finkml -W HOB01 //hobc03k/DISK_E $MNT
cd $MNT/finkml/projects/RDVPN_2/branch-2.2-2

#same procedure as on Linux

# compile SDHs
cd wsp-sdhs/src
gmake PLATFORM=BsdX64 > ../build-logs/build.log.bsd_em64t 2>&1

#check results
# ../build-logs/build.log.bsd_em64t

# copy SDHs
cd ..
./copy.sh

# compile WSPs
cd src/wsp
./comp-wsp.sh > build_wsp-bsd.log 2>&1
./comp-lgw.sh > build_lgw-bsd.log 2>&1

#check results
# build_wsp-bsd.log
# build_lgw-bsd.log

mkdir bsd64
mv nbipgw?? nbipgw??.debug build_* bsd64/

./comp-wsp.sh --debug > build_wsp-bsd-dbg.log 2>&1
./comp-lgw.sh --debug > build_lgw-bsd-dbg.log 2>&1
mkdir bsd64dbg
mv nbipgw?? build_* bsd64dbg/

rm *.o

cd ../../..

# copy WSPs
cd binaries/wsp.bsd_em64t
cp -pv ../../wsp-sdhs/src/wsp/bsd64/nbipgw20 .
cp -pv ../../wsp-sdhs/src/wsp/bsd64/nbipgw19 .
