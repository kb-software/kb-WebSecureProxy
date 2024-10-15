@echo off
rem Note: sourcepath and targetpath have to be also set in library.pl;
rem script has to be executed from its own directory.

set BASEDIR=%CD%
set sourcepath=..\..\binaries\www
set targetpath=www
set OS_ARCH_ED=win_em64t_blue

set JWT_CHECKOUT=D:\entwtech\installer\jwt41\release
set JWT_HELP=D:\entwtech\installer\jwt41\adds\Help\Online_Help
rem svn checkout https://linux02.hob.de/repos/Helps/HOBLink_JWT/HOBLink_JWT_4.1/Online_Help jwt41_help


echo Creating release www folder in %BASEDIR%\%targetpath%
echo.
echo Copying necessary folders and files...
perl ..\..\installer\build\prepare-environment.pl log.txt %OS_ARCH_ED%

if errorlevel 1 (
   echo Failure in prepare-environment.pl - exit code %errorlevel%.
   echo This could be caused by an open Explorer window which prevents deleting an existing www folder.
   exit /b %errorlevel%
)

set CURDIR=%CD%

rem Skip WSG for NetAccess edition
rem (check if OS_ARCH_ED does not change after replacing all occurrances of "red" by a empty string)
if "%OS_ARCH_ED%"=="%OS_ARCH_ED:net=%" set isNotNetAccess=1
if defined isNotNetAccess (
   echo Preparing Web Server Gate release file HOBwsg.js...
   cd ..\..\installer\prepare_wsg
   call HOBwsg_rebuild_obfuscator.bat %BASEDIR%\%sourcepath%\protected\wsg.dev %BASEDIR%\%targetpath%\protected\wsg
   cd %CURDIR%
) else (
   echo Skipping HOBwsg.js, NetAccess edition does not include it.
)


rem Include JWT only for Blue or Red edition

rem is edition blue?
if not "%OS_ARCH_ED%"=="%OS_ARCH_ED:blue=%" set includeJWT=1
rem is edition red?
if not "%OS_ARCH_ED%"=="%OS_ARCH_ED:red=%" set includeJWT=1

if defined includeJWT (
   echo Create hotfix archive for JWT 4.1...
   rem (from installer/make_jwt_sa.bat)

   mkdir %targetpath%\public\lib\lib
   mkdir %targetpath%\public\lib\lib\addwebres\resources
   mkdir %targetpath%\public\lib\lib\keyboard
   mkdir %targetpath%\public\lib\lib\x11keyboard
   mkdir %targetpath%\public\lib\configs
   mkdir %targetpath%\public\lib\globalconfig
   mkdir %targetpath%\public\lib\help
   
   xcopy /y /q %JWT_CHECKOUT%\build\ssl\jwtwebJ2.jar                  %targetpath%\public\lib\lib\jwtjws.*
   xcopy /y /q %JWT_CHECKOUT%\build\ssl\jwtwebJ2.jar.pack.gz          %targetpath%\public\lib\lib\jwtjws.jar.pack.*
   xcopy /y /q %JWT_CHECKOUT%\build\www\lib\shellb.png                %targetpath%\public\lib\lib\
   xcopy /y /q %JWT_CHECKOUT%\build\www\lib\shells.png                %targetpath%\public\lib\lib\
   xcopy /y /q %JWT_CHECKOUT%\build\www\lib\addwebres\hob.xml         %targetpath%\public\lib\lib\addwebres\
   xcopy /y /q %JWT_CHECKOUT%\build\www\lib\addwebres\resources\*.jar %targetpath%\public\lib\lib\addwebres\resources\
   xcopy /y /q %JWT_CHECKOUT%\build\www\lib\keyboard\*                %targetpath%\public\lib\lib\keyboard\
   xcopy /y /q %JWT_CHECKOUT%\build\www\lib\x11keyboard\*             %targetpath%\public\lib\lib\x11keyboard\
   xcopy /y /q %JWT_CHECKOUT%\build\www\configs\default.xml           %targetpath%\public\lib\configs\
   xcopy /y /q %JWT_CHECKOUT%\build\templates\default.cdb             %targetpath%\public\lib\globalconfig\
   xcopy /y /q %JWT_CHECKOUT%\build\templates\default.cfg             %targetpath%\public\lib\globalconfig\
   xcopy /y /q %JWT_CHECKOUT%\build\templates\default.pwd             %targetpath%\public\lib\globalconfig\
   xcopy /y /q %JWT_CHECKOUT%\build\www\globalconfig\default.xml      %targetpath%\public\lib\globalconfig\
   xcopy /s /y /q "%JWT_HELP%\*"                                      %targetpath%\public\lib\help
) else (
   echo Skipping JWT 4.1, edition not Blue or Red.
)

echo Copying additional files from jwt41_release checkout...
rem (from installer/copy_jwt_files.bat)

xcopy /y /s /q %JWT_CHECKOUT%\build\native              %targetpath%\public\lib\hob\dlls\native\
xcopy /y /s /q %JWT_CHECKOUT%\build\www\lib\addwebres   %targetpath%\public\lib\hob\dlls\addwebres\
xcopy /y /s /q %JWT_CHECKOUT%\build\www\lib\keyboard    %targetpath%\public\lib\hob\hltc\keyboard\
xcopy /y /s /q %JWT_CHECKOUT%\build\www\lib\x11keyboard %targetpath%\public\lib\hob\hltc\x11keyboard\


echo Write version information into versionRDVPN.js...
rem (from https://stackoverflow.com/questions/23087463/batch-script-to-find-and-replace-a-string-in-text-file-within-a-minute-for-files)

setlocal
call :FindReplace "$VERSION_MAJ$"     "2"    %targetpath%\protected\js\versionRDVPN.js
call :FindReplace "$VERSION_MIN$"     "3"    %targetpath%\protected\js\versionRDVPN.js
call :FindReplace "$VERSION_REL$"     "1"    %targetpath%\protected\js\versionRDVPN.js
call :FindReplace "$SUBVERSION_NR$"   "7502" %targetpath%\protected\js\versionRDVPN.js
call :FindReplace "$VERSION_EDITION$" "blue edition" %targetpath%\protected\js\versionRDVPN.js
call :FindReplace "$OS_INSTALLED$"    "win"  %targetpath%\protected\js\versionRDVPN.js

exit /b

:FindReplace <findstr> <replstr> <file>
set tmp="%temp%\tmp.txt"
If not exist %temp%\_.vbs call :MakeReplace
for /f "tokens=*" %%a in ('dir "%3" /s /b /a-d /on') do (
  for /f "usebackq" %%b in (`Findstr /mic:"%~1" "%%a"`) do (
    echo(&Echo Replacing "%~1" with "%~2" in file %%~nxa
    <%%a cscript //nologo %temp%\_.vbs "%~1" "%~2">%tmp%
    if exist %tmp% move /Y %tmp% "%%~dpnxa">nul
  )
)
del %temp%\_.vbs
exit /b

:MakeReplace
>%temp%\_.vbs echo with Wscript
>>%temp%\_.vbs echo set args=.arguments
>>%temp%\_.vbs echo .StdOut.Write _
>>%temp%\_.vbs echo Replace(.StdIn.ReadAll,args(0),args(1),1,-1,1)
>>%temp%\_.vbs echo end with
