IF "%1" == "" goto LBL_INPUTERR
"C:\Program Files (x86)\Windows Kits\8.0\bin\x86\signtool" sign /q /f D:\projects\Tools\certificate\MS_IE\cs-0619.pfx /d "HOB Software" /p %1 /du "http://www.hobsoft.com" /t "http://timestamp.verisign.com/scripts/timstamp.dll" ibipgw08-r-x86\ibipgw08.exe
"C:\Program Files (x86)\Windows Kits\8.0\bin\x86\signtool" sign /q /f D:\projects\Tools\certificate\MS_IE\cs-0619.pfx /d "HOB Software" /p %1 /du "http://www.hobsoft.com" /t "http://timestamp.verisign.com/scripts/timstamp.dll" ibipgw08-r-EM64T\ibipgw08.exe
goto :EOF

:LBL_INPUTERR
echo Please enter certificate password as parameter!
