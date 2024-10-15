rem ..\..\external\gmake-3.81\bin\windows\x86\gmake.exe WinUpdate > update.log
rem "C:\Program Files (x86)\Notepad++\notepad++.exe" update.log

..\..\external\precomp\bin\windows\x86\precomp.exe xslstor1.pre xsl-stor-big-n.cpp %%SET:D_BIG_STOR=1;
..\..\external\precomp\bin\windows\x86\precomp.exe xslstor1.pre ..\lib_sdhstorage\src\xsl-stor-sdh.cpp %%SET:DSDHBIG1=1;

rem "C:\Program Files (x86)\Araxis Merge 2007\Merge.exe" .\src .\src_bac
rem "C:\Program Files (x86)\Araxis Merge 2007\Merge.exe" .\include .\include_bac