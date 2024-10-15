@echo off

REM In order for this batch file to work, devcon.exe needs to be available in the PATH or current directory.
REM If the folder structure is modified, modify the 3rd parameter accordingly.

devcon -r remove hobtun.inf hobtun

pause