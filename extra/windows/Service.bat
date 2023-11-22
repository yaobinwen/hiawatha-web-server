@ECHO OFF

SET INSTALL_DIR=%~dp0
SET CYGWIN=nodosfilewarning

WHOAMI /groups | FINDSTR Administrators | FINDSTR /c:"Enabled group" > NUL && GOTO MAIN
ECHO You need to have Administrator rights to do this.
GOTO END

SET /p task="[I]nstall or [U]ninstall Hiawatha as a Windows service? "
ECHO.
IF /i %task% == i GOTO INSTALL
IF /i %task% == u GOTO UNINSTALL
ECHO Invalid option.
GOTO END

:INSTALL
ECHO Installing Hiawatha as a Windows service...
"%INSTALL_DIR%program\cygrunsrv.exe" -I hiawatha -d "Hiawatha webserver" -f "Secure and advanced webserver" -p "%INSTALL_DIR%program\hiawatha.exe" -a "-d -c '%INSTALL_DIR%config'"
GOTO END

:UNINSTALL
ECHO Uninstalling Hiawatha as a Windows service...
"%INSTALL_DIR%program\cygrunsrv.exe" -R hiawatha

:END
ECHO.
PAUSE
