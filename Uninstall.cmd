@echo off
rem Remove HW Blackbox (the service, the agent's task, the program, the shortcut). The data in
rem %ProgramData%\HWBlackbox stays; to delete it too, run: install.ps1 -Uninstall -RemoveData (elevated).
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','\"%~dp0install.ps1\"','-Uninstall'"
if exist "%TEMP%\hwblackbox-install.txt" type "%TEMP%\hwblackbox-install.txt"
echo.
pause
