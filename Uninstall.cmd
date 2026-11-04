@echo off
rem Remove HW Blackbox (the service, the agent's task, the program, the shortcut). The data in
rem %ProgramData%\HWBlackbox stays; to delete it too, run: install.ps1 -Uninstall -RemoveData (elevated).
if exist "%TEMP%\hwblackbox-install.txt" del "%TEMP%\hwblackbox-install.txt"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','\"%~dp0install.ps1\"','-Uninstall'" 2>nul
if exist "%TEMP%\hwblackbox-install.txt" (
  type "%TEMP%\hwblackbox-install.txt"
) else (
  echo.
  echo HW Blackbox was not removed: it needs admin rights, and Windows didn't get them.
  echo Run this again and choose Yes when Windows asks.
)
echo.
pause
