@echo off
rem Remove HW Blackbox (the service, the agent's task, the program, the shortcut, its Installed apps entry). The data in
rem %ProgramData%\HWBlackbox stays; to delete it too, run: install.ps1 -Uninstall -RemoveData (elevated).
rem Settings -> Apps -> Installed apps -> HW Blackbox -> Uninstall does the same.
rem All of it is one block, read before any of it runs, and it leaves the program's folder first: run from
rem C:\Program Files\HWBlackbox, this file is removed while it runs. "(goto)" ends it without reading the file again.
(
  cd /d "%SystemRoot%"
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
  (goto) 2>nul
)
