@echo off
rem Install (or update) HW Blackbox: asks for admin rights, runs install.ps1 from this folder, shows its report.
if exist "%TEMP%\hwblackbox-install.txt" del "%TEMP%\hwblackbox-install.txt"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','\"%~dp0install.ps1\"'" 2>nul
if exist "%TEMP%\hwblackbox-install.txt" (
  type "%TEMP%\hwblackbox-install.txt"
) else (
  echo.
  echo HW Blackbox was not installed: it needs admin rights, and Windows didn't get them.
  echo Run this again and choose Yes when Windows asks.
)
echo.
pause
