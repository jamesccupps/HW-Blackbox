@echo off
rem Install (or update) HW Blackbox: asks for admin rights, runs install.ps1 from this folder, shows its report.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','\"%~dp0install.ps1\"'"
if exist "%TEMP%\hwblackbox-install.txt" type "%TEMP%\hwblackbox-install.txt"
echo.
pause
