@echo off
rem Remove HW Blackbox (the service, the agent's task, the program, the shortcut, its Installed apps entry). The data in
rem %ProgramData%\HWBlackbox stays; to delete it too, run: install.ps1 -Uninstall -RemoveData (elevated).
rem Settings -> Apps -> Installed apps -> HW Blackbox -> Uninstall does the same.
rem install.ps1 asks Windows for an admin itself, and that window shows how it went (-Pause). (Until 1.1.3 this
rem read the report from the user's TEMP folder, where the installer wrote it as an admin.)
rem All of it is one block, read before any of it runs, and it leaves the program's folder first: run from
rem C:\Program Files\HWBlackbox, this file is removed while it runs. "(goto)" ends it without reading the file again.
(
  cd /d "%SystemRoot%"
  "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" -Uninstall -Pause
  (goto) 2>nul
)
