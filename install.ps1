<#
.SYNOPSIS
  Install, update or remove HW Blackbox. Run it in an elevated PowerShell, from the release folder (python\, app\),
  or double-click Install.cmd / Uninstall.cmd there, which ask for admin rights themselves.

.DESCRIPTION
  .\install.ps1                         install, or update an installed one (settings and history are kept)
  .\install.ps1 -Uninstall              remove the service, the agent's task, the program and the shortcut;
                                        the data (logs, reports, settings) stays in %ProgramData%\HWBlackbox
  .\install.ps1 -Uninstall -RemoveData  ...and delete the data too
  -Set "k=v", ...                       settings for a first install's config.json (dashboard.port=9071)
  -NoStart                              install, but start nothing
  -PawnIO ask|yes|no                    when the PawnIO driver (the CPU and board sensors) is missing: ask (the
                                        default; with nobody to answer, it's left out), install it with winget, or
                                        leave it out
  -Pause                                at the end, keep the window open 15 seconds (or until a key): for Settings ->
                                        Apps -> Installed apps, whose Uninstall runs this

  HW Blackbox is listed in Settings -> Apps -> Installed apps; its Uninstall runs this script from the program's folder
  with -Uninstall -Pause. Unelevated, -Uninstall asks Windows for an admin itself (for this same script, in Program
  Files, which only admins can change).

  What it puts where:
  C:\Program Files\HWBlackbox     the program, with a Python of its own (only admins can change it: the service
                                  runs as SYSTEM)
  C:\ProgramData\HWBlackbox       the data: SYSTEM and admins write, everyone reads; each user's session agent
                                  writes in sessions\<user>; secrets\ is for SYSTEM and admins only
  the service "HWBlackbox"        LocalSystem, automatic start, restarted by Windows if it fails
  the task "HWBlackboxAgent"      at every sign-in, as that user, not elevated: the session agent
  Start menu: "HW Blackbox"       opens the dashboard
#>
param(
  [switch]$Uninstall,
  [switch]$RemoveData,
  [string[]]$Set,
  [switch]$NoStart,
  [string]$Report,
  [ValidateSet('ask', 'yes', 'no')][string]$PawnIO = 'ask',
  [switch]$Pause
)
$ErrorActionPreference = 'Stop'
# Windows' QuickEdit: a click in a console window starts selecting text, and while it selects, whatever writes to the
# window waits. 2026-11-06: an update's window sat at "== 9. Check" (its title "Select ...") until it was closed. Off
# for this window, so a click can't hold the install up.
try {
  Add-Type -Namespace HWB -Name Console -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern IntPtr GetStdHandle(int n);
[DllImport("kernel32.dll")] public static extern bool GetConsoleMode(IntPtr h, out uint m);
[DllImport("kernel32.dll")] public static extern bool SetConsoleMode(IntPtr h, uint m);
'@
  $conIn = [HWB.Console]::GetStdHandle(-10)
  $conMode = [uint32]0
  if ([HWB.Console]::GetConsoleMode($conIn, [ref]$conMode)) {
    $conMode = $conMode -bor 0x80                                  # ENABLE_EXTENDED_FLAGS (needed to change QuickEdit)
    if ($conMode -band 0x40) { $conMode -= 0x40 }                 # ENABLE_QUICK_EDIT_MODE off
    [void][HWB.Console]::SetConsoleMode($conIn, [uint32]$conMode)
  }
} catch { }
$Service = 'HWBlackbox'
$TaskName = 'HWBlackboxAgent'
$Dest = Join-Path $env:ProgramFiles 'HWBlackbox'
$Data = Join-Path $env:ProgramData 'HWBlackbox'
$Py = Join-Path $Dest 'python\pythonw.exe'
$PyCon = Join-Path $Dest 'python\python.exe'
$StartMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\HW Blackbox.lnk'
$AppsKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\HWBlackbox'     # (Installed apps' entry)
if (-not $Report) { $Report = Join-Path $env:TEMP 'hwblackbox-install.txt' }
$script:failed = @()
$script:warned = @()

function Warn($m) { $script:warned += $m; Say "WARNING: $m" }
# HW Blackbox's own commands, their output (stdout and stderr) into the report. (Windows PowerShell turns a native
# program's stderr into errors, which 'Stop' would make fatal: so not here.)
function Run-Hwb([string[]]$a) {
  $old = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try { & $PyCon -m hwblackbox @a 2>&1 | ForEach-Object { Say "  $_" } } finally { $ErrorActionPreference = $old }
}
function Say($m) {
  $line = '{0}  {1}' -f (Get-Date -Format 'HH:mm:ss'), $m
  $line | Out-File $Report -Append -Encoding utf8
  Write-Host $line
}
function Fail($m) { $script:failed += $m; Say "FAILED: $m" }
# -Pause: the window stays a while at the end, so whoever started it (Installed apps' Uninstall) sees how it went:
# 15 seconds, or until a key; with warnings or failures, 2 minutes.
function Wait-End {
  if (-not $Pause) { return }
  try {
    if (-not [Environment]::UserInteractive -or [Console]::IsInputRedirected) { return }
    $long = $script:warned -or $script:failed
    Write-Host ''
    Write-Host $(if ($long) { 'Press a key to close this window.' } else { 'This window closes in 15 seconds, or press a key.' })
    $until = (Get-Date).AddSeconds($(if ($long) { 120 } else { 15 }))
    while ((Get-Date) -lt $until -and -not [Console]::KeyAvailable) { Start-Sleep -Milliseconds 100 }
  } catch { }
}

function Stop-HWBlackbox {
  $svc = Get-Service -Name $Service -ErrorAction SilentlyContinue
  if ($svc -and $svc.Status -ne 'Stopped') {
    Say 'stopping the service'
    try { Stop-Service -Name $Service -Force -ErrorAction Stop } catch { Say "  stop: $($_.Exception.Message)" }
    $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
  }
  # whatever still runs from the program folder: the session agents, an "open" window's server
  Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($Dest + '\', [StringComparison]::OrdinalIgnoreCase) } |
    ForEach-Object { Say "  ending pid $($_.ProcessId) ($($_.CommandLine))"; Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

# The data folder. The service writes there as SYSTEM, so nobody else may own it or the folders in it, and none of them
# may be a link to somewhere else: someone who could do either could make SYSTEM write or delete any file. It's made
# with its owner and permissions final before anything goes in it (SYSTEM and admins: everything; users: read). A
# folder someone else made first, or a link, is moved aside, never used.
# (the attributes of the path itself, not of where a link points: $null when there's nothing there, even a link to
# something gone, which Test-Path calls missing)
function Get-OwnAttributes([string]$Path) { try { [IO.File]::GetAttributes($Path) } catch { $null } }
function Test-TrustedFolder([string]$Path, [string[]]$Owners) {
  $a = Get-OwnAttributes $Path
  if (($a -band [IO.FileAttributes]::ReparsePoint) -or -not ($a -band [IO.FileAttributes]::Directory)) { return $false }
  return $Owners -contains (Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value
}
function Initialize-DataFolder([string]$Root) {
  # who may own them: SYSTEM, Administrators, TrustedInstaller, or an admin's own account (where a policy gives an
  # admin's new folders to the admin instead of the Administrators group)
  $owners = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
  try { $owners += @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { $_.SID.Value }) }
  catch { Say "  (the Administrators group's members can't be listed: $($_.Exception.Message))" }
  $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  $aside = {
    param($p)
    try { Rename-Item -LiteralPath $p -NewName ("{0}.untrusted-{1}" -f (Split-Path $p -Leaf), $stamp) }
    catch { Say "$p was made by someone else, or is a link, and can't be moved aside: $($_.Exception.Message)"; exit 1 }
    Warn "$p was made by someone other than SYSTEM or an admin, or is a link to somewhere else: moved aside to $p.untrusted-$stamp"
  }
  if ((Get-OwnAttributes $Root) -and -not (Test-TrustedFolder $Root $owners)) { & $aside $Root }
  $sec = New-Object Security.AccessControl.DirectorySecurity
  $sec.SetSecurityDescriptorSddlForm('O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)',
                                     'Owner, Group, Access')
  if (-not (Get-OwnAttributes $Root)) { [void][IO.Directory]::CreateDirectory($Root, $sec) }
  $kids = 'logs', 'state', 'incidents', 'sessions', 'secrets'
  foreach ($d in $kids) {
    $p = Join-Path $Root $d
    if ((Get-OwnAttributes $p) -and -not (Test-TrustedFolder $p $owners)) { & $aside $p }
  }
  # (only now, with nothing but trusted folders in it, since setting these passes them down to what's inside: for
  # one that was there, the owner, and no grants but these)
  Set-Acl -LiteralPath $Root -AclObject $sec
  foreach ($d in $kids) {
    $p = Join-Path $Root $d
    if (-not (Get-OwnAttributes $p)) { [void](New-Item -ItemType Directory -Path $p) }
  }
  # sessions\: each user's session agent makes a folder of its own there (and owns it). secrets\: SYSTEM and admins.
  & icacls.exe (Join-Path $Root 'sessions') /grant '*S-1-5-32-545:(AD)' '*S-1-3-0:(OI)(CI)(IO)M' /Q | Out-Null
  if ($LASTEXITCODE) { Say "setting the permissions of sessions\ failed (icacls $LASTEXITCODE)"; exit 1 }
  & icacls.exe (Join-Path $Root 'secrets') /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q | Out-Null
  if ($LASTEXITCODE) { Say "setting the permissions of secrets\ failed (icacls $LASTEXITCODE)"; exit 1 }
}

# The PawnIO driver: LibreHardwareMonitor reads the CPU's and the board's sensors through it. It's someone else's
# (namazso's, signed, freeware), so it's only installed on a yes. winget runs in this window, so anything it asks
# (an agreement on a PC that has never used it) is asked here, and answered by whoever is installing.
$PawnPage = 'https://github.com/namazso/PawnIO.Setup/releases/latest'
function Get-PawnIO { Get-CimInstance Win32_SystemDriver -Filter "Name='PawnIO'" -ErrorAction SilentlyContinue }
# a yes or no from whoever is at this window: $true, $false, or $null when nobody can answer (no window to type in,
# or no key in 2 minutes). Enter is yes.
function Read-YesNo([string]$q) {
  try {
    if (-not [Environment]::UserInteractive -or [Console]::IsInputRedirected) { return $null }
    while ([Console]::KeyAvailable) { [void][Console]::ReadKey($true) }    # (keys pressed earlier aren't the answer)
    Write-Host ''
    Write-Host "$q [Y/n] " -ForegroundColor Yellow -NoNewline
    $until = (Get-Date).AddMinutes(2)
    while ((Get-Date) -lt $until) {
      if ([Console]::KeyAvailable) {
        $k = [Console]::ReadKey($true)
        if ($k.Key -eq 'Enter' -or $k.Key -eq 'Y') { Write-Host 'yes'; return $true }
        if ($k.Key -eq 'N' -or $k.Key -eq 'Escape') { Write-Host 'no'; return $false }
      }
      Start-Sleep -Milliseconds 100
    }
    Write-Host 'no answer'
  } catch { }
  return $null
}
function Install-PawnIO {
  $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
  if (-not $winget) {
    Say "winget isn't on this PC: opening PawnIO's download page ($PawnPage). Run its installer, then restart the PC"
    try { Start-Process $PawnPage } catch { Say "  (the page didn't open: $($_.Exception.Message))" }
    return
  }
  Say 'installing PawnIO with winget (namazso.PawnIO)'
  $old = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try { & $winget.Source install --id namazso.PawnIO --exact --source winget; $code = $LASTEXITCODE }
  catch { $code = $null; Say "  winget: $($_.Exception.Message)" }
  finally { $ErrorActionPreference = $old }
  if ($null -ne $code) { Say ('  winget finished: exit {0} (0x{0:X8})' -f $code) }
  $d = Get-PawnIO
  if ($d -and $d.State -ne 'Running') { & sc.exe start PawnIO | Out-Null; $d = Get-PawnIO }
  if ($d) { Say "PawnIO driver: $($d.State)" }
}

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
           [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin -and $Uninstall) {
  # Installed apps' Uninstall starts this unelevated: Windows asks for an admin, for this same script (in Program
  # Files, where only admins can change it), in a window of its own; this one waits for it.
  Write-Host 'HW Blackbox: removing it needs admin rights. Windows asks for them now.'
  $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Uninstall')
  if ($RemoveData) { $a += '-RemoveData' }
  if ($Pause) { $a += '-Pause' }
  if ($Report -ne (Join-Path $env:TEMP 'hwblackbox-install.txt')) { $a += @('-Report', "`"$Report`"") }
  try { $p = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList $a; exit $p.ExitCode }
  catch {
    Write-Host "HW Blackbox was not removed: Windows didn't get admin rights. Try again, and choose Yes when it asks."
    $script:failed += 'no admin rights'
    Wait-End
    exit 1
  }
}
"HW Blackbox install: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), user $env:USERNAME, from $PSScriptRoot" | Out-File $Report -Encoding utf8
if (-not $admin) { Say 'NOT elevated: run this in an elevated PowerShell'; exit 1 }
if (-not [Environment]::Is64BitOperatingSystem) { Say 'HW Blackbox needs 64-bit Windows'; exit 1 }

# ---------------------------------------------------------------------------------------------------------------------
if ($Uninstall) {
  # (out of the program's folder first: this script may be running from it, and a process's current folder can't be
  # removed. Set-Location only moves PowerShell's own idea of it; the process's is CurrentDirectory. PowerShell has
  # read the whole script already, so removing the file itself is fine.)
  Set-Location $env:SystemRoot
  [Environment]::CurrentDirectory = $env:SystemRoot
  Stop-HWBlackbox
  if (Get-Service -Name $Service -ErrorAction SilentlyContinue) { sc.exe delete $Service | Out-Null; Say 'removed the service' }
  if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false; Say 'removed the agent task'
  }
  if (Test-Path $StartMenu) { Remove-Item $StartMenu -Force; Say 'removed the Start menu shortcut' }
  if (Test-Path $AppsKey) { Remove-Item $AppsKey -Recurse -Force; Say 'removed it from Installed apps' }
  if (Test-Path $Dest) {
    # (a moment for the processes just ended to let go of their files, then once more)
    $gone = $false
    foreach ($try in 1..3) {
      try { Remove-Item $Dest -Recurse -Force -ErrorAction Stop; $gone = $true; break }
      catch { $why = $_.Exception.Message; Start-Sleep -Seconds 2 }
    }
    if ($gone) { Say "removed $Dest" }
    else { Warn "$Dest couldn't all be removed ($why): delete what's left after a restart" }
  }
  if ($RemoveData -and (Get-OwnAttributes $Data)) {
    # (rmdir removes a link it meets without going into it; Windows PowerShell's Remove-Item -Recurse can follow one)
    if ((Get-OwnAttributes $Data) -band [IO.FileAttributes]::ReparsePoint) { & cmd.exe /c rmdir "$Data" }
    else { & cmd.exe /c rmdir /s /q "$Data" }
    Say "removed $Data"
  }
  elseif (Test-Path $Data) { Say "kept the data in $Data (its logs, reports and settings; delete the folder to remove them)" }
  Say $(if ($script:warned) { "DONE (uninstalled) WITH WARNINGS: $($script:warned -join '; ')" } else { 'DONE (uninstalled)' })
  Wait-End
  exit 0
}

# ---------------------------------------------------------------------------------------------------------------------
Say '== 1. Check the build'
foreach ($f in 'python\pythonw.exe', 'python\python312._pth', 'app\hwblackbox\__init__.py', 'app\lib\LibreHardwareMonitorLib.dll', 'MANIFEST.json') {
  if (-not (Test-Path (Join-Path $PSScriptRoot $f))) { Say "the build is incomplete: $f is missing (run tools\build.py)"; exit 1 }
}
$manifest = Get-Content (Join-Path $PSScriptRoot 'MANIFEST.json') -Raw | ConvertFrom-Json
Say "HW Blackbox $($manifest.version), built $($manifest.built), $($manifest.files) files"
if ($PSScriptRoot.TrimEnd('\') -ieq $Dest) { Say 'run the install from the built folder, not from the installed one'; exit 1 }
# the CPU and motherboard sensors need the PawnIO driver (LibreHardwareMonitor reads them through it)
$pawn = Get-PawnIO
$pawnHint = 'install the PawnIO driver (winget install namazso.PawnIO, or run Install.cmd again and answer yes), then restart the PC'
if ($pawn) { Say "PawnIO driver: $($pawn.State)" }
else {
  Say "the PawnIO driver isn't installed: without it there are no CPU or motherboard sensors (the CPU temperature and power, the rails)"
  $yes = if ($PawnIO -eq 'yes') { $true } elseif ($PawnIO -eq 'no') { $false } else {
    Read-YesNo 'Install PawnIO now? It is a signed driver, freeware by namazso (pawnio.eu), installed with winget'
  }
  if ($yes) { Install-PawnIO }
  elseif ($null -eq $yes) { Say '  (nobody to ask: left out)' }
  else { Say '  left out' }
  $pawn = Get-PawnIO
  if (-not $pawn) { Warn "the PawnIO driver isn't installed, so there will be no CPU or motherboard sensors (the rails, the CPU temperature): $pawnHint" }
  elseif ($pawn.State -ne 'Running') { Warn "the PawnIO driver is installed but $($pawn.State.ToLower()): restart the PC to start it" }
}

Say '== 2. Stop a running HW Blackbox (an update)'
Stop-HWBlackbox

Say "== 3. Copy the program to $Dest"
& robocopy.exe $PSScriptRoot $Dest /MIR /R:2 /W:1 /NFL /NDL /NJH /NJS /NP /XF 'hwblackbox-install*.txt' | Out-Null
if ($LASTEXITCODE -ge 8) { Say "robocopy failed ($LASTEXITCODE)"; exit 1 }
# every file as built (a damaged or changed copy shouldn't run as SYSTEM)
$bad = @()
foreach ($p in $manifest.sha256.PSObject.Properties) {
  $file = Join-Path $Dest ($p.Name -replace '/', '\')
  if (-not (Test-Path $file) -or (Get-FileHash $file -Algorithm SHA256).Hash -ne $p.Value.ToUpper()) { $bad += $p.Name }
}
if ($bad) { Say "these files don't match the build: $($bad[0..9] -join ', ')"; exit 1 }
# (a downloaded release carries Windows' "from the internet" mark, which would make the shortcut ask before it runs)
Get-ChildItem $Dest -Recurse -File | Unblock-File
Say "copied and checked $($manifest.files) files"

Say "== 4. The data folder $Data"
Initialize-DataFolder $Data
$initArgs = @('init', '--data-dir', $Data)
foreach ($s in $Set) { $initArgs += @('--set', $s) }
Run-Hwb $initArgs
if (-not (Test-Path (Join-Path $Data 'config.json'))) { Say 'no config.json: the settings could not be written'; exit 1 }

Say '== 5. The service'
$bin = '"{0}" -m hwblackbox service' -f $Py
$desc = 'HW Blackbox: every sensor and the voltage rails into crash-safe logs, the apps that close or crash, Windows'' records, the ports, and a report for every power-off. The dashboard: HW Blackbox in the Start menu.'
if (Get-Service -Name $Service -ErrorAction SilentlyContinue) {
  # (through WMI: sc.exe can't be handed a path in quotes from Windows PowerShell)
  $r = Get-CimInstance Win32_Service -Filter "Name='$Service'" |
       Invoke-CimMethod -MethodName Change -Arguments @{ PathName = $bin; StartMode = 'Automatic'; DisplayName = 'HW Blackbox' }
  if ($r.ReturnValue -ne 0) { Say "updating the service failed: $($r.ReturnValue)"; exit 1 }
} else {
  New-Service -Name $Service -BinaryPathName $bin -DisplayName 'HW Blackbox' -StartupType Automatic -Description $desc | Out-Null
}
Set-Service -Name $Service -Description $desc
# restart on failure: after 5 s, 30 s, then 2 min; the count resets after a day. Failure includes a stop with an error
# code (failureflag), which is how the service ends itself when a part of it is stuck.
sc.exe failure $Service reset= 86400 actions= restart/5000/restart/30000/restart/120000 | Out-Null
sc.exe failureflag $Service 1 | Out-Null
# time to write its last record when Windows shuts down (milliseconds)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$Service" -Name PreshutdownTimeout -Value 15000 -Type DWord
$q = sc.exe qc $Service
Say ("registered: " + (($q | Select-String 'BINARY_PATH_NAME|START_TYPE|SERVICE_START_NAME') -join ' | ') -replace '\s+', ' ')

Say '== 6. The session agent: at every sign-in, as that user'
$users = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')).Translate([Security.Principal.NTAccount]).Value
$action = New-ScheduledTaskAction -Execute $Py -Argument '-m hwblackbox agent' -WorkingDirectory (Join-Path $Dest 'app')
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -GroupId $users -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
  -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances Parallel -Priority 4
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
  -Description 'HW Blackbox''s session agent: the screens, the app in front, sign-outs, and the dashboard.' -Force | Out-Null
Say "registered $TaskName (group $users)"

Say '== 7. The Start menu shortcut, and Installed apps'
$ws = New-Object -ComObject WScript.Shell
$lnk = $ws.CreateShortcut($StartMenu)
$lnk.TargetPath = $Py
$lnk.Arguments = '-m hwblackbox open'
$lnk.WorkingDirectory = Join-Path $Dest 'app'
$lnk.IconLocation = "$env:SystemRoot\System32\perfmon.exe,0"
$lnk.Description = 'HW Blackbox: the dashboard'
$lnk.Save()
Say "made $StartMenu"
# Settings -> Apps -> Installed apps: its Uninstall runs the installed copy of this script (which asks for an admin).
# Nice to have, so never a reason to stop: a failure here is a warning, and the install carries on to start it.
# (Not "$uninstall": PowerShell's names ignore case, and that's this script's -Uninstall switch. The first 1.0.11
# build stopped here, before starting the service.)
try {
  $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $appsUninstall = "`"$ps`" -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $Dest 'install.ps1')`" -Uninstall -Pause"
  New-Item -Path $AppsKey -Force | Out-Null
  $entry = [ordered]@{
    DisplayName = 'HW Blackbox'; DisplayVersion = [string]$manifest.version; Publisher = 'James Cupps'
    Comments = 'A hardware monitor and black box for Windows'; InstallLocation = $Dest
    DisplayIcon = "$env:SystemRoot\System32\perfmon.exe,0"; UninstallString = $appsUninstall
    URLInfoAbout = 'https://github.com/jamesccupps/HW-Blackbox'
    URLUpdateInfo = 'https://github.com/jamesccupps/HW-Blackbox/releases'
    HelpLink = 'https://github.com/jamesccupps/HW-Blackbox#readme'; InstallDate = (Get-Date -Format 'yyyyMMdd')
  }
  foreach ($k in $entry.Keys) { New-ItemProperty -Path $AppsKey -Name $k -Value $entry[$k] -PropertyType String -Force | Out-Null }
  foreach ($k in 'NoModify', 'NoRepair') { New-ItemProperty -Path $AppsKey -Name $k -Value 1 -PropertyType DWord -Force | Out-Null }
  New-ItemProperty -Path $AppsKey -Name EstimatedSize -PropertyType DWord -Force `
    -Value ([int]([long]$manifest.bytes / 1KB)) | Out-Null                      # (in KB)
  Say 'listed in Settings -> Apps -> Installed apps (its Uninstall removes HW Blackbox and keeps the data)'
} catch { Warn "listing it in Installed apps: $($_.Exception.Message) (Uninstall.cmd still removes it)" }

if ($NoStart) { Say 'DONE (not started: -NoStart)'; exit 0 }

Say '== 8. Start'
$t0 = Get-Date
try {
  Start-Service -Name $Service
  (Get-Service -Name $Service).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
  Say "service: $((Get-Service -Name $Service).Status)"
} catch { Fail "starting the service: $($_.Exception.Message)" }
# the agent, in this session (later sign-ins start it themselves)
try {
  $ts = New-Object -ComObject Schedule.Service
  $ts.Connect()
  $null = $ts.GetFolder('\').GetTask($TaskName).RunEx($null, 4, (Get-Process -Id $PID).SessionId, '')
  Say "started the agent in session $((Get-Process -Id $PID).SessionId)"
} catch { Warn "starting the agent now: $($_.Exception.Message) (it starts at the next sign-in)" }

Say '== 9. Check'
$status = Join-Path $Data 'state\status.json'
$deadline = (Get-Date).AddSeconds(90)
$st = $null
Say 'waiting for the service''s first readings (usually 10-40 seconds)'
do {
  Start-Sleep -Seconds 3
  if ((Test-Path $status) -and (Get-Item $status).LastWriteTime -gt $t0) {
    try { $st = Get-Content $status -Raw | ConvertFrom-Json } catch { $st = $null }
  }
} while (-not ($st -and $st.sensors -and $st.sensors.rows -gt 1) -and (Get-Date) -lt $deadline)
if (-not $st) { Fail 'the service wrote no status in 90 s' }
else {
  Say "service: state $($st.state), watching $(@($st.apps).Count) apps, problems: $(if ($st.problems) { ($st.problems) -join '; ' } else { 'none' })"
  if ($st.sensors) {
    Say "sensors: LibreHardwareMonitor $($st.sensors.lhm), NVML $($st.sensors.nvml), admin $($st.sensors.admin), $($st.sensors.sensors) sensors, rails $($st.sensors.rails_ok), CPU temperature $($st.sensors.cpu_temp_ok)"
    if (-not $st.sensors.admin) { Fail 'the sensors are not elevated' }
    # (a laptop, or a board whose chip can't be read: no rails to read, and no fault. Without the driver, step 1 has
    # said so already. Until 1.0.11 every laptop's install ended "DONE WITH PROBLEMS: no rail voltages".)
    if ($st.attributes.rails -eq 'none on this PC') { Say "rails: none on this PC ($($st.attributes.board_note))" }
    elseif (-not $st.sensors.rails_ok -and $pawn) { Fail 'no rail voltages (the board''s sensor chip didn''t answer)' }
  } else { Fail 'the sensors have not started' }
}
$me = $env:USERNAME
$hbFile = Get-ChildItem (Join-Path $Data 'sessions') -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'agent.json' } |
  Where-Object { (Test-Path $_) -and (Get-Item $_).LastWriteTime -gt $t0 } | Select-Object -First 1
$deadline = (Get-Date).AddSeconds(45)
if (-not $hbFile) { Say 'waiting for the session agent (up to 45 seconds)' }
while (-not $hbFile -and (Get-Date) -lt $deadline) {
  Start-Sleep -Seconds 3
  $hbFile = Get-ChildItem (Join-Path $Data 'sessions') -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'agent.json' } |
    Where-Object { (Test-Path $_) -and (Get-Item $_).LastWriteTime -gt $t0 } | Select-Object -First 1
}
if ($hbFile) {
  $hb = Get-Content $hbFile -Raw | ConvertFrom-Json
  Say "agent: $($hb.user), session $($hb.session), dashboard port $($hb.dashboard.port) $($hb.dashboard.error)"
  if ($hb.dashboard.port) {
    try {
      $ping = Invoke-RestMethod "http://127.0.0.1:$($hb.dashboard.port)/api/ping" -TimeoutSec 5
      Say "dashboard answers: $($ping.app) $($ping.version)"
    } catch { Warn "the dashboard doesn't answer: $($_.Exception.Message)" }
  } else { Warn "the dashboard isn't serving: $($hb.dashboard.error)" }
} else { Warn 'no session agent heartbeat in 45 s (the service starts it within minutes, and every sign-in does)' }

$open = 'Open HW Blackbox from the Start menu' + $(if ($hbFile -and $hb.dashboard.port) { " (or http://127.0.0.1:$($hb.dashboard.port)/ in a browser)." } else { '.' })
if ($script:failed) { Say "DONE WITH PROBLEMS: $($script:failed -join '; ')"; Say $open; exit 2 }
if ($script:warned) { Say "DONE WITH WARNINGS: $($script:warned -join '; ')"; Say $open; exit 0 }
Say "DONE. $open"
exit 0
