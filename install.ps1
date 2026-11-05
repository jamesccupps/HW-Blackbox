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
  [string]$Report
)
$ErrorActionPreference = 'Stop'
$Service = 'HWBlackbox'
$TaskName = 'HWBlackboxAgent'
$Dest = Join-Path $env:ProgramFiles 'HWBlackbox'
$Data = Join-Path $env:ProgramData 'HWBlackbox'
$Py = Join-Path $Dest 'python\pythonw.exe'
$PyCon = Join-Path $Dest 'python\python.exe'
$StartMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\HW Blackbox.lnk'
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

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
           [Security.Principal.WindowsBuiltInRole]::Administrator)
"HW Blackbox install: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), user $env:USERNAME, from $PSScriptRoot" | Out-File $Report -Encoding utf8
if (-not $admin) { Say 'NOT elevated: run this in an elevated PowerShell'; exit 1 }
if (-not [Environment]::Is64BitOperatingSystem) { Say 'HW Blackbox needs 64-bit Windows'; exit 1 }

# ---------------------------------------------------------------------------------------------------------------------
if ($Uninstall) {
  Stop-HWBlackbox
  if (Get-Service -Name $Service -ErrorAction SilentlyContinue) { sc.exe delete $Service | Out-Null; Say 'removed the service' }
  if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false; Say 'removed the agent task'
  }
  if (Test-Path $StartMenu) { Remove-Item $StartMenu -Force; Say 'removed the Start menu shortcut' }
  if (Test-Path $Dest) { Remove-Item $Dest -Recurse -Force; Say "removed $Dest" }
  if ($RemoveData -and (Get-OwnAttributes $Data)) {
    # (rmdir removes a link it meets without going into it; Windows PowerShell's Remove-Item -Recurse can follow one)
    if ((Get-OwnAttributes $Data) -band [IO.FileAttributes]::ReparsePoint) { & cmd.exe /c rmdir "$Data" }
    else { & cmd.exe /c rmdir /s /q "$Data" }
    Say "removed $Data"
  }
  elseif (Test-Path $Data) { Say "kept the data in $Data" }
  Say 'DONE (uninstalled)'
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
$pawn = Get-CimInstance Win32_SystemDriver -Filter "Name='PawnIO'" -ErrorAction SilentlyContinue
$pawnHint = 'install the PawnIO driver (winget install namazso.PawnIO), then run Install.cmd again'
if ($pawn) { Say "PawnIO driver: $($pawn.State)" }
else { Warn "the PawnIO driver isn't installed, so there will be no CPU or motherboard sensors (the rails, the CPU temperature): $pawnHint" }

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

Say '== 7. The Start menu shortcut'
$ws = New-Object -ComObject WScript.Shell
$lnk = $ws.CreateShortcut($StartMenu)
$lnk.TargetPath = $Py
$lnk.Arguments = '-m hwblackbox open'
$lnk.WorkingDirectory = Join-Path $Dest 'app'
$lnk.IconLocation = "$env:SystemRoot\System32\perfmon.exe,0"
$lnk.Description = 'HW Blackbox: the dashboard'
$lnk.Save()
Say "made $StartMenu"

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
    if (-not $st.sensors.rails_ok) { Fail ('no rail voltages' + $(if (-not $pawn) { ": $pawnHint" } else { ' (the board''s sensor chip may not be supported)' })) }
  } else { Fail 'the sensors have not started' }
}
$me = $env:USERNAME
$hbFile = Get-ChildItem (Join-Path $Data 'sessions') -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'agent.json' } |
  Where-Object { (Test-Path $_) -and (Get-Item $_).LastWriteTime -gt $t0 } | Select-Object -First 1
$deadline = (Get-Date).AddSeconds(45)
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
