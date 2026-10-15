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
  if ($RemoveData -and (Test-Path $Data)) { Remove-Item $Data -Recurse -Force; Say "removed $Data" }
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
foreach ($d in '', 'logs', 'state', 'incidents', 'sessions', 'secrets') {
  $p = Join-Path $Data $d
  if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p | Out-Null }
}
# SYSTEM and admins: everything; users: read. sessions\: each user may make a folder of their own (and owns it).
# secrets\: SYSTEM and admins only.
& icacls.exe $Data /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /Q | Out-Null
& icacls.exe (Join-Path $Data 'sessions') /grant '*S-1-5-32-545:(AD)' '*S-1-3-0:(OI)(CI)(IO)M' /Q | Out-Null
& icacls.exe (Join-Path $Data 'secrets') /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q | Out-Null
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
    if (-not $st.sensors.rails_ok) { Fail 'no rail voltages' }
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

if ($script:failed) { Say "DONE WITH PROBLEMS: $($script:failed -join '; ')"; exit 2 }
if ($script:warned) { Say "DONE WITH WARNINGS: $($script:warned -join '; ')"; exit 0 }
Say 'DONE'
exit 0
