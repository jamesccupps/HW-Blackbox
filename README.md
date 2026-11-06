# HW Blackbox

A hardware monitor and a black box for a Windows PC. It answers the question Windows leaves open: *why did the PC
switch off, or why did that app close?*

**[⬇ Download for Windows](https://github.com/jamesccupps/HW-Blackbox/releases/latest/download/HWBlackbox-win64.zip)**
(64-bit Windows 10 or 11) · [All releases](https://github.com/jamesccupps/HW-Blackbox/releases) ·
[Website](https://jamesccupps.github.io/HW-Blackbox/)

![The dashboard's overview: the service, the sensors, the key readings now, power-offs, disks and this PC](docs/screenshots/overview.png)
*The screenshots show made-up data (`tools\make_demo.py`).*

- **Records the moment it happens.** Every sensor every 5 s, and the voltage rails four times a second, written to
  disk before the next reading, so the last seconds before a power loss survive.
- **Writes the report for you.** After a power-off: when the PC really went down (not Windows' guess), for how long,
  and the last two minutes of readings. After an app crash: the exit code in words, and the last three minutes of
  everything.
- **Tells you what's wrong, and what to do.** The Diagnose tab checks what it has recorded (power-offs, crashes,
  heat, the rails, a program stuck busy or growing without end, memory, disk space) and says what to do about each.
- **Runs from boot, as a Windows service,** whether or not anyone signs in. Windows restarts it if it ever fails.
- **Stays on your PC.** A local dashboard on `127.0.0.1`; optionally a status for your own Home Assistant, with
  alerts for a problem, a power loss or a PC that has gone quiet.

## Install

1. For the CPU and motherboard sensors, install the PawnIO driver first: `winget install namazso.PawnIO`.
2. Download **[HWBlackbox-win64.zip](https://github.com/jamesccupps/HW-Blackbox/releases/latest/download/HWBlackbox-win64.zip)**
   and unzip it.
3. Double-click **`Install.cmd`**. It asks for admin rights, installs the service and the agent, and shows what it
   did. The scripts aren't code-signed, so Windows may show *Windows protected your PC*: click **More info**, then
   **Run anyway**.
4. Open **HW Blackbox** from the Start menu, or go to `http://127.0.0.1:9070/`.

Each release lists the zip's SHA-256 (`Get-FileHash .\HWBlackbox-win64.zip`), and the installer checks every file
against the release's manifest. More options are under [Install, in detail](#install-in-detail).

## A closer look

| | |
|---|---|
| ![Charts](docs/screenshots/charts.png) **Charts:** any reading over days, with power-offs (red) and your own milestones | ![Power](docs/screenshots/power.png) **Power:** the rails four times a second, and every power-off caught |
| ![Events](docs/screenshots/events.png) **Events:** crashes, shutdowns and who asked, sessions, port clashes | ![Incident](docs/screenshots/incident.png) **Incidents:** the report written after a power-off |

## What it records

- **Sensors.** Every sensor LibreHardwareMonitor finds is read every 5 s: CPU, motherboard sensor chip, fan
  controllers and Corsair digital power supplies. An NVIDIA GPU is read through NVML, an AMD or Intel GPU through
  LibreHardwareMonitor, and Windows supplies the CPU load and memory.
  - The key readings go to `flight_YYYYMMDD.csv`.
  - The +12 / +5 / +3.3 V rails, Vcore and SoC go to `rails_YYYYMMDD.csv`, four times a second, with the CPU's power
    and temperature (read once a second).
  - Every row is written to disk before the next one is taken (fsync), so the last rows before a sudden power loss
    survive.
- **Power-offs.** At the boot after a shutdown that wasn't clean (Windows' Kernel-Power 41 and EventLog 6008), it
  writes a report with:
  - the time the PC really went down: the last logged row, which can be half an hour off Windows' own guess;
  - how long it was off;
  - the last two minutes of both logs, the rails trace last;
  - whether the service had seen a shutdown begin.
- **Shutdowns.** Who asked for a shutdown or restart (User32 1074). Windows asking each session to end, with the
  idle time and the app in front. The service's own goodbye as services stop, so a missing goodbye means the power
  went.
- **Apps.** The apps on a watch list, in every session: when they start and end, the exit code and what it means
  (clean, crash, killed by another program), and their memory every minute. A crash gets an incident report with the
  last 3 minutes of everything and the app that was in front.
- **Windows' records.** Crashes, hangs and error reports for any app, display driver resets, low memory, services
  ending unexpectedly, boots and shutdowns. Records written while the service wasn't running are read at its next
  start.
- **Ports.** Who listens on which TCP port, every 15 s. It flags two programs on one port where their addresses
  overlap (one on all addresses and one on 127.0.0.1, say), a known port held by the wrong program, and a server
  that should always be listening but isn't.
- **Sessions.** Sign-ins, locks and sign-outs; sleep and resume; screen changes (resolution, position, scaling); the
  taskbar coming back after Explorer restarts; the clock being changed.
- **Programs.** Every program's CPU, memory, graphics memory and GPU use, minute by minute, all its processes
  together, plus the time the processors spent on drivers' interrupts. Windows keeps no such history: Task Manager
  only shows now. So when the CPU was busy at 3 in the morning, or a program grew by gigabytes overnight, the
  Processes tab says which program it was. The GPU's figures come from Windows' own GPU counters (the ones Task
  Manager uses), so they work for any make of GPU.
- **Disk space.** Every fixed drive's free space, once a minute, to chart over days. The Windows drive is a problem
  when it gets low or fills up fast (an update unpacking, a download, a runaway log). It also notes a Windows update
  that's waiting for a restart.

Optionally, it sends a status to **Home Assistant** every minute, so you can be alerted to a problem, a power loss, or
a PC that has gone quiet.

## How it's built

| Part | Runs as | Does |
|---|---|---|
| **Service** `HWBlackbox` | LocalSystem, from boot, whether or not anyone signs in | sensors, power-offs, apps, Windows' records, ports, status, Home Assistant |
| **Session agent** (task `HWBlackboxAgent`) | each signed-in user, not elevated | what only a session can see: the screens, the app in front, the taskbar, sign-outs; serves the dashboard |
| **Dashboard** | a page in your browser, from the agent, on `127.0.0.1` | everything above |

What keeps it reliable:

- **The service is a real Windows service.** Windows restarts it if it fails. It also hears about shutdowns,
  sessions, sleep and clock changes directly, and gets time to write a last record when Windows shuts down.
- **A dead man's switch** ends the service if any part of it stops moving (a stuck driver call, a deadlock), so
  Windows starts it again. It's a native thread-pool timer, so it still works when Python itself is wedged.
- **The rails lane has its own high-priority thread** and keeps to a schedule. A slow GPU read can't hold it up, and
  Windows' 15.6 ms timer rounding doesn't make it drift.
- **The CPU has a lane of its own.** Reading the CPU's sensors means visiting each core in turn, and a core kept busy
  by a program of higher priority can hold that up for seconds. So the CPU is read once a second on its own thread,
  and the rails never wait for it.
- **The service starts the agent again** through its scheduled task if the agent stops in a signed-in session.
- **Ports come from Windows' own listener table.** That's `GetExtendedTcpTable` with `TCP_TABLE_OWNER_PID_LISTENER`,
  not the connection table's state field, which is garbage on some Windows builds (netstat and
  `Get-NetTCPConnection` list the wrong ports there).
- **Every process in one call** (`NtQuerySystemInformation`), about 10 ms, rather than seconds of asking process by
  process. It brings every process's CPU time and memory with it.
- **Windows' GPU counters once a minute**, on a thread of their own (`GPU Process Memory` and `GPU Engine`, through
  PDH): NVIDIA's own interface can't tell programs' graphics memory apart on Windows.

## Requirements

- **Windows 10 or 11, 64-bit, and an administrator account** to install.
- **PawnIO** for the CPU and motherboard sensors (temperatures, voltages, fans). It's the signed driver
  LibreHardwareMonitor uses for low-level hardware access, and it's installed separately:
  `winget install namazso.PawnIO`. Without it you still get the GPU, the CPU load, memory and everything that isn't
  a sensor.
- **To build:** Python 3.12 (64-bit), and LibreHardwareMonitorLib's DLLs in `lib\` (see [Building](#building)). The
  installed program carries its own Python, so nothing else is needed on the PC.

## Install, in detail

`Install.cmd`, from the unzipped [release](https://github.com/jamesccupps/HW-Blackbox/releases/latest), runs
`install.ps1`:
- It copies the program to `C:\Program Files\HWBlackbox` and checks every file against the release's manifest.
- It sets up the data folder.
- It registers and starts the service and the agent's task, and adds **HW Blackbox** to the Start menu.
- It checks that everything reports.

Its log is `%TEMP%\hwblackbox-install.txt`. Running it again updates an installed HW Blackbox and keeps the settings
and the history. **`Uninstall.cmd`** removes it and keeps the data.

The same from an elevated PowerShell, with options:

```powershell
.\install.ps1 -Set "dashboard.port=9071","home_assistant.enabled=false"   # settings for a first install
.\install.ps1 -Uninstall              # remove the program, the service, the task and the shortcut; keep the data
.\install.ps1 -Uninstall -RemoveData  # ...and delete the data too
```

## The dashboard

Open **HW Blackbox** from the Start menu, or go to `http://127.0.0.1:9070/`. The page has these tabs:

| Tab | Shows |
|---|---|
| **Overview** | the service and the agents, any problems, the key readings now, power-offs, disks (with their last week) |
| **Diagnose** | checks over what's been recorded, each with what it found and what to do: power-offs, crashes, display driver resets, CPU and GPU heat, the rails, programs stuck busy or growing, RAM, graphics memory, disk space, a waiting update, uptime |
| **Sensors** | every sensor: current, minimum, maximum and average, since the page opened or since the service started |
| **Charts** | the 5-second log and the drives' free space over 1 hour to 7 days: the line is the average, the band the minimum and maximum |
| **Power** | the 4-a-second rails over the last minutes, and every power-off caught |
| **Events** | the records: apps closing and crashing, shutdowns and who asked, sessions, ports, Windows' records |
| **Ports** | who listens where, and port problems |
| **Incidents** | the power-off and crash reports |
| **Processes** | what's using the CPU and memory right now, and every program's CPU, memory, graphics memory and GPU use over the last week (pick the programs to chart) |

The header shows the page's version. After an update, a page that was already open says so and offers a reload.

The dashboard only reads. It listens on `127.0.0.1` alone and answers only requests addressed that way, so a web page
can't reach it through DNS rebinding.

## Settings

`C:\ProgramData\HWBlackbox\config.json`. Admins can edit it; everyone can read it. Change it with an editor run as
admin, or from an elevated prompt:

```powershell
& "C:\Program Files\HWBlackbox\python\python.exe" -m hwblackbox set dashboard.port=9071 home_assistant.enabled=true
```

The service reads `ports`, `home_assistant`, `dashboard` (its milestones), `disk_warn_gb` and `disk_drop_gb` again
every minute. The watch list and the sensors' timing take a restart of the service (`Restart-Service HWBlackbox`);
the dashboard's port, or turning it off, takes signing out and in again (the session agent serves it). A setting of
the wrong kind (a word where a number goes) keeps its default, and the Overview says which.

```jsonc
{
  "sensors": {"interval_s": 5, "rails_interval_s": 0.25, "keep_days": 183, "rails_keep_days": 7, "lhm_gpu": "auto"},
  "events": {"keep_days": 183},
  "watch": [
    {"exe": "explorer.exe", "label": "Windows Explorer"},
    {"exe": "node.exe", "label": "My server", "ports": [8080], "incidents": "crash"},
    {"exe": "pythonw.exe", "label": "My script", "match": "myscript.py", "exclude": "--test"}
  ],
  "ports": {
    "expected": {"8080": {"label": "My server", "exe": "node.exe", "always": true}},
    "ignore": [],
    "down_after_min": 5
  },
  "home_assistant": {"enabled": false, "env_file": "C:\\ProgramData\\HWBlackbox\\secrets\\home_assistant.env",
                     "entity": "sensor.my_pc_hw_blackbox", "name": "MY-PC HW Blackbox"},
  "dashboard": {"enabled": true, "port": 9070,
                "milestones": [{"at": "2026-10-08T19:03:00", "text": "BIOS setting changed"}]},
  "disk_warn_gb": 10,
  "disk_drop_gb": 10
}
```

**`disk_warn_gb`** and **`disk_drop_gb`** are about the Windows drive. It's a problem when less than `disk_warn_gb`
is free, or when it's filling up fast: `disk_drop_gb` gone within an hour, and at that rate under `disk_warn_gb`
within two hours (`0` turns that off). A drive with plenty of room that swings by tens of GB (temporary files
written and deleted all day) isn't flagged. Once on, "filling up fast" stays on for 15 minutes, so a swing doesn't
make it flicker. Other drives are logged and charted, not judged: a data drive that's nearly full is often meant to
be.

**`watch` rules:**
- **`match`** and **`exclude`**: a word the command line must or mustn't have.
- **`ports`**: a server found by the port it listens on. The process of the same program that started it is watched
  too, as its supervisor.
- **`incidents: "crash"`**: write a report only for a crash, for an app you stop and start all day. The default is a
  report for any exit but a clean one.

**`milestones`** are marked on the charts, such as a BIOS change you want to compare before and after. The Power tab
counts the power-offs since the newest one.

**`lhm_gpu`** is LibreHardwareMonitor's GPU support.
- **`"auto"`**: on for AMD and Intel GPUs, and off when there's an NVIDIA GPU, which NVML reads instead.
  LibreHardwareMonitor's own NVIDIA code has crashed its host process in the past.
- **`true`** or **`false`**: force it on or off.

## Home Assistant

1. In Home Assistant, create a long-lived access token (your profile → Security).
2. As admin, write `C:\ProgramData\HWBlackbox\secrets\home_assistant.env`. Only SYSTEM and admins can read that
   folder.

   ```
   HA_URL=http://homeassistant.local:8123
   HA_TOKEN=eyJ...
   ```

3. Set `home_assistant.enabled` to `true` (and `entity` and `name` if you like).

Every minute the entity gets state `ok` or `problem`, with these attributes:
- `problems`: a list, in words;
- `sensors`, `rails`, `cpu_temperature`, `watcher`, `session_agent`;
- `last_incident`, `last_shutdown`, `last_power_loss`, `last_power_loss_died_at`;
- `windows_update`: "waiting for a restart since ..." or "no restart waiting";
- `disk_free_gb`, `logs_gb`, `boot`, `version`.

It only reports changes that matter, so the history stays small. Every report still updates `last_reported`, which a
"gone quiet" alert can use:

```yaml
triggers:
  - trigger: state
    entity_id: sensor.my_pc_hw_blackbox
    to: problem
    for: {minutes: 3}
  - trigger: state
    entity_id: sensor.my_pc_hw_blackbox
    attribute: last_power_loss
  - trigger: template
    value_template: "{{ (now() - states.sensor.my_pc_hw_blackbox.last_reported).total_seconds() > 900 }}"
```

## Files

`C:\ProgramData\HWBlackbox`:

| | |
|---|---|
| `config.json` | the settings |
| `logs\flight_YYYYMMDD.csv` | every 5 s: the key readings (kept 183 days, about 2.5 MB a day) |
| `logs\rails_YYYYMMDD.csv` | 4 a second: rails, Vcore, SoC, CPU power and temperature (kept 7 days, about 24 MB a day) |
| `logs\programs_YYYYMMDD.csv` | every minute: each busy or big program's CPU time, memory, graphics memory and GPU share, a row per program (kept 183 days, about 1.5 MB a day). 1.0.7 wrote `cpu_YYYYMMDD.csv` (the CPU alone); it's still read |
| `logs\disks_YYYYMMDD.csv` | every minute: each fixed drive's free and total GB, a row per drive (kept 183 days, about 100 KB a day for two drives) |
| `logs\events_YYYYMMDD.jsonl` | the service's records, one JSON object a line |
| `state\status.json` | the status, every 30 s |
| `state\sensors.json` | every sensor, with its minimum, maximum and average since the service started |
| `state\ports.json` | who listens where |
| `incidents\incident_*.txt` | `incident_<boot>.txt` for a power-off, `incident_<time>_<app>.txt` for an app |
| `sessions\<user>\` | each user's agent: `session_YYYYMMDD.jsonl`, `agent.json` (its heartbeat), `front.json` (the app in front over the last 3 minutes, overwritten as it changes) |
| `crash.log` | anything the service couldn't put anywhere else |

From a prompt:

```powershell
$hwb = "C:\Program Files\HWBlackbox\python\python.exe"
& $hwb -m hwblackbox status                  # the service's status
& $hwb -m hwblackbox once                    # one look at everything, printed
& $hwb -m hwblackbox serve --data-dir D:\copy --port 9080   # the dashboard over a data folder copied from another PC
```

The dashboard can link to a view: `#charts:72:cpu_temp_c,v12_v` (those readings, the last 72 hours),
`#charts:168:disk:C:` (C:'s free space, the last week), `#processes:mem` (memory by program; also `cpu`, `vram`,
`gpu`), `#diagnose`, `#sensors:logger`, `#incidents:<report file>`.

## Limitations

- **Tested on one PC so far:** an AMD Ryzen 5 5600G on a B550 board, with an NVIDIA RTX 3060, on Windows 11. Other
  CPUs, sensor chips and GPUs go through LibreHardwareMonitor and should work. Which readings show up, and what
  they're called, varies by board, and the rails need a sensor chip that reports them.
- **It isn't code-signed.** Windows SmartScreen may warn about `Install.cmd` the first time. Check the zip's SHA-256
  against the release notes; the installer then checks every file against the release's manifest.
- **Times are local, without a time zone.** The logs and records use the PC's local time, so when daylight saving
  ends, the repeated hour appears twice in the logs and on the charts. The checks that raise problems aren't
  affected: they use a steady clock.
- **Windows 10 and 11, 64-bit only.** Ports are TCP only.

## Privacy and security

- **Nothing leaves the PC** unless you turn Home Assistant on, and then only the status above goes to your own Home
  Assistant.
- **The app in front is kept for the last 3 minutes only**, as a rolling window. It's copied into a record when
  Windows shuts down or restarts, and into an app's incident report; those are kept (records 183 days, app reports
  the same, power-off reports until you delete them).
- **The program history names programs:** each minute, the busiest and biggest programs by exe name (`chrome.exe`,
  `game.exe`), kept 183 days. It doesn't say which account ran them, or what they had open.
- **On a PC with several accounts, everyone signed in sees the same dashboard:** every account's sessions, the app
  in front included, and every listening program's command line (with password-like values hidden as `***`).
- **The program can only be changed by admins:** Program Files, with a Python of its own. The service runs as
  SYSTEM, so nothing it loads can be in a folder a normal account can write. The data folder is the same: it belongs
  to Administrators and users can only read it, except that each session agent makes a folder of its own in
  `sessions\`. The token in `secrets\` is for SYSTEM and admins only. The installer moves aside a data folder anyone
  else made first, and the service never writes through a link.
- **Watching is reading only:** other processes are opened for their exit code and nothing more. HW Blackbox changes
  no settings and never blocks a shutdown.

## Building

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install pythonnet psutil pywin32 nvidia-ml-py
# lib\: LibreHardwareMonitorLib.dll and its dependencies (HidSharp, RAMSPDToolkit-NDD, System.*), from a
# LibreHardwareMonitor release or the LibreHardwareMonitorLib NuGet package (net472)
.venv\Scripts\python.exe tools\build.py --zip    # -> build\HWBlackbox, and dist\HWBlackbox-<version>-win64.zip
```

What `build.py` does:
- It copies the interpreter and its standard library (without tests, tkinter or IDLE), plus this venv's packages,
  into `build\HWBlackbox\python\`.
- A `python312._pth` file fixes the module path to those folders only.
- It compiles everything and checks that the result runs on its own.
- It writes `MANIFEST.json` with every file's SHA-256 for the installer to check.

The tests: `.venv\Scripts\python.exe -m unittest discover -s tests`.

To try changes without installing, run a second instance next to the installed one, with its own data folder:

```powershell
.venv\Scripts\python.exe -m hwblackbox console --test --data-dir C:\temp\hwb --run-for 120
.venv\Scripts\python.exe -m hwblackbox agent --test --data-dir C:\temp\hwb
```

`--test` never sends to Home Assistant and never restarts the real agents. Unelevated it has no CPU or board sensors.

The screenshots come from made-up data:

```powershell
.venv\Scripts\python.exe tools\make_demo.py --out C:\temp\hwb-demo --live 600
.venv\Scripts\python.exe -m hwblackbox serve --data-dir C:\temp\hwb-demo     # http://127.0.0.1:9079/
.venv\Scripts\python.exe tools\screenshots.py
```

## License

MIT; see [LICENSE](LICENSE). The bundled third-party software and its licenses are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
