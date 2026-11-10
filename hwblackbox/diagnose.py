r"""The Diagnose tab: checks over what HW Blackbox has recorded, each saying what it found and, when something is
wrong, what to do about it.

run(inputs) takes what the dashboard's server gathers (diagnose_inputs there: the status, the last day of the
5-second log and of the programs log, the last week of records, the power-offs, the screen changes) and returns
{"checks": [...], "counts": {...}}. A check is

  {"id", "title", "level": "ok" | "info" | "warn" | "bad", "summary": one line, "window": what it looked at,
   "seen": [what it found, line by line], "advice": [what to do], "link": "#a-tab" or None}

Nothing here reads files or asks Windows: it judges what it's given, so every rule can be tested with made-up data.
The thresholds are deliberately plain (a CPU at 95 °C, a rail 5 % off, a program a core flat out for half an hour),
so a finding can be checked by eye on the charts it links to."""
import bisect
import collections
import datetime as dt
import re
import statistics

from .util import parse_iso

ORDER = {"bad": 0, "warn": 1, "info": 2, "ok": 3}
DAY = 86400.0

# Windows' own programs, what they are, and what to do when one is busy or keeps growing. "busy_min": the minutes a
# core flat out in a day before it counts (Windows' programs should be close to idle; a scan or an update isn't).
FRESH_START = "Sign out and back in, or restart the PC: that starts it fresh."
RESTART_EXPLORER = ("Restart it: Task Manager → Processes → Windows Explorer → Restart. Open folder windows close; "
                    "nothing else is lost.")
GRAPHICS_DRIVER = ("If it comes back, update the graphics driver from NVIDIA's, AMD's or Intel's own site (not through "
                   "Windows Update).")
DRIVERS = "Update the chipset, network, storage, USB and audio drivers (from the PC's or the motherboard maker's site)."
KNOWN = {
    "dwm.exe": {"what": "Windows' Desktop Window Manager, which draws every window on the screen",
                "busy": [FRESH_START, GRAPHICS_DRIVER,
                         "It often follows a change of screens: a remote session starting or ending, a monitor "
                         "switched off or unplugged, a change of resolution or scaling."],
                "memory": [FRESH_START, GRAPHICS_DRIVER]},
    "explorer.exe": {"what": "Windows Explorer: the taskbar, Start, the desktop and folder windows",
                     "busy": [RESTART_EXPLORER, "Add-ons to Explorer (right-click menu entries, cloud-storage icons) "
                              "are a common cause: ShellExView (NirSoft, free) can turn them off one at a time."],
                     "memory": [RESTART_EXPLORER, "Add-ons to Explorer (right-click menu entries, cloud-storage "
                                "icons) are a common cause: ShellExView (NirSoft, free) can turn them off one at a "
                                "time."]},
    "System interrupts": {"what": "the processors' time on answering devices (interrupts and DPCs), which Windows "
                                  "charges to no program",
                          "busy": ["A driver or a device is the cause. " + DRIVERS,
                                   "Unplug USB devices one at a time to see if one of them is it.",
                                   "LatencyMon (free) names the driver."]},
    "System": {"what": "Windows' kernel and its drivers",
               "busy": ["Usually a driver. " + DRIVERS, "Process Explorer (Microsoft, free) shows which driver: "
                        "System → Properties → Threads, sorted by CPU."],
               "memory": ["Usually a driver. " + DRIVERS, "PoolMon (in the Windows Driver Kit) names the driver "
                          "holding the memory."]},
    "MsMpEng.exe": {"what": "Microsoft Defender, scanning files", "busy_min": 120,
                    "busy": ["Normal during a scan. If it's busy for hours every day, exclude folders whose files "
                             "change all the time (build output, virtual machine disks, game caches): Windows "
                             "Security → Virus & threat protection → Manage settings → Exclusions."]},
    "SearchIndexer.exe": {"what": "Windows Search, indexing files", "busy_min": 120,
                          "busy": ["Normal after many files change. If it never settles, rebuild the index: Control "
                                   "Panel → Indexing Options → Advanced → Rebuild."]},
    "svchost.exe": {"what": "a host for Windows services (many run inside it)",
                    "busy": ["Task Manager → Details → right-click svchost.exe with the pid above → Go to service(s): "
                             "that's the service.", "Restart the PC; if it comes back, look for a Windows update."]},
    "WmiPrvSE.exe": {"what": "WMI, which answers programs asking for information about the PC",
                     "busy": ["A program is asking over and over. Event Viewer → Applications and Services Logs → "
                              "Microsoft → Windows → WMI-Activity → Operational names it (ClientProcessId)."]},
    "TiWorker.exe": {"what": "Windows Update, installing updates", "busy_min": 180,
                     "busy": ["Normal while updates install: let it finish, then restart."]},
    "TrustedInstaller.exe": {"what": "Windows Update, installing updates", "busy_min": 180,
                             "busy": ["Normal while updates install: let it finish, then restart."]},
    "audiodg.exe": {"what": "Windows' audio engine",
                    "busy": ["Turn off audio enhancements (Settings → System → Sound → the device → Audio "
                             "enhancements: Off) and update the audio driver."]},
}
for _n in ("csrss.exe", "RuntimeBroker.exe", "ShellExperienceHost.exe", "StartMenuExperienceHost.exe", "SearchHost.exe",
           "ctfmon.exe", "sihost.exe", "taskhostw.exe", "fontdrvhost.exe", "WUDFHost.exe", "spoolsv.exe", "lsass.exe",
           "services.exe", "wininit.exe", "winlogon.exe", "smss.exe", "Registry", "Memory Compression",
           "SecurityHealthService.exe", "conhost.exe", "dllhost.exe"):
    KNOWN.setdefault(_n, {"what": "a part of Windows", "busy": [FRESH_START, "If it comes back, look for a Windows "
                                                                "update, and update the drivers."]})
BUSY_MIN = 30                   # minutes a core flat out in a day: a Windows program
BUSY_MIN_APP = 360              # ... any other program (a game, a render or a build is meant to: an evening's game
                                # isn't worth a note, six hours at full tilt might be)
GROWN_MB = 1024                 # a program's memory up by this much in a day, and at least doubled, and still there


# formatting -----------------------------------------------------------------------------------------------------------

def when(t, now):
    d = dt.datetime.fromtimestamp(t)
    return d.strftime("%H:%M") if now - t < 20 * 3600 else "%s %d %s" % (d.strftime("%a"), d.day, d.strftime("%b %H:%M"))


def span(seconds):
    m = int(round(seconds / 60.0))
    if m < 60:
        return "%d min" % max(1, m)
    if m < 48 * 60:
        return "%d h" % (m // 60) + (" %d min" % (m % 60) if m % 60 else "")
    return "%d days" % round(m / 1440.0)


def mb(v):
    return "%.1f GB" % (v / 1024) if v >= 1024 else "%d MB" % round(v)


def finding(cid, title, level, summary, window, seen=(), advice=(), link=None):
    return {"id": cid, "title": title, "level": level, "summary": summary, "window": window, "seen": list(seen),
            "advice": list(advice), "link": link}


# the inputs, as the checks want them ---------------------------------------------------------------------------------

class Inputs:
    def __init__(self, d):
        self.now = d.get("now")
        self.status = d.get("status") or {}
        self.status_age = d.get("status_age")
        self.cfg = d.get("cfg") or {}
        self.sensors = d.get("sensors") or []
        self.flight_t = d.get("flight_t") or []
        self.flight = d.get("flight") or {}
        self.programs = d.get("programs") or []          # (epoch, seconds, program, cpu, mem, vram, gpu, n, pid)
        self.power_offs = d.get("power_offs") or []
        self.records = d.get("records") or []            # the service's exits and Windows' records, with "t"
        self.displays = sorted(d.get("displays") or [])  # when the screens changed
        self.watched_mem = {k: sorted(v) for k, v in (d.get("watched_mem") or {}).items()}  # exe -> [(t, MB)]
        self.drives = d.get("drives") or {}               # state\drives.json: {"drives": [...], "error"}
        self.drive_rows = d.get("drive_rows") or []      # [(t, disk, {column: value})], the last 30 days
        self.by_program = collections.defaultdict(list)
        self.minutes = {}                                 # minute's epoch -> its rows
        for r in self.programs:
            self.by_program[r[2]].append(r)
            self.minutes.setdefault(r[0], []).append(r)
        self.minute_times = sorted(self.minutes)

    def series(self, col):
        """[(t, value)] of a 5-second log column, blanks left out."""
        vals = self.flight.get(col) or []
        return [(t, v) for t, v in zip(self.flight_t, vals) if v is not None and v == v]

    def sensor(self, sid):
        for s in self.sensors:
            if isinstance(s, dict) and s.get("id") == sid:
                return s.get("value")
        return None

    def minute_at(self, t):
        """The programs' rows for the minute that covers time t (None if there's none within two minutes)."""
        i = bisect.bisect_left(self.minute_times, t)
        for j in (i, i - 1):
            if 0 <= j < len(self.minute_times) and abs(self.minute_times[j] - t) <= 120:
                return self.minutes[self.minute_times[j]]
        return None

    def leaders_at(self, t, col, n=3, unit=""):
        rows = [r for r in (self.minute_at(t) or []) if r[2] not in ("(all)",) and r[col] is not None]
        if col == 3:
            rows = [r for r in rows if r[1] > 0]
            key = lambda r: r[3] / r[1]                   # noqa: E731
            fmt = lambda r: "%s (%s)" % (r[2], cores(r[3] / r[1]))                 # noqa: E731
        else:
            key = lambda r: r[col]                        # noqa: E731
            fmt = lambda r: "%s (%s)" % (r[2], mb(r[col]) if unit == "MB" else "%.0f %%" % r[col])  # noqa: E731
        return [fmt(r) for r in sorted(rows, key=key, reverse=True)[:n] if key(r) > 0]


def cores(c):
    return ("%.1f cores" % c) if c >= 1.5 else "a core flat out" if c >= 0.9 else "%d %% of a core" % round(100 * c)


# the checks ----------------------------------------------------------------------------------------------------------

PROBLEM_ADVICE = [
    (r"The PawnIO driver isn't",
     ["Run Install.cmd again (from the folder you installed from) and answer yes when it offers to install PawnIO: it "
      "installs the driver, then starts HW Blackbox again with the settings and history kept. PawnIO is the signed "
      "driver LibreHardwareMonitor reads the CPU's and the board's sensors through.",
      "Or install it yourself, in a terminal run as admin: winget install namazso.PawnIO (or its installer from "
      "github.com/namazso/PawnIO.Setup/releases), then restart the PC, or only HW Blackbox's service (as admin: "
      "Restart-Service HWBlackbox)."]),
    (r"didn't answer when the service started",
     ["Restart the service, as admin: Restart-Service HWBlackbox (or restart the PC).",
      "If it stays missing, another monitoring program may be holding the chip: close it and restart the service."]),
    (r"aren't logging|haven't started|No rail voltages|No CPU temperature|PawnIO",
     ["Check the PawnIO driver is installed (it reads the CPU and board sensors): winget install namazso.PawnIO.",
      "Restart the service, as admin: Restart-Service HWBlackbox (or restart the PC)."]),
    (r"No CPU readings for",
     ["Another program keeping a core busy at a higher priority holds the CPU's sensors up: see the busy-program "
      "findings here.", "If no program is busy, restart the service, as admin: Restart-Service HWBlackbox."]),
    (r"session agent isn't running",
     ["Open HW Blackbox from the Start menu, or sign out and back in: the agent starts at sign-in."]),
    (r"[Pp]ort", ["The Ports tab shows which program holds the port, and since when."]),
    (r"stuck", ["The service ends itself and Windows starts it again within 3 minutes. If it keeps happening, crash.log "
                "in C:\\ProgramData\\HWBlackbox says where."]),
    (r"config\.json", ["Fix the setting it names in config.json; until then that setting has its default."]),
    (r"event logs", ["Restart the service, as admin: Restart-Service HWBlackbox. If it stays, check that the Windows "
                     "Event Log service is running (services.msc)."]),
]
DISK_PROBLEM = re.compile(r"is filling up fast|has only [\d.]+ GB free")


def check_problems(x):
    if x.status_age is None or x.status_age > 180:
        return finding("problems", "HW Blackbox's service", "bad", "The service isn't reporting", "now",
                       ["Its status file is %s." % ("missing" if x.status_age is None else
                                                    "%s old" % span(x.status_age))],
                       ["Start it: Services (services.msc) → HW Blackbox → Start, or restart the PC.",
                        "If it won't stay running, run Install.cmd again: it repairs the install and keeps the data."],
                       "#overview")
    probs = [p for p in x.status.get("problems") or [] if not DISK_PROBLEM.search(p)]
    if not probs:
        return finding("problems", "Problems right now", "ok", "None: every part of HW Blackbox is working", "now")
    advice = []
    for p in probs:
        for pat, adv in PROBLEM_ADVICE:
            if re.search(pat, p):
                advice.extend(a for a in adv if a not in advice)
                break
    return finding("problems", "Problems right now", "bad", probs[0] if len(probs) == 1 else
                   "%d problems" % len(probs), "now", probs, advice, "#overview")


def check_power_offs(x):
    rows = []
    for p in x.power_offs:
        t = parse_iso(p.get("went_down") or "") or parse_iso(p.get("boot") or "")
        if t:
            rows.append((t, p))
    month = [r for r in rows if x.now - r[0] <= 30 * DAY]
    week = [r for r in month if x.now - r[0] <= 7 * DAY]
    if not month:
        last = max(rows)[0] if rows else None
        return finding("power", "Power-offs", "ok", "None in the last 30 days" + (
            " (the last: %s)" % when(last, x.now) if last else ""), "the last 30 days", link="#power")
    seen, whys = [], set()
    for t, p in sorted(month, key=lambda r: r[0]):
        r = p.get("last_rails") or {}
        why = p.get("why") or ""
        whys.add("crash" if why.startswith("Windows crashed") else "button" if "power button" in why else
                 "sleep" if "sleep" in why else "flat" if FLAT.match(p.get("battery") or "") else "none")
        bits = [why or None,
                "off for %s" % span(p["gap_s"]) if p.get("gap_s") else None,
                "battery %s" % p["battery"] if p.get("battery") else None,
                "+12 V %.3f" % r["v12_v"] if r.get("v12_v") else None,
                "CPU %.0f W" % r["cpu_power_w"] if r.get("cpu_power_w") else None]
        seen.append("%s: %s" % (when(t, x.now), ", ".join(b for b in bits if b) or "no readings before it"))
    portable = (x.status.get("sensors") or {}).get("portable")
    advice = []
    if "crash" in whys:
        advice += ["A blue screen: look up its stop code (Microsoft's \"Bug check code reference\"). Update the graphics, "
                   "chipset and storage drivers and the BIOS; if they keep coming, test the memory (run mdsched.exe) "
                   "and undo any overclock (XMP / EXPO off)."]
    if "button" in whys:
        advice += ["Held down on the power button: if the PC had frozen first, the freeze is what to chase (the "
                   "report's last readings, and the Events tab just before it). If it was only a quick way off, there's "
                   "nothing wrong."]
    if "sleep" in whys:
        advice += ["Going to sleep or waking up: update the graphics, chipset and Wi-Fi drivers and the BIOS; if it "
                   "keeps happening, turn off fast startup and hibernation to see if it stops."]
    if "flat" in whys:
        advice += ["The battery ran out: Windows should hibernate before that. If it doesn't, the battery's gauge is "
                   "off (it's worn): see its wear in powercfg /batteryreport, and set the critical battery action to "
                   "hibernate in the power options."]
    if "none" in whys and portable:
        advice += ["Windows recorded no reason, which on a laptop is a battery that ran out, a hard freeze, or a power "
                   "cut it couldn't ride out (a worn battery that can't hold the load). The report's last readings say "
                   "which: the battery's charge and whether it was plugged in, the CPU's power and temperature."]
    elif "none" in whys:
        advice += ["Windows recorded no reason: the power was cut, or the PC froze too hard to record anything. Check "
                   "the power cables at both ends, and anything between the wall and the PC (a power strip, a UPS and "
                   "its battery).",
                   "A power supply that trips under load cuts out within milliseconds, so steady rails up to the last "
                   "reading don't clear it. If it went off under heavy load (a game, a render), the supply is the "
                   "first suspect; if it went off while idle, the wall power, the UPS, and anything changed in the "
                   "BIOS."]
    advice.append("Each one has a report on the Incidents tab, with the last readings before it.")
    return finding("power", "Power-offs", "bad" if len(week) >= 2 else "warn",
                   "%d in the last 30 days%s" % (len(month), " (%d this week)" % len(week) if week else ""),
                   "the last 30 days", seen, advice, "#power")


FLAT = re.compile(r"[0-5](?:\.\d+)? %, on battery")       # (the last sample before it: 5 % or less, unplugged)


def check_crashes(x):
    week = [r for r in x.records if r.get("t") and x.now - r["t"] <= 7 * DAY]
    crashes = collections.defaultdict(list)
    memory_like = set()
    exits = [(r["t"], (r.get("exe") or "").lower()) for r in week
             if r.get("kind") == "exit" and "crash" in (r.get("meaning") or "")]
    for r in week:
        if r.get("kind") == "exit" and "crash" in (r.get("meaning") or ""):
            app = r.get("app") or r.get("exe") or "?"
            crashes[app].append((r["t"], r.get("meaning")))
            if (r.get("code") or "").upper() in ("0XC0000005", "0XC0000374"):
                memory_like.add(app.lower())
        elif r.get("kind") == "winevent" and r.get("source") == "Application Error":
            ins = r.get("inserts") or []
            exe = str(ins[0] if ins else "").lower()
            if any(e == exe and abs(t - r["t"]) <= 120 for t, e in exits):
                continue                     # (a watched app's crash: its exit record already counted it)
            app = r.get("app") or (ins[0] if ins else "?")
            # which program's exe it was (a python.exe can be anyone's: QGIS's, a game's, a tool's), and the part of
            # it that crashed when that's another file (gdal313.dll)
            prog = r.get("program")
            if prog and prog.lower() not in app.lower():
                app = "%s (%s)" % (app, prog)
            module = str(ins[3]) if len(ins) > 3 else ""
            code = next((i for i in ins if re.fullmatch(r"0x[0-9a-fA-F]{8}", str(i))), "")
            crashes[app].append((r["t"], "Windows recorded a crash" +
                                 (" in %s" % module if module and module.lower() not in (exe, "unknown") else "") +
                                 (" (%s)" % code if code else "")))
            if code.lower() in ("0xc0000005", "0xc0000374"):
                memory_like.add(app.lower())
    if not crashes:
        return finding("crashes", "Programs crashing", "ok", "No crashes in the last 7 days", "the last 7 days",
                       link="#events")
    seen = ["%s: %d (the last %s, %s)" % (app, len(v), when(max(v)[0], x.now), max(v)[1])
            for app, v in sorted(crashes.items(), key=lambda kv: -len(kv[1]))]
    advice = ["Update the program that crashes, or reinstall it.",
              "Its report on the Incidents tab has the exit code and what else was happening."]
    level = "warn" if any(len(v) >= 2 for v in crashes.values()) else "info"
    if len(memory_like) >= 3:
        level = "warn"
        advice.insert(0, "Several different programs crashing the same way points at the PC rather than at one "
                         "program: test the memory (Windows Memory Diagnostic: run mdsched.exe; or MemTest86), and "
                         "put the memory and CPU back to stock speeds (XMP / EXPO off, no overclock) to see if it "
                         "stops.")
    n = sum(len(v) for v in crashes.values())
    return finding("crashes", "Programs crashing", level, "%d crash%s in the last 7 days, %d program%s" % (
        n, "" if n == 1 else "es", len(crashes), "" if len(crashes) == 1 else "s"), "the last 7 days", seen, advice,
        "#events")


HW_ADVICE = {
    "CPU": ["Put the CPU back to its stock settings: undo any overclock or undervolt (PBO and Curve Optimizer on AMD, "
            "XTU or ThrottleStop on Intel), then see if the errors stop.",
            "Update the BIOS: many CPU errors are fixed by the microcode in a newer one.",
            "Check the CPU's temperature (below) and that its cooler sits firmly."],
    "memory": ["Test the memory: Windows Memory Diagnostic (run mdsched.exe) or MemTest86 (free, from a USB stick).",
               "Turn XMP / EXPO off in the BIOS (the memory at its standard speed) and see if the errors stop. If they "
               "do, the memory's rated speed isn't stable on this board: a slower profile, or a little more voltage, "
               "is the usual fix."],
    "PCI Express": ["Power off, unplug, and reseat the graphics card and the NVMe drives; check the card's power cables "
                    "are firmly in at both ends.",
                    "Update the BIOS and the chipset driver.",
                    "If they keep coming from one slot, setting that slot one PCIe generation lower in the BIOS (Gen 4 "
                    "to Gen 3) often stops them, at no cost you'd notice."],
    None: ["Update the BIOS and the chipset driver, and put the CPU and memory back to stock (no overclock, XMP / EXPO "
           "off) to see if they stop."],
}


def check_hardware(x):
    """The hardware's own error reports (WHEA): a corrected error did no harm but is a sign of a part (or a setting)
    on the edge; a fatal one took Windows down (a blue screen, stop code 0x124)."""
    from .events import WHEA, WHEA_SHORT, hardware_error
    recs = sorted((r["t"], hardware_error(r), r) for r in x.records if r.get("kind") == "winevent" and
                  r.get("source") == WHEA and r.get("t") and x.now - r["t"] <= 7 * DAY)
    if not recs:
        return finding("hardware", "Hardware errors", "ok", "None in the last 7 days", "the last 7 days",
                       link="#events")
    parts = collections.OrderedDict()
    for t, (part, fatal), r in recs:
        p = parts.setdefault(part, {"fatal": 0, "corrected": 0, "last": t})
        p["fatal" if fatal else "corrected"] += 1 + int(r.get("skipped_before") or 0)
        p["last"] = t
    fatal = sum(p["fatal"] for p in parts.values())
    seen = ["%s: %s (the last %s)" % (WHEA_SHORT[part][0].upper() + WHEA_SHORT[part][1:], ", ".join(
        "%d %s" % (p[k], k) for k in ("fatal", "corrected") if p[k]), when(p["last"], x.now))
        for part, p in parts.items()]
    advice = []
    for part in parts:
        advice.extend(a for a in HW_ADVICE.get(part, HW_ADVICE[None]) if a not in advice)
    advice.append("A corrected error did no harm, but a part that keeps needing it is on the edge; a fatal one crashes "
                  "Windows. Each one is on the Events tab (Hardware), with Windows' own record of it.")
    n = sum(p["fatal"] + p["corrected"] for p in parts.values())
    return finding("hardware", "Hardware errors", "bad" if fatal else "warn",
                   "%d hardware error%s in the last 7 days%s" % (n, "" if n == 1 else "s",
                                                                 ", %d fatal" % fatal if fatal else ""),
                   "the last 7 days", seen, advice, "#events")


def check_drives(x):
    """The drives: what Windows thinks of each, its wear, its temperature, the errors it has counted (and whether
    they grew this month), and the drives' error records of the last week."""
    from .events import disk_error
    drives = [d for d in (x.drives.get("drives") or []) if isinstance(d, dict)]
    model = {d.get("disk"): d.get("model") for d in drives}
    errs = []
    for r in x.records:
        if r.get("kind") == "winevent" and r.get("t") and x.now - r["t"] <= 7 * DAY:
            got = disk_error(r)
            if got:
                errs.append((r["t"], got, int(r.get("skipped_before") or 0)))
    if not drives and not errs:
        return None
    level, seen, advice = "ok", [], []
    rank = lambda lv: ORDER[lv]                                           # noqa: E731

    def worse(lv):
        nonlocal level
        if rank(lv) < rank(level):
            level = lv

    def add(*tips):
        advice.extend(t for t in tips if t not in advice)
    BACKUP = "Back up what's on it now (copy what matters to another drive or the cloud)."
    first = {}                                        # disk -> its oldest row of the month (the counters then)
    for t, disk, vals in sorted(x.drive_rows):
        first.setdefault(disk, vals)
    for d in drives:
        disk, bits = d.get("disk"), [d.get("health") or "unknown"]
        name = "Disk %s (%s)" % (disk, d.get("model") or "?")
        hot = 70 if d.get("media") != "HDD" else 55
        if d.get("temp_c"):
            bits.append("%d °C" % d["temp_c"])
        if d.get("wear_pct") is not None:
            bits.append("%d %% worn" % d["wear_pct"])
        if d.get("power_on_h"):
            bits.append("%s on" % span(d["power_on_h"] * 3600))
        unc = (d.get("read_err_unc") or 0) + (d.get("write_err_unc") or 0)
        before = first.get(disk) or {}
        grew = unc - ((before.get("read_err_unc") or 0) + (before.get("write_err_unc") or 0)) if before else 0
        if unc:
            bits.append("%d errors it couldn't correct%s" % (unc, " (+%d this month)" % grew if grew > 0 else ""))
        seen.append("%s: %s" % (name, ", ".join(bits)))
        if d.get("health") == "unhealthy":
            worse("bad")
            add(BACKUP, "Then replace it: Windows itself says it's failing (its own health check, from the drive's "
                        "SMART data).")
        elif d.get("health") == "warning":
            worse("warn")
            add(BACKUP, "Windows says it needs a look: see its maker's tool (Samsung Magician, WD Dashboard, Crucial "
                        "Storage Executive, SeaTools...) for what it reports.")
        if grew > 0:
            worse("bad")
            add(BACKUP, "Its count of errors it couldn't correct is growing: replace it.")
        elif unc:
            worse("info")
        if d.get("wear_pct") is not None and d["wear_pct"] >= 100:
            worse("warn")
            add(BACKUP, "It has written all it was rated for: it may go on for a long time, but keep its data backed "
                        "up and plan to replace it.")
        elif d.get("wear_pct") is not None and d["wear_pct"] >= 80:
            worse("info")
            add("It's used most of the writes it's rated for: plan to replace it in time.")
        if d.get("temp_c") and d["temp_c"] >= hot:
            worse("warn")
            add("It runs hot: give it airflow (an NVMe drive's heatsink, a case fan over it), and keep it away from "
                "the graphics card's exhaust.")
    by_disk = collections.defaultdict(list)
    for t, (what, lv, disk), more in errs:
        by_disk[disk].append((t, what, lv, more))
    for disk, rows in by_disk.items():
        n = sum(1 + more for _t, _w, _lv, more in rows)
        bad = [r for r in rows if r[2] == "bad"]
        t, what, _lv, _m = max(rows)
        name = "Disk %s (%s)" % (disk, model.get(disk) or "?") if disk is not None else "A drive"
        seen.append("%s: %d error record%s this week; the last, %s: %s" % (name, n, "" if n == 1 else "s",
                                                                          when(t, x.now), what))
        worse("bad" if bad else "warn" if n >= 3 else "info")
        if bad:
            add(BACKUP, "Then check it: in a terminal run as admin, chkdsk C: /scan (with the drive's letter), and its "
                        "maker's tool for its SMART health.")
        else:
            add("Retries and resets come from the drive, its cable or its port: reseat it (a SATA drive: another cable "
                "and port), and update its firmware with its maker's tool and the storage or chipset driver.")
    worst = next((s for s in seen if "unhealthy" in s or "couldn't correct" in s), None)
    healthy = sum(1 for d in drives if d.get("health") == "healthy")
    summary = ("%d drive%s, all healthy" % (len(drives), "" if len(drives) == 1 else "s") if level == "ok" else
               worst or ("%d error record%s from the drives this week" % (
                   sum(1 + m for _t, _g, m in errs), "" if len(errs) == 1 else "s") if errs else
                   "%d of %d drives healthy" % (healthy, len(drives))))
    if x.drives.get("error") and not any(d.get("temp_c") or d.get("wear_pct") is not None for d in drives):
        seen.append("Their temperature and wear couldn't be read: %s" % x.drives["error"])
    return finding("drives", "Drives", level, summary, "now, and the last 7 days' records", seen, advice, "#events")


def check_display_resets(x):
    resets = sorted(r["t"] for r in x.records if r.get("kind") == "winevent" and r.get("source") == "Display" and
                    r.get("id") == 4101 and r.get("t") and x.now - r["t"] <= 7 * DAY)
    if not resets:
        return finding("display", "The graphics driver", "ok", "No driver resets in the last 7 days", "the last 7 days")
    return finding("display", "The graphics driver", "bad" if len(resets) >= 3 else "warn",
                   "It stopped responding and was reset %d time%s" % (len(resets), "" if len(resets) == 1 else "s"),
                   "the last 7 days", ["%s: Windows reset the display driver (Display 4101)" % when(t, x.now)
                                       for t in resets[-6:]],
                   ["Update the graphics driver. If it started after an update, go back to the one before (a clean "
                    "install: DDU, in safe mode).",
                    "Check the GPU's temperature (below) and its power cables (firmly in at both ends).",
                    "Undo any GPU overclock or undervolt."], "#events")


def check_temperature(x, col, part, warn, bad, prog_col, advice):
    s = x.series(col)
    if not s:
        return None
    t_hot, hot = max(s, key=lambda p: p[1])
    over = sum(1 for _t, v in s if v >= warn) * 5.0                       # (a row every 5 s)
    level = "bad" if hot >= bad else "warn" if over >= 300 else "ok"
    summary = "Hottest %.0f °C at %s" % (hot, when(t_hot, x.now))
    if level == "ok":
        return finding(col, "%s temperature" % part, "ok", summary, "the last 24 hours",
                       link="#charts:24:%s" % col)
    seen = [summary + (" (the busiest then: %s)" % ", ".join(x.leaders_at(t_hot, prog_col, 2, "%"))
                       if x.leaders_at(t_hot, prog_col, 2, "%") else ""),
            "%s at %d °C or more" % (span(over), warn) if over else "Only briefly above %d °C" % warn]
    return finding(col, "%s temperature" % part, level, summary, "the last 24 hours", seen, advice,
                   "#charts:24:%s" % col)


CPU_HEAT = ["Clean the dust out of the CPU cooler and the case's filters.",
            "Check the CPU fan spins, and its fan curve in the BIOS.",
            "If the cooler was fitted or moved recently: its mounting and the thermal paste.",
            "Brief peaks under full load are normal for modern CPUs; hot while idle is the worry."]
GPU_HEAT = ["Clean the GPU's fans and heatsink, and make sure the case draws air through.",
            "Check the GPU's fan curve (the maker's app, or MSI Afterburner).",
            "Cap the frame rate in games (or turn on V-Sync): it cuts the heat a lot."]


def check_rails(x):
    nominal = {"v12_v": ("+12 V", 12.0), "v5_v": ("+5 V", 5.0), "v33_v": ("+3.3 V", 3.3)}
    seen, level, have = [], "ok", False
    for col, (name, nom) in nominal.items():
        s = [v for _t, v in x.series(col)]
        if not s:
            continue
        have = True
        lo, hi = min(s), max(s)
        off = max(abs(lo - nom), abs(hi - nom)) / nom * 100
        line = "%s: %.3f to %.3f V (%.1f %% off at most)" % (name, lo, hi, off)
        if off > 5:
            level = "bad"
            seen.append(line + ": outside the ATX limit of 5 %")
        elif (hi - lo) / nom * 100 > 4 and level != "bad":
            level = "warn"
            seen.append(line + ": it moves a lot")
        else:
            seen.append(line)
    if not have:
        return None
    if level == "ok":
        return finding("rails", "Power supply rails", "ok", "All within the ATX limits (5 %)", "the last 24 hours",
                       link="#power")
    return finding("rails", "Power supply rails", level, "A rail outside the limits" if level == "bad" else
                   "A rail that moves a lot", "the last 24 hours", seen,
                   ["The board's sensors can be a few percent off: measure the rail with a multimeter (a spare SATA "
                    "or Molex plug) before replacing anything.",
                    "If the multimeter agrees, the power supply is out of spec: replace it.",
                    "Reseat the 24-pin and the CPU's 8-pin power plugs."], "#power")


def check_busy(x):
    out = []
    for prog, rows in x.by_program.items():
        if prog == "(all)":
            continue
        busy = [r for r in rows if r[1] > 0 and r[3] / r[1] >= 0.9]
        known = KNOWN.get(prog)
        need = (known.get("busy_min", BUSY_MIN) if known else BUSY_MIN_APP)
        mins = sum(r[1] for r in busy) / 60.0
        if mins < need:
            continue
        # the longest stretch (minutes no more than 3 apart)
        runs, cur = [], []
        for r in sorted(busy):
            if cur and r[0] - cur[-1][0] > 180:
                runs.append(cur)
                cur = []
            cur.append(r)
        runs.append(cur)
        best = max(runs, key=len)
        seen = ["A core flat out (or more) for %s in the last 24 hours" % span(mins * 60),
                "The longest stretch: %s to %s" % (when(best[0][0] - best[0][1], x.now), when(best[-1][0], x.now))]
        peak = max(rows, key=lambda r: r[3] / r[1] if r[1] else 0)
        if peak[1]:
            seen.append("At its busiest: %s (pid %s)" % (cores(peak[3] / peak[1]), peak[8] or "?"))
        if known:
            seen.insert(0, "%s is %s." % (prog, known["what"]))
            advice = known.get("busy") or [FRESH_START]
            level = "warn"
        else:
            advice = ["Expected if it was working (a game, a render, a build). If it should have been idle, close it, "
                      "or end it in Task Manager.", "If it keeps happening, look for an update to it."]
            level = "info"
        out.append(finding("busy:" + prog, "%s kept the CPU busy" % prog, level,
                           "A core flat out for %s" % span(mins * 60), "the last 24 hours", seen, advice,
                           "#processes:cpu"))
    if not out:
        return [finding("busy", "Programs keeping the CPU busy", "ok", "None: no program held a core for long" if
                        x.programs else "Not enough history yet (it's logged every minute)", "the last 24 hours",
                        link="#processes:cpu")]
    return out


def check_memory(x):
    out = []
    ends = [x.minute_times[-1]] if x.minute_times else []
    ends += [s[-1][0] for s in x.watched_mem.values() if s]
    latest = max(ends) if ends else None
    for prog in set(x.by_program) | set(x.watched_mem):
        if prog in ("(all)", "System interrupts"):
            continue
        s = [(r[0], r[4]) for r in x.by_program.get(prog, []) if r[4] is not None]
        # The watched apps' own minute records go further back (before the programs log began, say). They count only
        # the app's main process, though, where the programs log counts all of its processes: joined only where the
        # two agree (an app of one process, like Explorer), or a browser's other processes would look like a leak.
        w = x.watched_mem.get(prog) or []
        if w and s:
            before = [p for p in w if p[0] < s[0][0] - 30]
            if before and abs(before[-1][1] - s[0][1]) <= max(64.0, 0.1 * s[0][1]):
                s = before + s
        elif w:
            s = w
        if len(s) < 30 or latest is None or s[-1][0] < latest - 180:
            continue
        early = [v for t, v in s if t <= s[0][0] + 3600]
        start = statistics.median(early) if early else s[0][1]
        now = s[-1][1]
        top = max(v for _t, v in s)
        if not (now - start >= GROWN_MB and now >= 2 * start and now >= 0.9 * top):
            continue
        jumps = [(s[i][0], s[i][1] - s[i - 1][1]) for i in range(1, len(s)) if s[i][1] - s[i - 1][1] >= 300]
        seen = ["From %s to %s since %s" % (mb(start), mb(now), when(s[0][0], x.now))]
        if jumps:
            seen.append("It grew in jumps: " + ", ".join("%s (+%s)" % (when(t, x.now), mb(d))
                                                         for t, d in sorted(jumps, key=lambda j: -j[1])[:4]))
            screens = [t for t, _d in jumps if any(0 <= t - s_t <= 180 for s_t in x.displays)]
            if screens:
                seen.append("%s right after the screens changed (a remote session, a monitor, the resolution or "
                            "scaling)" % ("Each jump came" if len(screens) == len(jumps) else
                                          "%d of the jumps came" % len(screens)))
        known = KNOWN.get(prog)
        if known:
            seen.insert(0, "%s is %s." % (prog, known["what"]))
        advice = (known or {}).get("memory") or [
            "Close and reopen it to get the memory back.",
            "If it grows again, it's leaking: look for an update to it, or tell its maker."]
        level = "warn" if known or now - start >= 2 * GROWN_MB else "info"
        out.append(finding("memory:" + prog, "%s keeps growing" % prog, level,
                           "Its memory went from %s to %s" % (mb(start), mb(now)), "the last 24 hours", seen, advice,
                           "#processes:mem"))
    if not out:
        return [finding("memory", "Programs' memory", "ok", "No program's memory kept growing" if x.programs else
                        "Not enough history yet (it's logged every minute)", "the last 24 hours", link="#processes:mem")]
    return out


def check_ram(x):
    s = x.series("ram_pct")
    low = sorted(r["t"] for r in x.records if r.get("kind") == "winevent" and
                 r.get("source") == "Microsoft-Windows-Resource-Exhaustion-Detector" and r.get("t") and
                 x.now - r["t"] <= 7 * DAY)
    if not s and not low:
        return None
    total = x.sensor("Psutil/ram_total_gb")
    t_hi, hi = max(s, key=lambda p: p[1]) if s else (None, None)
    over = sum(1 for _t, v in s if v >= 90) * 5.0
    level = "bad" if low or sum(1 for _t, v in s if v >= 95) * 5.0 >= 300 else "warn" if over >= 900 else "ok"
    summary = "Highest %.0f %%%s" % (hi, " of %.1f GB" % total if total else "") if hi is not None else \
        "Windows ran low on memory"
    if level == "ok":
        return finding("ram", "Memory (RAM)", "ok", summary, "the last 24 hours", link="#charts:24:ram_pct")
    seen = []
    if hi is not None:
        seen.append("%s at %s; %s at 90 %% or more" % (summary, when(t_hi, x.now), span(over) if over else "none"))
        big = x.leaders_at(t_hi, 4, 4, "MB")
        if big:
            seen.append("The biggest then: " + ", ".join(big))
    seen.extend("%s: Windows ran low on memory (Resource-Exhaustion-Detector 2004)" % when(t, x.now) for t in low[-4:])
    return finding("ram", "Memory (RAM)", level, summary, "the last 24 hours (7 days for low-memory warnings)", seen,
                   ["Close what you don't need: the biggest programs are listed above, and on the Processes tab.",
                    "If one program keeps growing, see its finding here: restarting it gets the memory back.",
                    "Leave the page file to Windows: Settings → System → About → Advanced system settings → "
                    "Performance → Settings → Advanced → Virtual memory → Automatically manage.",
                    "If it's just normal use, more RAM is the fix."], "#charts:24:ram_pct")


def check_vram(x):
    s = x.series("gpu_vram_mb")
    total = x.sensor("Nvml/gpu_vram_total_mb")
    if not s or not total:
        return None
    t_hi, hi = max(s, key=lambda p: p[1])
    over = sum(1 for _t, v in s if v >= 0.9 * total) * 5.0
    summary = "Highest %s of %s (%.0f %%)" % (mb(hi), mb(total), 100 * hi / total)
    if over < 600:
        return finding("vram", "Graphics memory", "ok", summary, "the last 24 hours", link="#charts:24:gpu_vram_mb")
    seen = ["%s at 90 %% or more" % span(over)]
    big = x.leaders_at(t_hi, 5, 4, "MB")
    if big:
        seen.append("The biggest users then: " + ", ".join(big))
    return finding("vram", "Graphics memory", "warn", summary, "the last 24 hours", seen,
                   ["Lower the game's texture quality or resolution.",
                    "Close programs holding graphics memory in the background (a browser playing video, Discord, OBS): "
                    "GPU memory on the Processes tab lists them."], "#processes:vram")


def battery_sensor(x, name):
    """A laptop battery's reading from LibreHardwareMonitor ("Designed Capacity", "Fully-Charged Capacity" in mWh,
    "Degradation Level" in %), or None."""
    for s in x.sensors:
        if isinstance(s, dict) and str(s.get("id", "")).split("/")[0].split("#")[0] == "Battery" and \
                s.get("name") == name and isinstance(s.get("value"), (int, float)):
            return s["value"]
    return None


def battery_use(x):
    """The last day on battery, from the 5-second log: (hours on battery, %/hour drained, (t, lowest %) or None).
    A stretch on battery is unbroken rows unplugged (a gap over a minute, a sleep, ends it); the drain counts the
    stretches of 10 minutes or more."""
    ac = dict(x.series("on_ac"))
    rows = [(t, v) for t, v in x.series("battery_pct") if ac.get(t) == 0]
    hours = drop = drop_h = 0.0
    low = None
    run = []
    for t, v in rows + [(None, None)]:
        if run and (t is None or t - run[-1][0] > 60):
            length = run[-1][0] - run[0][0]
            hours += length / 3600
            if length >= 600 and run[0][1] > run[-1][1]:
                drop += run[0][1] - run[-1][1]
                drop_h += length / 3600
            run = []
        if t is not None:
            run.append((t, v))
            if low is None or v < low[1]:
                low = (t, v)
    return hours, (drop / drop_h if drop_h >= 0.25 else None), low


def check_battery(x):
    """A laptop's battery: how much of its charge it still holds (its wear), how fast it drained on battery over the
    last day, and how low it ran. Desktops have none: no finding."""
    designed, full = battery_sensor(x, "Designed Capacity"), battery_sensor(x, "Fully-Charged Capacity")
    wear = None
    if designed and full and designed > 0 and 0 < full <= designed * 1.2:
        wear = max(0.0, 100.0 * (1 - full / designed))
    elif battery_sensor(x, "Degradation Level") is not None:
        wear = max(0.0, float(battery_sensor(x, "Degradation Level")))
    pct = x.series("battery_pct")
    if wear is None and not pct:
        return None
    hours, rate, low = battery_use(x)
    seen, advice, level = [], [], "ok"
    if wear is not None:
        seen.append(("Holds %.0f Wh of the %.0f Wh it was made for: %.0f %% worn" % (full / 1000, designed / 1000, wear))
                    if designed and full and designed > 0 and 0 < full <= designed * 1.2 else "%.0f %% worn" % wear)
        summary = "Holds %.0f %% of the charge it held new" % (100 - wear)
        if wear >= 40:
            level = "warn"
            advice += ["It holds well under what it was made for: plan to replace it (the maker's own part, or one made "
                       "for this exact model).",
                       "Until then, keep it plugged in for long work: a worn battery can cut out suddenly near empty, "
                       "before Windows' low-battery warning."]
        elif wear >= 20:
            level = "info"
            advice += ["Normal for a battery a few years old. To slow it down: if the laptop's BIOS or its maker's app "
                       "has a charge limit (\"battery charge limit\", \"conservation mode\"), set it to about 80 %, and "
                       "keep the laptop out of the heat."]
    else:
        summary = "Its charge is logged; it doesn't report its wear"
    if hours >= 0.1:
        line = "On battery for %s in the last 24 hours" % span(hours * 3600)
        if rate:
            line += ", draining about %.0f %% an hour: a full charge would last about %s at that rate" % (
                rate, span(max(600, round(100 / rate * 6) * 600)))           # (an estimate: to 10 minutes)
        seen.append(line)
    if low and low[1] <= 5:
        seen.append("Ran down to %.0f %% on battery at %s" % (low[1], when(low[0], x.now)))
        if level == "ok":
            level = "info"
        advice.append("It ran nearly empty: set what Windows does at its critical level to Hibernate (Control Panel → "
                      "Power Options → Change plan settings → Change advanced power settings → Battery → Critical "
                      "battery action), so running out never loses work.")
    if pct:
        ac = dict(x.series("on_ac"))
        t, v = pct[-1]
        state = {1: "plugged in", 0: "on battery"}.get(ac.get(t))
        seen.append("Now %.0f %%" % v + (", " + state if state else ""))
    if level != "ok":
        advice.append("Its whole history: run powercfg /batteryreport in a terminal; it writes battery-report.html, with "
                      "the capacity it held over the months.")
    return finding("battery", "Battery", level, summary, "now and the last 24 hours", seen, advice,
                   "#charts:24:battery_pct")


def check_disk(x):
    pc = x.status.get("pc") or {}
    warn = x.cfg.get("disk_warn_gb") or 10
    sysd = [d for d in pc.get("disks") or [] if str(d.get("mount", "")).upper().startswith("C:")]
    if not sysd:
        return None
    d = sysd[0]
    free, total = d.get("free_gb") or 0, d.get("total_gb") or 0
    fast = [p for p in x.status.get("problems") or [] if "filling up fast" in p]
    summary = "%.0f GB free of %.0f GB" % (free, total)
    level = "bad" if free < warn else "warn" if fast or (total and free < 0.1 * total) or free < 2 * warn else "ok"
    if level == "ok":
        return finding("disk", "Space on C:", "ok", summary, "now", link="#charts:168:disk:C:")
    return finding("disk", "Space on C:", level, summary, "now", fast or [summary],
                   ["Settings → System → Storage → Temporary files (or Disk Cleanup → Clean up system files).",
                    "Turn on Storage Sense, so Windows keeps it clean.",
                    "Move or delete big folders (Downloads, old installers, game libraries): WizTree or WinDirStat "
                    "(free) shows what's big."], "#charts:168:disk:C:")


def check_update(x):
    text = (x.status.get("attributes") or {}).get("windows_update") or ""
    m = re.match(r"waiting for a restart since (\d{4}-\d\d-\d\d \d\d:\d\d)", text)
    if not m:
        return finding("update", "Windows Update", "ok", "No update waiting for a restart", "now")
    since = dt.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M").timestamp()
    return finding("update", "Windows Update", "warn" if x.now - since > 2 * DAY else "info",
                   "An update has been waiting for a restart for %s" % span(x.now - since), "now", [text],
                   ["Restart when it suits you: the update finishes then."])


def check_uptime(x):
    boot = (x.status.get("pc") or {}).get("boot_epoch")
    if not boot:
        return None
    up = x.now - boot
    if up < 14 * DAY:
        return finding("uptime", "Uptime", "ok", "Up for %s" % ("%d days" % (up // DAY) if up >= 2 * DAY else
                                                                 span(up)), "now")
    return finding("uptime", "Uptime", "info", "Up for %d days" % (up // DAY), "now", [],
                   ["Restart now and then: it gets back memory that programs have grown into, and finishes updates."])


def run(d):
    x = Inputs(d)
    checks = []
    steps = [check_problems, check_power_offs, check_hardware, check_crashes, check_display_resets, check_drives,
             lambda x: check_temperature(x, "cpu_temp_c", "CPU", 85, 95, 3, CPU_HEAT),
             lambda x: check_temperature(x, "gpu_temp_c", "GPU", 83, 90, 6, GPU_HEAT),
             check_rails, check_busy, check_memory, check_ram, check_vram, check_battery, check_disk, check_update,
             check_uptime]
    for step in steps:
        try:
            got = step(x)
        except Exception as e:                       # (a check that can't run says so; the rest still do)
            got = finding("error", "A check couldn't run", "info", "%s: %s" % (type(e).__name__, e), "now")
        if got:
            checks.extend(got if isinstance(got, list) else [got])
    checks.sort(key=lambda c: ORDER.get(c["level"], 9))
    counts = collections.Counter(c["level"] for c in checks)
    return {"checks": checks, "counts": dict(counts), "at": x.now}
