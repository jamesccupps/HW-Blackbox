r"""A made-up HW Blackbox data folder, for screenshots and for trying the dashboard: three days of a desktop's logs
(evenings of gaming, idle nights, one power-off, one app crash, a restart), its records, reports, sensors and ports.
Nothing in it comes from a real PC.

  python tools\make_demo.py --out demo [--live 120]
  python -m hwblackbox serve --data-dir demo           (then http://127.0.0.1:9079/)

--live N keeps it "live" for N seconds: rows keep coming at 5 s and 4 a second, the status and the agent's heartbeat
stay fresh, as with a running service."""
import argparse
import csv
import datetime as dt
import json
import math
import os
import random
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from hwblackbox import VERSION  # noqa: E402
from hwblackbox.cpulog import COLUMNS as CPU_COLUMNS  # noqa: E402
from hwblackbox.disks import COLUMNS as DISK_COLUMNS  # noqa: E402
from hwblackbox.sensors import COLUMNS, FAST_COLUMNS  # noqa: E402

HOST, USER = "DEMO-PC", "alex"
CPU, BOARD, CHIP, GPU = "AMD Ryzen 7 7700X", "ASUS TUF GAMING B650-PLUS", "Nuvoton NCT6799D", "NVIDIA GeForce RTX 4070"
RAM_GB = 31.6
rnd = random.Random(7)


def q(v, step):
    """A reading in the sensor chip's steps (a +12 V rail moves in ~72 mV steps)."""
    return round(round(v / step) * step, 3)


class Machine:
    """What the PC is doing at a moment: idle at night, light use by day, games in the evening."""

    def __init__(self):
        self.wander = 0.0

    def state(self, t):
        h = t.hour + t.minute / 60
        if 19 <= h < 22.5:
            return "game"
        if 9 <= h < 19 or 22.5 <= h < 24.5 or h < 0.5:
            return "use"
        return "idle"

    def row(self, t):
        st = self.state(t)
        self.wander = max(-1, min(1, self.wander + rnd.uniform(-0.08, 0.08)))
        wave = math.sin(t.timestamp() / 97) * 0.5 + math.sin(t.timestamp() / 23) * 0.3
        load = {"idle": 3, "use": 18, "game": 46}[st] + wave * {"idle": 1.5, "use": 9, "game": 10}[st] + rnd.uniform(-2, 2)
        load = max(0.4, min(99, load))
        gpu = {"idle": 1, "use": 6, "game": 94}[st] + rnd.uniform(-3, 4)
        gpu = max(0, min(100, gpu))
        cpu_temp = 41 + load * 0.55 + self.wander * 2 + rnd.uniform(-0.6, 0.6)
        gpu_temp = 36 + gpu * 0.32 + self.wander + rnd.uniform(-0.4, 0.4)
        gpu_power = 12 + gpu * 1.8 + rnd.uniform(-3, 3)
        ram = {"idle": 11.2, "use": 15.0, "game": 20.5}[st] + wave + rnd.uniform(-0.2, 0.2)
        r = {c: "" for c in COLUMNS}
        r.update({
            "timestamp": t.isoformat(timespec="seconds"),
            "cpu_temp_c": round(cpu_temp, 1), "cpu_power_w": round(24 + load * 1.25 + rnd.uniform(-1, 1), 1),
            "vcore_v": round(min(1.35, 0.98 + load * 0.006 + rnd.uniform(-0.03, 0.03)), 3),
            "vsoc_v": q(1.25 + rnd.uniform(-0.004, 0.004), 0.008),
            "v12_v": q(12.12 - (0.06 if gpu > 80 and rnd.random() < 0.4 else 0) + rnd.uniform(-0.05, 0.05), 0.072),
            "v5_v": q(5.05 + rnd.uniform(-0.02, 0.02), 0.03), "v33_v": q(3.35 + rnd.uniform(-0.012, 0.012), 0.016),
            "board_temp_c": round(33 + load * 0.06 + self.wander * 0.5, 1),
            "gpu_temp_c": round(gpu_temp), "gpu_power_w": round(max(8, gpu_power), 1), "gpu_util_pct": round(gpu),
            "gpu_clock_mhz": 2745 if gpu > 50 else (1365 if gpu > 4 else 210),
            "gpu_vram_mb": round(8200 + rnd.uniform(-600, 600) if st == "game" else 1150 + rnd.uniform(-200, 300)),
            "cpu_load_pct": round(load, 1), "ram_used_gb": round(ram, 2), "ram_pct": round(ram / RAM_GB * 100, 1),
            "fans": "CPU Fan=%d;Chassis Fan #1=%d;Chassis Fan #2=%d;GPU Fan=%d%%" % (
                900 + load * 9, 760 + load * 4, 780 + load * 4, 0 if gpu_temp < 50 else 38 + (gpu_temp - 50) * 2)})
        return r

    def rails(self, t, base):
        r = {c: "" for c in FAST_COLUMNS}
        r.update({"timestamp": t.isoformat(timespec="milliseconds"), "v12_v": q(base["v12_v"] + rnd.uniform(-0.05, 0.05), 0.072),
                  "v5_v": q(5.05 + rnd.uniform(-0.02, 0.02), 0.03), "v33_v": q(3.35 + rnd.uniform(-0.012, 0.012), 0.016),
                  "vcore_v": round(base["vcore_v"] + rnd.uniform(-0.02, 0.02), 3), "vsoc_v": base["vsoc_v"],
                  "cpu_power_w": round(base["cpu_power_w"] + rnd.uniform(-4, 4), 1),
                  "cpu_temp_c": round(base["cpu_temp_c"] + rnd.uniform(-0.5, 0.5), 1)})
        return r


def write_csv(path, columns, rows):
    new = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new:
            w.writerow(columns)
        for r in rows:
            w.writerow([r.get(c, "") for c in columns])


class Records:
    def __init__(self, folder, prefix):
        self.folder, self.prefix = folder, prefix
        os.makedirs(folder, exist_ok=True)

    def add(self, t, kind, **payload):
        rec = dict({"ts": t.isoformat(timespec="milliseconds"), "kind": kind}, **payload)
        path = os.path.join(self.folder, "%s_%s.jsonl" % (self.prefix, t.strftime("%Y%m%d")))
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")


def winevent(t, source, eid, log="System", inserts=(), app=None):
    return {"log": log, "source": source, "id": eid, "at": t.isoformat(timespec="seconds"), "inserts": list(inserts),
            "app": app}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--days", type=int, default=3)
    ap.add_argument("--live", type=float, default=0)
    args = ap.parse_args()
    out = os.path.abspath(args.out)
    if os.path.exists(out):
        shutil.rmtree(out)
    for d in ("logs", "state", "incidents", "sessions/" + USER):
        os.makedirs(os.path.join(out, d))
    logs, inc = os.path.join(out, "logs"), os.path.join(out, "incidents")
    now = dt.datetime.now().replace(microsecond=0)
    start = (now - dt.timedelta(days=args.days - 1)).replace(hour=7, minute=58, second=0)
    d1 = start.date() + dt.timedelta(days=1)
    off_at = dt.datetime.combine(d1, dt.time(3, 12, 47, 250000))            # the power-off
    back_at = off_at + dt.timedelta(seconds=53)
    restart_at = dt.datetime.combine(d1, dt.time(23, 41, 6))                 # a restart, asked for
    restart_back = restart_at + dt.timedelta(seconds=74)
    crash_at = dt.datetime.combine(start.date(), dt.time(20, 14, 5))         # Blender crashes
    m = Machine()
    svc = Records(logs, "events")
    agent = Records(os.path.join(out, "sessions", USER), "session")
    with open(os.path.join(out, "config.json"), "w", encoding="utf-8") as f:
        json.dump({"watch": [{"exe": "explorer.exe", "label": "Windows Explorer"},
                             {"exe": "obs64.exe", "label": "OBS Studio"}, {"exe": "blender.exe", "label": "Blender"},
                             {"exe": "node.exe", "label": "Home server", "ports": [8080], "incidents": "crash"},
                             {"exe": "pythonw.exe", "label": "HW Blackbox agent", "match": "hwblackbox agent"}],
                   "ports": {"expected": {"8080": {"label": "Home server", "exe": "node.exe", "always": True},
                                          "11434": {"label": "Ollama", "exe": "ollama.exe"}},
                             "ignore": [], "down_after_min": 5},
                   "home_assistant": {"enabled": True, "env_file": "C:\\ProgramData\\HWBlackbox\\secrets\\home_assistant.env",
                                      "entity": "sensor.demo_pc_hw_blackbox", "name": "DEMO-PC HW Blackbox"},
                   "dashboard": {"enabled": True, "port": 9079,
                                 "milestones": [{"at": (start + dt.timedelta(hours=26)).isoformat(timespec="seconds"),
                                                 "text": "BIOS updated to 3201 (fan curves reset)"}]}}, f, indent=1)

    # the 5-second log, the gaps where the PC was off
    rows, t, last = [], start, None
    while t <= now:
        if off_at < t < back_at + dt.timedelta(seconds=40) or restart_at < t < restart_back + dt.timedelta(seconds=35):
            t += dt.timedelta(seconds=5)
            continue
        r = m.row(t)
        if t.date() != (last.date() if last else None) and rows:
            write_csv(os.path.join(logs, "flight_%s.csv" % last.strftime("%Y%m%d")), COLUMNS, rows)
            rows = []
        rows.append(r)
        last = t
        t += dt.timedelta(seconds=5)
    write_csv(os.path.join(logs, "flight_%s.csv" % last.strftime("%Y%m%d")), COLUMNS, rows)
    # the rails: the last 40 minutes, and the minute before the power-off
    rails = []
    t = now - dt.timedelta(minutes=40)
    while t <= now:
        rails.append(m.rails(t, m.row(t)))
        t += dt.timedelta(milliseconds=250)
    write_csv(os.path.join(logs, "rails_%s.csv" % now.strftime("%Y%m%d")), FAST_COLUMNS, rails)
    before = []
    t = off_at - dt.timedelta(seconds=60)
    while t <= off_at:
        before.append(m.rails(t, m.row(t)))
        t += dt.timedelta(milliseconds=250)
    write_csv(os.path.join(logs, "rails_%s.csv" % off_at.strftime("%Y%m%d")), FAST_COLUMNS, before)
    # the drives' free space, a reading a minute: C: slowly (logs, caches), and a game downloaded one evening (its
    # installer cleaned up after)
    disk_rows, t, span = {}, start, (now - start).total_seconds()
    dl = start + dt.timedelta(hours=34)
    while t <= now:
        if not (off_at < t < back_at + dt.timedelta(seconds=40) or restart_at < t < restart_back + dt.timedelta(seconds=35)):
            frac, x = (t - start).total_seconds() / span, (t - dl).total_seconds() / 60
            c = 434.6 - 14.0 * frac - (38 * x / 40 if 0 <= x < 40 else 38 - 30 * (x - 40) / 15 if 40 <= x < 55 else
                                       8 if x >= 55 else 0)
            for drive, free, total in (("C:", c, 930.6), ("D:", 1214.0 - 3.6 * frac, 1863.0)):
                disk_rows.setdefault(t.strftime("%Y%m%d"), []).append(
                    {"timestamp": t.isoformat(timespec="seconds"), "drive": drive, "free_gb": round(free, 2),
                     "total_gb": total})
        t += dt.timedelta(minutes=1)
    for day, rows_ in disk_rows.items():
        write_csv(os.path.join(logs, "disks_%s.csv" % day), DISK_COLUMNS, rows_)
    # each program's CPU use, a minute at a time (16 logical processors: 60 s of CPU in a minute is one of them): the
    # browser and an editor by day, a game and OBS in the evening, and a virus scan at 2 every night
    cpu_rows, t = {}, start
    while t <= now:
        if not (off_at < t < back_at + dt.timedelta(seconds=40) or restart_at < t < restart_back + dt.timedelta(seconds=35)):
            st, h = m.state(t), t.hour + t.minute / 60
            w = 1 + 0.35 * math.sin(t.timestamp() / 410) + rnd.uniform(-0.15, 0.15)
            progs = {"dwm.exe": 1.2 + {"idle": 0, "use": 2.5, "game": 9}[st], "System interrupts": 0.9,
                     "System": 0.7, "explorer.exe": 0.4 + (st == "use") * 1.2}
            if st == "use":
                progs.update({"chrome.exe": 14 * w, "Code.exe": 5 * w, "Discord.exe": 1.6})
            elif st == "game":
                progs.update({"Game.exe": 240 * w, "obs64.exe": 38 * w, "Discord.exe": 2.4, "chrome.exe": 3})
            if 2 <= h < 2.75:                                       # the nightly scan
                progs["MsMpEng.exe"] = 52 * w
            if t.minute % 15 == 0:
                progs["SearchIndexer.exe"] = 3.5
            rows_ = [(p, round(v * rnd.uniform(0.9, 1.1), 2)) for p, v in progs.items()]
            rows_ = sorted((r for r in rows_ if r[1] >= 0.6 or r[0] == "System interrupts"), key=lambda r: -r[1])
            ts = t.isoformat(timespec="seconds")
            day = cpu_rows.setdefault(t.strftime("%Y%m%d"), [])
            for p, v in rows_:
                day.append({"timestamp": ts, "seconds": 60.0, "program": p, "cpu_s": v,
                            "processes": {"chrome.exe": 23, "Discord.exe": 6, "Code.exe": 9, "System": 1}.get(p, 0 if p == "System interrupts" else 1),
                            "pid": "" if p == "System interrupts" else 1000 + sum(map(ord, p))})
            day.append({"timestamp": ts, "seconds": 60.0, "program": "(all)", "cpu_s": round(sum(v for _, v in rows_) + 2.1, 2),
                        "processes": 287, "pid": ""})
        t += dt.timedelta(minutes=1)
    for day, rows_ in cpu_rows.items():
        write_csv(os.path.join(logs, "cpu_%s.csv" % day), CPU_COLUMNS, rows_)

    # the records
    def boot(at, clean, prev_kind):
        svc.add(at + dt.timedelta(seconds=9), "winevent", **winevent(at, "Microsoft-Windows-Kernel-General", 12,
                                                                       inserts=["10", "0", "26100"], app=None),
                backfill=True)
        svc.add(at + dt.timedelta(seconds=9), "startup", pid=3180, version=VERSION, python="3.12.10", user="SYSTEM",
                system=True, admin=True, session=0, data_dir="C:\\ProgramData\\HWBlackbox", test=None,
                previous_run={"last_record": None, "kind": prev_kind, "ended_cleanly": clean})
        svc.add(at + dt.timedelta(seconds=11), "sensors", event="open", lhm="ok", nvml="ok", sensors=74,
                devices={"Cpu": CPU, "Motherboard": BOARD, "SuperIO": CHIP}, gpu=GPU, admin=True)
        svc.add(at + dt.timedelta(seconds=38), "session", event="sign-in", session=1, user=USER)
        agent.add(at + dt.timedelta(seconds=41), "startup", pid=7344, version=VERSION, user=USER, session=1,
                  screens=["\\\\.\\DISPLAY1 0,0 2560x1440 at 125%"], dashboard=9070)
        svc.add(at + dt.timedelta(seconds=41), "start", app="HW Blackbox agent", exe="pythonw.exe", pid=7344,
                session=1, user=USER)
        svc.add(at + dt.timedelta(minutes=2), "start", app="Home server", exe="node.exe", pid=4120, session=0)
        svc.add(at + dt.timedelta(minutes=2, seconds=20), "port", event="open", addr="0.0.0.0:8080", pid=4120,
                exe="node.exe", app="Home server", cmd="server.js --port 8080", before=None)

    boot(start, True, "stop")
    day0 = start.date()
    for h, m_ in ((9, 2), (12, 40), (17, 55)):
        at = dt.datetime.combine(day0, dt.time(h, m_))
        svc.add(at, "session", event="lock", session=1, user=USER)
        svc.add(at + dt.timedelta(minutes=27), "session", event="unlock", session=1, user=USER)
    svc.add(dt.datetime.combine(day0, dt.time(19, 2, 11)), "start", app="Blender", exe="blender.exe", pid=11872,
            session=1, user=USER)
    crash = {"app": "Blender", "exe": "blender.exe", "pid": 11872, "main": True, "session": 1, "user": USER,
             "taskbar": None, "code": "0xC0000005", "meaning": "crash: access violation", "ran": "1h 11m 54s",
             "mem_mb": 6844, "still_running": 0}
    svc.add(crash_at, "exit", **crash)
    svc.add(crash_at + dt.timedelta(seconds=2), "winevent", **winevent(
        crash_at, "Application Error", 1000, "Application",
        ["blender.exe", "4.2.3.0", "66f1a2b4", "cycles_kernel_oneapi.dll", "4.2.3.0", "66f1a1d0", "c0000005",
         "00000000001a7e2c", "2e60", "01db2f0c8a4b1e77"], app="blender.exe"))
    svc.add(dt.datetime.combine(day0, dt.time(21, 30, 2)), "winevent", **winevent(
        dt.datetime.combine(day0, dt.time(21, 30, 1)), "Display", 4101, inserts=["nvlddmkm", "", ""]))
    agent.add(dt.datetime.combine(day0, dt.time(21, 30, 3)), "display",
              before=["\\\\.\\DISPLAY1 0,0 2560x1440 at 125%"], after=["\\\\.\\DISPLAY1 0,0 2560x1440 at 125%",
                                                                       "\\\\.\\DISPLAY2 2560,180 1920x1080 at 100%"])
    # the power-off, and the boot after it
    boot(back_at, False, "mem")
    svc.add(back_at + dt.timedelta(seconds=10), "winevent", **winevent(back_at + dt.timedelta(seconds=2),
            "Microsoft-Windows-Kernel-Power", 41, inserts=["0", "0x0", "0x0", "0x0", "0x0", "false", "0", "0"]),
            backfill=True)
    svc.add(back_at + dt.timedelta(seconds=10), "winevent", **winevent(back_at + dt.timedelta(seconds=3), "EventLog",
            6008, inserts=["3:12:41 AM", off_at.strftime("%m/%d/%Y"), "", "", "2981", "", ""]), backfill=True)
    report = "incident_%s.txt" % back_at.strftime("%Y%m%d_%H%M%S")
    svc.add(back_at + dt.timedelta(seconds=14), "power_off_report",
            summary="Dirty shutdown detected: The previous system shutdown at 3:12:41 AM was unexpected.  ->  " + report)
    # the evening: a game, a port clash, a restart asked for
    gstart = dt.datetime.combine(d1, dt.time(19, 6, 30))
    svc.add(gstart, "start", app="OBS Studio", exe="obs64.exe", pid=14316, session=1, user=USER)
    svc.add(dt.datetime.combine(d1, dt.time(20, 41, 2)), "port", event="open", addr="127.0.0.1:8080", pid=9812,
            exe="python.exe", app=None, cmd="-m http.server 8080 --bind 127.0.0.1", before=None)
    clash = "Port 8080 is held by 2 programs: node.exe (pid 4120, on 0.0.0.0), python.exe (pid 9812, on 127.0.0.1)"
    svc.add(dt.datetime.combine(d1, dt.time(20, 41, 2, 300000)), "port", event="problem", problem=clash)
    svc.add(dt.datetime.combine(d1, dt.time(20, 44, 47)), "port", event="closed", addr="127.0.0.1:8080", pid=9812,
            exe="python.exe", app=None, seen_for="0h 03m")
    svc.add(dt.datetime.combine(d1, dt.time(20, 44, 47, 400000)), "port", event="problem over", problem=clash)
    svc.add(dt.datetime.combine(d1, dt.time(22, 40, 9)), "exit", app="OBS Studio", exe="obs64.exe", pid=14316,
            main=True, session=1, user=USER, taskbar=None, code="0x00000000", meaning="clean exit", ran="3h 33m 39s",
            mem_mb=612, still_running=0)
    svc.add(restart_at - dt.timedelta(seconds=3), "winevent", **winevent(
        restart_at - dt.timedelta(seconds=3), "User32", 1074,
        inserts=["C:\\Windows\\explorer.exe (DEMO-PC)", "DEMO-PC", "Other (Planned)", "0x80000000", "restart", "",
                 "DEMO-PC\\alex"]))
    agent.add(restart_at - dt.timedelta(seconds=2), "shutdown", phase="asked", type="shut down or restart",
              lparam="0x00000000", idle_s=0.4, locked=False, remote=False, in_front="explorer.exe")
    agent.add(restart_at - dt.timedelta(seconds=1), "shutdown", phase="ending", lparam="0x00000000")
    svc.add(restart_at, "shutdown", phase="services stopping", update_restart_pending=False, processes=231)
    svc.add(restart_at + dt.timedelta(seconds=1), "stop", pid=3180, why="Windows is shutting down", ran=62893)
    boot(restart_back, True, "stop")
    # today
    t0 = dt.datetime.combine(now.date(), dt.time(9, 15))
    if t0 < now:
        agent.add(t0, "taskbar", event="TaskbarCreated: the taskbar came back (Explorer restarted)", taskbar_pid=9020)
        svc.add(t0 - dt.timedelta(seconds=4), "exit", app="Windows Explorer", exe="explorer.exe", pid=6612, main=True,
                session=1, user=USER, taskbar=True, code="0xC0000409",
                meaning="crash: fail-fast (__fastfail / stack buffer overrun)", ran="9h 33m 52s", mem_mb=412,
                still_running=0)
        svc.add(t0 - dt.timedelta(seconds=1), "start", app="Windows Explorer", exe="explorer.exe", pid=9020, session=1,
                user=USER)
    for h in [x for x in (13,) if x < now.hour]:
        at = dt.datetime.combine(now.date(), dt.time(h, 5 + h))
        svc.add(at, "session", event="lock", session=1, user=USER)
        svc.add(at + dt.timedelta(minutes=12), "session", event="unlock", session=1, user=USER)

    # the reports
    flight_rows = []
    with open(os.path.join(logs, "flight_%s.csv" % off_at.strftime("%Y%m%d")), encoding="utf-8") as f:
        for line in f:
            if line[:19] <= off_at.isoformat(timespec="seconds") and not line.startswith("timestamp"):
                flight_rows.append(line.rstrip())
    rails_rows = []
    with open(os.path.join(logs, "rails_%s.csv" % off_at.strftime("%Y%m%d")), encoding="utf-8") as f:
        for line in f:
            if not line.startswith("timestamp") and line[:23] <= off_at.isoformat(timespec="milliseconds"):
                rails_rows.append(line.rstrip())
    flight_name = "flight_%s.csv" % off_at.strftime("%Y%m%d")
    rails_name = "rails_%s.csv" % off_at.strftime("%Y%m%d")
    with open(os.path.join(inc, report), "w", encoding="utf-8") as f:
        f.write("HW Blackbox: power-off report (written %s)\n%s\n\n" % (
            (back_at + dt.timedelta(seconds=14)).isoformat(timespec="seconds"), "=" * 70))
        f.write("Booted at:    %s, after a shutdown that wasn't clean\n" % back_at.isoformat(sep=" "))
        f.write("Went down:    %s  (the last sample before the gap; Windows' own\n"
                "              estimate in the 6008 below can be many minutes off)\n" %
                off_at.isoformat(sep=" ", timespec="milliseconds"))
        f.write("Gap:          %d s\n" % (back_at - off_at).total_seconds())
        f.write("Last record:  %s mem (no shutdown had begun)\n\n" % (off_at - dt.timedelta(seconds=7)).isoformat(sep=" ", timespec="milliseconds"))
        f.write("EVENT 6008 (unexpected shutdown):\nEvent[0]:\n  Log Name: System\n  Source: EventLog\n  Date: %s\n"
                "  Event ID: 6008\n  Level: Error\n  Description:\nThe previous system shutdown at 3:12:41 AM on %s "
                "was unexpected.\n\n" % ((back_at + dt.timedelta(seconds=3)).isoformat(timespec="milliseconds"),
                                        off_at.strftime("%m/%d/%Y")))
        f.write("EVENT 41 (Kernel-Power, check BugcheckCode):\nEvent[0]:\n  Log Name: System\n  Source: "
                "Microsoft-Windows-Kernel-Power\n  Date: %s\n  Event ID: 41\n  Level: Critical\n  Description:\n"
                "The system has rebooted without cleanly shutting down first. This error could be caused if the system "
                "stopped responding, crashed, or lost power unexpectedly.\n  BugcheckCode: 0\n  PowerButtonTimestamp: 0"
                "\n\n" % (back_at + dt.timedelta(seconds=2)).isoformat(timespec="milliseconds"))
        f.write("LAST SAMPLES BEFORE THE GAP (last %d rows):\n" % min(120, len(flight_rows)))
        f.write("\n".join("%s: %s" % (flight_name, r) for r in flight_rows[-120:]) + "\n")
        f.write("\nSUB-SECOND RAIL TRACE BEFORE THE GAP (last %d rows):\n" % min(240, len(rails_rows)))
        f.write("\n".join("%s: %s" % (rails_name, r) for r in rails_rows[-240:]) + "\n")
    with open(os.path.join(inc, "incident_%s_blender.exe.txt" % crash_at.strftime("%Y%m%d_%H%M%S")), "w",
              encoding="utf-8") as f:
        f.write("Blender ended: crash: access violation\n%s\n\nThe record:\n%s\n\n" % (
            crash_at.isoformat(timespec="milliseconds"), json.dumps(dict({"ts": crash_at.isoformat(), "kind": "exit"},
                                                                        **crash), indent=2)))
        f.write("The screens now (session 1):\n  \\\\.\\DISPLAY1 0,0 2560x1440 at 125%\n\n")
        f.write("The biggest processes now (private memory):\n  Memory Compression (pid 2140, session 0): 1890 MB "
                "private\n  firefox.exe (pid 8816, session 1): 1204 MB private\n  obs64.exe (pid 14316, session 1): "
                "598 MB private\n  Discord.exe (pid 10284, session 1): 471 MB private\n\n")
        f.write("The last 3 minutes (everything the service wrote):\n  {\"ts\": \"%s\", \"kind\": \"mem\", "
                "\"private_mb\": {\"blender.exe/11872\": 6812, \"explorer.exe/6612\": 188}}\n\n" %
                (crash_at - dt.timedelta(seconds=55)).isoformat(timespec="milliseconds"))
        f.write("The app in front, session 1 (last 3 minutes):\n  %s  blender.exe\n  %s  firefox.exe\n  %s  "
                "blender.exe\n" % tuple((crash_at - dt.timedelta(seconds=s)).strftime("%H:%M:%S") for s in (178, 92, 61)))

    # what's true now
    st = os.path.join(out, "state")
    sensors = make_sensors(m.row(now), start)
    with open(os.path.join(st, "sensors.json"), "w", encoding="utf-8") as f:
        json.dump(sensors, f)
    with open(os.path.join(st, "last_incident.json"), "w", encoding="utf-8") as f:
        json.dump({"boot": back_at.isoformat(timespec="seconds"),
                   "time_of_death": off_at.isoformat(timespec="milliseconds"), "incident": report}, f)
    write_ports(st, restart_back)
    write_live(out, now, restart_back, back_at, off_at, report, crash_at)
    print("made %s: %d days, a power-off at %s, a crash at %s" % (out, args.days, off_at, crash_at))
    if args.live:
        live(out, m, args.live, restart_back, back_at, off_at, report, crash_at)


def make_sensors(r, started):
    s = []

    def add(group, device, hw, typ, name, unit, v, lo=None, hi=None, avg=None, note=None):
        s.append({"id": "%s/%s/%s" % (hw, typ, name), "group": group, "device": device, "type": typ, "name": name,
                  "unit": unit, "value": v, "min": lo if lo is not None else v, "max": hi if hi is not None else v,
                  "avg": avg if avg is not None else v, "note": note})
    load = r["cpu_load_pct"]
    add("CPU", CPU, "Cpu", "Temperature", "Core (Tctl/Tdie)", "°C", r["cpu_temp_c"], 38.1, 79.4, 52.6)
    add("CPU", CPU, "Cpu", "Temperature", "CCD1 (Tdie)", "°C", round(r["cpu_temp_c"] - 3.4, 1), 35.0, 75.2, 49.1)
    add("CPU", CPU, "Cpu", "Power", "Package", "W", r["cpu_power_w"], 22.4, 118.6, 41.8)
    for i in range(1, 9):
        add("CPU", CPU, "Cpu", "Power", "Core #%d (SMU)" % i, "W", round(r["cpu_power_w"] / 14 + i * 0.07, 1),
            0.1, 14.8, 2.3)
    add("CPU", CPU, "Cpu", "Load", "CPU Total", "%", load, 0.4, 97.1, 17.9)
    add("CPU", CPU, "Cpu", "Load", "CPU Core Max", "%", min(100, round(load * 1.6, 1)), 3.1, 100, 38.2)
    for i in range(1, 9):
        add("CPU", CPU, "Cpu", "Clock", "Core #%d" % i, "MHz", 5390 - i * 11, 3591, 5574, 4980)
    add("CPU", CPU, "Cpu", "Clock", "Cores (Average Effective)", "MHz", round(400 + load * 42), 71, 5021, 1144)
    add("CPU", CPU, "Cpu", "Voltage", "Core (SVI3 TFN)", "V", r["vcore_v"], 0.912, 1.344, 1.083)
    add("CPU", CPU, "Cpu", "Voltage", "SoC (SVI3 TFN)", "V", r["vsoc_v"], 1.24, 1.256, 1.25)
    add("Motherboard", CHIP, "SuperIO", "Temperature", "CPU", "°C", round(r["cpu_temp_c"] - 6, 1), 33, 71, 46.2)
    add("Motherboard", CHIP, "SuperIO", "Temperature", "Motherboard", "°C", r["board_temp_c"], 31.5, 39.0, 34.4)
    add("Motherboard", CHIP, "SuperIO", "Temperature", "VRM", "°C", round(r["board_temp_c"] + 14, 1), 41, 63, 49.7)
    add("Motherboard", CHIP, "SuperIO", "Temperature", "Chipset", "°C", 51.0, 48, 56, 51.6)
    for name, v, lo, hi, avg in (("Vcore", r["vcore_v"], 0.904, 1.352, 1.077), ("+5V", r["v5_v"], 5.01, 5.07, 5.046),
                                 ("+12V", r["v12_v"], 12.024, 12.24, 12.139), ("+3.3V", r["v33_v"], 3.328, 3.36, 3.347),
                                 ("+3V Standby", 3.376, 3.36, 3.392, 3.376), ("CMOS Battery", 3.152, 3.152, 3.168, 3.155)):
        add("Motherboard", CHIP, "SuperIO", "Voltage", name, "V", v, lo, hi, avg)
    for name, v, lo, hi, avg in (("CPU Fan", 900 + load * 9, 862, 1784, 1036), ("Chassis Fan #1", 760 + load * 4, 731, 1142, 818),
                                 ("Chassis Fan #2", 780 + load * 4, 744, 1170, 836), ("AIO Pump", 2640, 2610, 2701, 2646),
                                 ("Chassis Fan #3", 0, 0, 0, 0)):
        add("Motherboard", CHIP, "SuperIO", "Fan", name, "RPM", round(v), lo, hi, avg)
    gpu = [("Nvml/gpu_temp_c", "Temperature", "GPU", "°C", r["gpu_temp_c"], 35, 71, 44.6),
           ("Nvml/gpu_power_w", "Power", "GPU board power", "W", r["gpu_power_w"], 8.9, 197.2, 52.3),
           ("Nvml/gpu_power_limit_w", "Power", "Power limit", "W", 200.0, 200.0, 200.0, 200.0),
           ("Nvml/gpu_clock_mhz", "Clock", "Graphics", "MHz", r["gpu_clock_mhz"], 210, 2790, 1012),
           ("Nvml/gpu_util_pct", "Load", "GPU", "%", r["gpu_util_pct"], 0, 100, 27.8),
           ("Nvml/gpu_fan_pct", "Fan", "Fan", "%", 0 if r["gpu_temp_c"] < 50 else 50, 0, 61, 12.4),
           ("Nvml/gpu_vram_mb", "SmallData", "Memory used", "MB", r["gpu_vram_mb"], 702, 9412, 3020),
           ("Nvml/gpu_vram_total_mb", "SmallData", "Memory total", "MB", 12282, 12282, 12282, 12282)]
    for sid, typ, name, unit, v, lo, hi, avg in gpu:
        s.append({"id": sid, "group": "GPU", "device": GPU, "type": typ, "name": name, "unit": unit, "value": v,
                  "min": lo, "max": hi, "avg": avg, "note": None})
    for sid, typ, name, unit, v, lo, hi, avg in (
            ("Psutil/cpu_load_pct", "Load", "CPU (all threads)", "%", load, 0.5, 96.8, 17.6),
            ("Psutil/ram_used_gb", "Data", "Memory used", "GB", r["ram_used_gb"], 10.42, 22.31, 14.86),
            ("Psutil/ram_pct", "Load", "Memory", "%", r["ram_pct"], 33.0, 70.6, 47.0),
            ("Psutil/ram_total_gb", "Data", "Memory total", "GB", RAM_GB, RAM_GB, RAM_GB, RAM_GB)):
        s.append({"id": sid, "group": "System", "device": "Windows", "type": typ, "name": name, "unit": unit,
                  "value": v, "min": lo, "max": hi, "avg": avg, "note": None})
    return {"ts": r["timestamp"], "started": started.isoformat(timespec="seconds"), "samples": 17283, "admin": True,
            "devices": {"Cpu": CPU, "Motherboard": BOARD, "SuperIO": CHIP, "Nvml": GPU}, "sensors": s}


def write_ports(st, since):
    rows = [("0.0.0.0", 135, 1104, "svchost.exe", None, None), ("[::]", 135, 1104, "svchost.exe", None, None),
            ("0.0.0.0", 445, 4, "System", None, None), ("0.0.0.0", 5040, 6620, "svchost.exe", None, None),
            ("127.0.0.1", 6463, 10284, "Discord.exe", None, "--type=renderer --user-data-dir=..."),
            ("0.0.0.0", 8080, 4120, "node.exe", "Home server", "server.js --port 8080"),
            ("127.0.0.1", 9070, 7344, "pythonw.exe", "HW Blackbox agent", "-m hwblackbox agent"),
            ("0.0.0.0", 11434, 5528, "ollama.exe", "Ollama", "serve"),
            ("127.0.0.1", 27060, 8204, "steam.exe", None, "-silent"),
            ("0.0.0.0", 27036, 8204, "steam.exe", None, "-silent"), ("0.0.0.0", 49664, 912, "lsass.exe", None, None),
            ("0.0.0.0", 49665, 780, "wininit.exe", None, None), ("0.0.0.0", 49669, 2988, "spoolsv.exe", None, None)]
    with open(os.path.join(st, "ports.json"), "w", encoding="utf-8") as f:
        json.dump({"ts": dt.datetime.now().isoformat(timespec="seconds"), "scans": 2810, "error": None,
                   "listening": [{"addr": "%s:%d" % (ip, port), "ip": ip,
                                  "port": port, "pid": pid, "exe": exe, "app": app, "cmd": cmd,
                                  "seen_since": since.isoformat(timespec="seconds")}
                                 for ip, port, pid, exe, app, cmd in rows], "problems": []}, f)


def write_live(out, now, booted, back_at, off_at, report, crash_at):
    st = os.path.join(out, "state")
    now = dt.datetime.now().replace(microsecond=0)
    attrs = {"sensors": "logging", "rails": "ok", "cpu_temperature": "ok", "watcher": "running",
             "session_agent": "running", "ports_listening": 13, "disk_free_gb": 412.6, "logs_mb": 9,
             "boot": booted.isoformat(timespec="seconds"), "version": VERSION,
             "last_incident": "%s: Blender ended: crash: access violation" % crash_at.isoformat(sep=" "),
             "last_shutdown": "%s: restart by explorer.exe (Other (Planned))" % (booted - dt.timedelta(seconds=77)).isoformat(sep=" "),
             "last_power_loss": (back_at + dt.timedelta(seconds=2)).isoformat(sep=" "),
             "last_power_loss_died_at": off_at.isoformat(timespec="milliseconds"),
             "windows_update": "waiting for a restart since %s" % (now - dt.timedelta(hours=27)).strftime("%Y-%m-%d %H:%M")}
    status = {"ts": now.isoformat(timespec="seconds"), "version": VERSION, "pid": 3180,
              "started": booted.isoformat(timespec="seconds"), "test": False, "state": "ok", "problems": [],
              "attributes": attrs,
              "sensors": {"lhm": "ok", "nvml": "ok", "admin": True, "sensors": 74, "last_sample": now.isoformat(),
                          "rows": 17281, "errors": 0, "fast_last": now.isoformat(), "fast_rows": 69128, "fast_hz": 4.0,
                          "rails_ok": True, "cpu_temp_ok": True},
              "apps": ["explorer.exe/9020", "node.exe/4120", "pythonw.exe/7344"],
              "agents": [{"session": 1, "user": USER, "state": "active", "agent": "running", "age": 12, "pid": 7344,
                          "version": VERSION}],
              "ha": {"ok": True, "at": (now - dt.timedelta(seconds=21)).isoformat(timespec="seconds"), "error": None},
              "pc": {"host": HOST, "windows": "Windows 11, build 26100", "boot_epoch": booted.timestamp(), "threads": 16,
                     "disks": [{"mount": "C:\\", "total_gb": 930.6, "free_gb": 412.6},
                               {"mount": "D:\\", "total_gb": 1863.0, "free_gb": 1210.4}]},
              "cpu_pct": 1.1, "mem_mb": 168.4, "threads": {"watcher": 0.4, "sensors": 2.1, "rails": 0.1},
              "event_logs": {"Application": True, "System": True}, "config_error": None,
              "data_dir": "C:\\ProgramData\\HWBlackbox",
              "last_dirty_shutdown": {"boot": back_at.isoformat(timespec="seconds"),
                                      "time_of_death": off_at.isoformat(timespec="milliseconds"), "incident": report}}
    with open(os.path.join(st, "status.json"), "w", encoding="utf-8") as f:
        json.dump(status, f)
    with open(os.path.join(out, "sessions", USER, "agent.json"), "w", encoding="utf-8") as f:
        json.dump({"ts": now.isoformat(timespec="seconds"), "pid": 7344, "version": VERSION, "user": USER, "session": 1,
                   "started": booted.isoformat(timespec="seconds"),
                   "screens": ["\\\\.\\DISPLAY1 0,0 2560x1440 at 125%", "\\\\.\\DISPLAY2 2560,180 1920x1080 at 100%"],
                   "taskbar_pid": 9020, "locked": False, "idle_s": 3, "in_front": "firefox.exe", "mem_mb": 21.4,
                   "dashboard": {"port": 9070, "error": None}}, f)


def live(out, m, seconds, *info):
    """Keep writing rows and refreshing the status, as a running service would."""
    logs = os.path.join(out, "logs")
    end = time.time() + seconds
    n = 0
    while time.time() < end:
        t = dt.datetime.now()
        base = m.row(t.replace(microsecond=0))
        write_csv(os.path.join(logs, "rails_%s.csv" % t.strftime("%Y%m%d")), FAST_COLUMNS, [m.rails(t, base)])
        if n % 20 == 0:
            write_csv(os.path.join(logs, "flight_%s.csv" % t.strftime("%Y%m%d")), COLUMNS, [base])
            sensors = make_sensors(base, dt.datetime.now() - dt.timedelta(days=1))
            with open(os.path.join(out, "state", "sensors.json"), "w", encoding="utf-8") as f:
                json.dump(sensors, f)
            write_live(out, t, *info)
        n += 1
        time.sleep(0.25)


if __name__ == "__main__":
    main()
