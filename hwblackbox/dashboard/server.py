r"""The dashboard's server: one page (index.html) and a read-only JSON API over HW Blackbox's files.

  Overview    the service and the session agents, problems, the key readings now, power-offs, disks
  Sensors     every sensor: current / minimum / maximum / average, since the page opened or since the service started
  Charts      the 5-second log and the drives' free space (a reading a minute), any range from an hour to 7 days (the
              line is the average, the band the min and max)
  Power       the 4-a-second rails (the last minutes) and every power-off caught
  Events      the records: apps closing and crashing, shutdowns and who asked, sessions, ports, Windows' own records
  Ports       who listens on which port, and port problems
  Incidents   the power-off and app incident reports, to read in place
  Processes   what's using the CPU and the memory right now

It only reads: HW Blackbox's files, and Windows for the processes and the disks. It listens on 127.0.0.1 (this PC
only), and answers only requests addressed to it that way, so a web page elsewhere can't reach it through a DNS
trick. It runs inside the session agent; `python -m hwblackbox open` starts one of its own when no agent serves it."""
import array
import bisect
import collections
import csv
import datetime as dt
import http.server
import json
import math
import os
import re
import shutil
import socket
import sys
import threading
import time
import urllib.parse
import urllib.request

import psutil

from .. import NAME, VERSION, config, paths, winapi
from ..util import age, read_json, tail_lines

APP = "hw-blackbox-dashboard"
PAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")

# The 5-second log's readings: column -> (label, unit, group). The order is the page's.
FLIGHT = collections.OrderedDict([
    ("cpu_temp_c", ("CPU temperature", "°C", "Temperatures")),
    ("gpu_temp_c", ("GPU temperature", "°C", "Temperatures")),
    ("board_temp_c", ("Board temperature", "°C", "Temperatures")),
    ("cpu_power_w", ("CPU package power", "W", "Power")),
    ("gpu_power_w", ("GPU power", "W", "Power")),
    ("v12_v", ("+12V rail", "V", "Voltages")),
    ("v5_v", ("+5V rail", "V", "Voltages")),
    ("v33_v", ("+3.3V rail", "V", "Voltages")),
    ("vcore_v", ("Vcore", "V", "Voltages")),
    ("vsoc_v", ("SoC voltage", "V", "Voltages")),
    ("cpu_load_pct", ("CPU load", "%", "Load")),
    ("gpu_util_pct", ("GPU load", "%", "Load")),
    ("gpu_clock_mhz", ("GPU clock", "MHz", "Clocks")),
    ("ram_used_gb", ("Memory used", "GB", "Memory")),
    ("ram_pct", ("Memory load", "%", "Memory")),
    ("gpu_vram_mb", ("GPU memory used", "MB", "Memory")),
])
RAILS = ("v12_v", "v5_v", "v33_v", "vcore_v", "vsoc_v", "cpu_power_w", "cpu_temp_c")
# records worth a line on the Events page (the rest are bulky or minute-by-minute)
EVENT_KINDS = {"exit", "start", "winevent", "shutdown", "power", "session", "display", "taskbar", "port", "startup",
               "stop", "error", "agent", "clock", "sensors", "power_off_report", "boot_part"}
POWEROFF_NAME = re.compile(r"incident_\d{8}_\d{6}\.txt$")
INCIDENT_NAME = re.compile(r"incident_\d{8}_\d{6}[\w.\-]*\.txt$")


def epoch(text):
    try:
        return dt.datetime.fromisoformat(text).timestamp()
    except (TypeError, ValueError):
        return None


def settings():
    return config.load()


def session_dirs():
    """[(user folder name, path)] for every session agent's folder."""
    try:
        return [(e.name, e.path) for e in os.scandir(paths.P.sessions) if e.is_dir()]
    except OSError:
        return []


# the 5-second log, parsed once per file and then only its new rows ------------------------------------------------

class FlightCache:
    """flight_YYYYMMDD.csv as columns of doubles (nan when blank), by file: about 2.5 MB a day, and only the KEEP most
    recently used days stay. Today's file grows every 5 s: only the rows added since the last look are parsed.
    Emptied after IDLE seconds without a request, so a page left closed costs nothing."""

    KEEP = 9
    IDLE = 600

    def __init__(self):
        self.lock = threading.Lock()
        self.files = collections.OrderedDict()   # name -> {"size", "pos", "head", "t": array, col: array}
        self.used = time.time()

    def drop_if_idle(self):
        with self.lock:
            if self.files and time.time() - self.used > self.IDLE:
                self.files.clear()

    def get(self, name):
        path = os.path.join(paths.P.logs, name)
        try:
            size = os.path.getsize(path)
        except OSError:
            return None
        with self.lock:
            self.used = time.time()
            c = self.files.get(name)
            if c is None or size < c["size"]:
                c = self.files[name] = {"size": 0, "pos": 0, "head": None, "t": array.array("d")}
            self.files.move_to_end(name)
            while len(self.files) > self.KEEP:
                self.files.popitem(last=False)
            if size > c["pos"]:
                with open(path, "rb") as f:
                    f.seek(c["pos"])
                    chunk = f.read(size - c["pos"])
                end = chunk.rfind(b"\n") + 1               # (a row still being written waits for next time)
                lines = chunk[:end].replace(b"\x00", b"").decode("utf-8", "replace").splitlines()
                c["pos"] += end
                for row in csv.reader(lines):
                    if not row:
                        continue
                    if row[0] == "timestamp":
                        c["head"] = row
                        for col in row[1:]:
                            c.setdefault(col, array.array("d"))
                        continue
                    t = epoch(row[0])
                    if t is None or c["head"] is None:
                        continue
                    c["t"].append(t)
                    for i, col in enumerate(c["head"][1:], start=1):
                        v = row[i] if i < len(row) else ""
                        try:
                            c[col].append(float(v) if v != "" else math.nan)
                        except ValueError:
                            c[col].append(math.nan)
            c["size"] = size
            return c

    def rows_between(self, start, end, cols):
        """(times, {col: values}) for start <= t <= end, across the day files that cover it."""
        days = []
        d = dt.date.fromtimestamp(start)
        while d <= dt.date.fromtimestamp(end):
            days.append(d)
            d += dt.timedelta(days=1)
        ts, out = [], {c: [] for c in cols}
        for d in days:
            c = self.get("flight_%s.csv" % d.strftime("%Y%m%d"))
            if not c or not c["t"]:
                continue
            i, j = bisect.bisect_left(c["t"], start), bisect.bisect_right(c["t"], end)
            ts.extend(c["t"][i:j])
            for col in cols:
                vals = c.get(col)
                out[col].extend(vals[i:j] if vals is not None else [math.nan] * (j - i))
        return ts, out


FLIGHT_CACHE = FlightCache()


def bucketed(ts, series, start, end, points):
    """Average, minimum and maximum per time bucket; a bucket with no rows is None (a gap: the PC off or the service
    down)."""
    if not ts:
        return {"t": [], "series": {c: {"avg": [], "min": [], "max": []} for c in series}, "step": None}
    step = max(5.0, (end - start) / max(1, points))
    n = int(math.ceil((end - start) / step))
    sums = {c: [0.0] * n for c in series}
    cnts = {c: [0] * n for c in series}
    mins = {c: [math.inf] * n for c in series}
    maxs = {c: [-math.inf] * n for c in series}
    for k, t in enumerate(ts):
        b = min(n - 1, int((t - start) / step))
        for c, vals in series.items():
            v = vals[k]
            if v == v:                                     # (not nan)
                sums[c][b] += v
                cnts[c][b] += 1
                if v < mins[c][b]:
                    mins[c][b] = v
                if v > maxs[c][b]:
                    maxs[c][b] = v
    out = {}
    for c in series:
        avg, lo, hi = [], [], []
        for b in range(n):
            if cnts[c][b]:
                avg.append(round(sums[c][b] / cnts[c][b], 4))
                lo.append(mins[c][b])
                hi.append(maxs[c][b])
            else:
                avg.append(None)
                lo.append(None)
                hi.append(None)
        out[c] = {"avg": avg, "min": lo, "max": hi}
    return {"t": [round(start + (b + 0.5) * step, 1) for b in range(n)], "series": out, "step": step}


# the API -------------------------------------------------------------------------------------------------------

def newest(prefix):
    try:
        names = sorted(f for f in os.listdir(paths.P.logs) if f.startswith(prefix))
    except OSError:
        return None
    return os.path.join(paths.P.logs, names[-1]) if names else None


def agents_now():
    """Every session agent's last heartbeat, with its age."""
    out = []
    for user, folder in session_dirs():
        hb = read_json(os.path.join(folder, "agent.json"), limit=1 << 20)
        if isinstance(hb, dict):
            hb["age"] = age(os.path.join(folder, "agent.json"))
            out.append(hb)
    return out


_cache = {}


def cached(key, seconds, fn):
    """fn()'s answer, worked out again only every `seconds` (the page asks every 5 s)."""
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < seconds:
        return hit[1]
    val = fn()
    _cache[key] = (time.time(), val)
    return val


def disks():
    out = []
    for p in psutil.disk_partitions(all=False):       # (slow with a network or removable drive: cached)
        if "fixed" not in (p.opts or ""):
            continue
        try:
            u = shutil.disk_usage(p.mountpoint)
        except OSError:
            continue
        out.append({"mount": p.mountpoint, "total_gb": round(u.total / 2**30, 1), "free_gb": round(u.free / 2**30, 1)})
    return out


def api_overview(q):
    cfg = settings()
    st = read_json(paths.P.status)
    ages = {"status": age(paths.P.status), "flight": None, "rails": None}
    f, r = newest("flight_"), newest("rails_")
    ages["flight"] = age(f) if f else None
    ages["rails"] = age(r) if r else None
    ha = cfg.get("home_assistant") or {}
    # the PC as the service recorded it (a data folder copied from another PC shows that PC), else this one
    pc = (st or {}).get("pc") or {}
    return {
        "host": pc.get("host") or socket.gethostname(), "now": time.time(),
        "boot": pc.get("boot_epoch") or psutil.boot_time(), "name": NAME, "version": VERSION,
        "windows": pc.get("windows") or "Windows %s, build %d" % (
            "11" if sys.getwindowsversion().build >= 22000 else "10", sys.getwindowsversion().build),
        "service": st, "agents": agents_now(), "ages": ages, "disks": pc.get("disks") or cached("disks", 60, disks),
        "problems": (st or {}).get("problems") or [] if ages["status"] is not None and ages["status"] < 120 else [],
        "ha": {"enabled": bool(ha.get("enabled")), "entity": ha.get("entity")},
        "power_offs": cached("power_offs", 30, power_offs),
        "milestones": (cfg.get("dashboard") or {}).get("milestones") or [],
        "first_log": cached("first_log", 300, first_log_day),
    }


def first_log_day():
    try:
        names = sorted(f for f in os.listdir(paths.P.logs) if f.startswith("flight_") and f.endswith(".csv"))
        return names[0][7:15] if names else None
    except OSError:
        return None


def api_sensors(q):
    """state\\sensors.json when it's fresh; else the 5-second log's latest row, with min / max / average over
    today's file."""
    data = read_json(paths.P.sensors)
    a = age(paths.P.sensors)
    if data and a is not None and a < 60:
        data["source"] = "sensors.json"
        data["age"] = a
        return data
    today = "flight_%s.csv" % dt.date.today().strftime("%Y%m%d")
    c = FLIGHT_CACHE.get(today)
    sensors = []
    if c and c["t"]:
        for col, (label, unit, group) in FLIGHT.items():
            vals = [v for v in (c.get(col) or []) if v == v]
            if not vals:
                continue
            last = c[col][-1]
            sensors.append({"id": "Flight/" + col, "group": group, "device": "5-second log", "type": group,
                            "name": label, "unit": unit, "value": None if last != last else last,
                            "min": min(vals), "max": max(vals), "avg": round(sum(vals) / len(vals), 3), "note": None})
    return {"source": "flight log", "age": age(os.path.join(paths.P.logs, today)),
            "ts": dt.datetime.fromtimestamp(c["t"][-1]).isoformat(timespec="seconds") if c and c["t"] else None,
            "samples": len(c["t"]) if c else 0, "started": "today 00:00", "devices": {}, "sensors": sensors}


def api_history(q):
    want = (q.get("cols") or "cpu_temp_c,gpu_temp_c").split(",")
    cols = [c for c in want if c in FLIGHT]
    dcols = [c for c in want if c.startswith(DISK)]
    hours = min(24 * 7, max(0.25, float(q.get("hours") or 6)))
    points = min(2000, max(50, int(q.get("points") or 600)))
    end = time.time()
    start = end - hours * 3600
    ts, series = FLIGHT_CACHE.rows_between(start, end, cols) if cols else ([], {})
    out = bucketed(ts, series, start, end, points)
    meta = {c: {"label": FLIGHT[c][0], "unit": FLIGHT[c][1], "group": FLIGHT[c][2]} for c in cols}
    rows = len(ts)
    if dcols:
        per = disk_series(start, end)
        for c in dcols:
            dts, vals = per.get(c[len(DISK):], ([], []))
            b = bucketed(dts, {c: vals}, start, end, points)
            if b["t"] and not out["t"]:             # (no 5-second rows in the range: the drives' buckets set the axis)
                out["t"], out["step"] = b["t"], b["step"]
                out["series"] = {k: empty_series(len(b["t"])) for k in out["series"]}
            out["series"][c] = hold(b["series"][c], b["t"]) if b["t"] else empty_series(len(out["t"]))
            meta[c] = disk_meta(c[len(DISK):])
            rows += len(dts)
    out.update({"cols": meta, "start": start, "end": end, "rows": rows})
    return out


def hold(series, t, seconds=90):
    """A reading a minute in buckets of a few seconds: each one carried on until the next, so the line doesn't
    break up; a longer gap (the PC off, the service down) stays a gap."""
    last = None
    for i in range(len(t)):
        if series["avg"][i] is not None:
            last = i
        elif last is not None and t[i] - t[last] <= seconds:
            for k in ("avg", "min", "max"):
                series[k][i] = series[k][last]
    return series


def api_flight_columns(q):
    return {"cols": [{"id": c, "label": l, "unit": u, "group": g} for c, (l, u, g) in FLIGHT.items()] +
                    [dict(disk_meta(d), id=DISK + d) for d in cached("drives", 300, logged_drives)]}


# the drives' free space (logs\disks_YYYYMMDD.csv, a row per drive a minute) ------------------------------------------

DISK = "disk:"                  # a chart column for a drive: "disk:C:"
_disk_files = {}                # name -> (size, rows)
_disk_lock = threading.Lock()   # (the server answers on several threads)


def empty_series(n):
    return {"avg": [None] * n, "min": [None] * n, "max": [None] * n}


def disk_meta(drive):
    return {"label": "%s free space" % drive, "unit": "GB free", "group": "Disks"}


def disk_rows(day):
    """A day's rows [(epoch, drive, free GB, total GB)], parsed again only when the file has grown."""
    from ..disks import path_for, read_rows
    path = path_for(day)
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    name = os.path.basename(path)
    with _disk_lock:
        hit = _disk_files.get(name)
        if not hit or hit[0] != size:
            hit = _disk_files[name] = (size, read_rows(path))
            while len(_disk_files) > 10:
                _disk_files.pop(next(iter(_disk_files)))
        return hit[1]


def disk_series(start, end):
    """{drive: (times, free GB)} for start <= t <= end."""
    out = {}
    d = dt.date.fromtimestamp(start)
    while d <= dt.date.fromtimestamp(end):
        for t, drive, free, _total in disk_rows(d):
            if start <= t <= end:
                ts, vals = out.setdefault(drive, ([], []))
                ts.append(t)
                vals.append(free)
        d += dt.timedelta(days=1)
    return out


def logged_drives():
    """The drives in the last week's logs, by letter."""
    seen = set()
    for back in range(7):
        seen.update(r[1] for r in disk_rows(dt.date.today() - dt.timedelta(days=back)))
    return sorted(seen)


def api_rails(q):
    """The last minutes of the 4-a-second lane, read from the end of the file(s)."""
    minutes = min(60, max(1, float(q.get("minutes") or 10)))
    end = time.time()
    start = end - minutes * 60
    rows = []
    for d in sorted({dt.date.fromtimestamp(start), dt.date.fromtimestamp(end)}):
        path = os.path.join(paths.P.logs, "rails_%s.csv" % d.strftime("%Y%m%d"))
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        want = int(minutes * 60 * 4 * 90 * 1.3) + 4096       # (rows are about 75 bytes)
        with open(path, "rb") as f:
            f.seek(max(0, size - want))
            text = f.read().replace(b"\x00", b"").decode("utf-8", "replace")
        lines = text.splitlines()
        if size > want:
            lines = lines[1:]                        # (cut in half by the seek)
        for row in csv.reader(lines):
            if not row or row[0] == "timestamp":
                continue
            t = epoch(row[0])
            if t is not None and start <= t <= end:
                rows.append((t, row))
    rows.sort(key=lambda r: r[0])
    out = {"t": [round(t, 3) for t, _ in rows], "minutes": minutes}
    for i, col in enumerate(RAILS, start=1):
        vals = []
        for _, row in rows:
            try:
                vals.append(float(row[i]) if i < len(row) and row[i] != "" else None)
            except ValueError:
                vals.append(None)
        out[col] = vals
    st = read_json(paths.P.status) or {}
    out["fast_hz"] = (st.get("sensors") or {}).get("fast_hz")
    return out


def power_offs():
    """Every power-off caught, from the incident reports: when it went down (the newest sample row in the report),
    when it came back, the gap, and the last rails row."""
    out = []
    try:
        names = sorted(f for f in os.listdir(paths.P.incidents) if POWEROFF_NAME.match(f))
    except OSError:
        names = []
    for name in names:
        try:
            with open(os.path.join(paths.P.incidents, name), encoding="utf-8", errors="replace") as f:
                text = f.read().replace("\x00", "")
        except OSError:
            continue
        died, last_rails = None, None
        for m in re.finditer(r"^(flight|rails)_\d{8}\.csv: (\d{4}-\d\d-\d\dT[\d:.]+),(.*)$", text, re.MULTILINE):
            if died is None or m.group(2) > died:
                died = m.group(2)
            if m.group(1) == "rails" and (last_rails is None or m.group(2) > last_rails[0]):
                last_rails = (m.group(2), m.group(3))
        m = re.search(r"Went down:\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?)", text)
        if m:
            died = m.group(1).replace(" ", "T")
        m = re.search(r"Booted at:\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)", text)
        boot = m.group(1).replace(" ", "T") if m else None
        if not boot:                    # (older reports are named by Windows' 6008 record, written at the boot)
            boot = dt.datetime.strptime(name[9:24], "%Y%m%d_%H%M%S").isoformat()
        est = re.search(r"previous system shutdown at ([\d:]+ [AP]M)", text)
        rails = None
        if last_rails:
            v = last_rails[1].split(",")
            rails = {k: (float(x) if x else None) for k, x in zip(RAILS, v)}
        b, d = epoch(boot), epoch(died) if died else None
        out.append({"report": name, "boot": boot, "went_down": died, "gap_s": round(b - d, 1) if b and d else None,
                    "windows_estimate": est.group(1) if est else None, "last_rails": rails})
    return out


def journal_files(day):
    """The service's records file for a day and every session agent's: [(source, path)]."""
    stamp = day.strftime("%Y%m%d")
    out = [("service", os.path.join(paths.P.logs, "events_%s.jsonl" % stamp))]
    for user, folder in session_dirs():
        out.append((user, os.path.join(folder, "session_%s.jsonl" % stamp)))
    return out


def api_events(q):
    hours = min(24 * 31, max(1, float(q.get("hours") or 48)))
    limit = min(5000, max(50, int(q.get("limit") or 1500)))
    cutoff = time.time() - hours * 3600
    out = []
    d = dt.date.fromtimestamp(cutoff)
    while d <= dt.date.today():
        for src, path in journal_files(d):
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if '"kind": "mem"' in line or '"kind": "watching"' in line or '"shutdown_snapshot"' in line:
                            continue
                        try:
                            rec = json.loads(line)
                        except ValueError:
                            continue
                        if rec.get("kind") not in EVENT_KINDS:
                            continue
                        # (Windows' records at the time they happened: one read after a restart was written later)
                        t = (epoch(rec.get("at")) if rec.get("kind") == "winevent" else None) or epoch(rec.get("ts"))
                        if t is None or t < cutoff:
                            continue
                        out.append(describe(rec, t, src))
            except OSError:
                continue
        d += dt.timedelta(days=1)
    out.sort(key=lambda e: e["t"])
    return {"events": out[-limit:], "hours": hours, "total": len(out)}


WIN_EVENTS = {("User32", 1074): "Shutdown or restart asked for", ("Microsoft-Windows-Kernel-Power", 41): "Power lost",
              ("EventLog", 6008): "Windows: the last shutdown was unexpected",
              ("Microsoft-Windows-Kernel-General", 12): "Windows started",
              ("Microsoft-Windows-Kernel-General", 13): "Windows shut down",
              ("Display", 4101): "The display driver reset",
              ("Microsoft-Windows-Resource-Exhaustion-Detector", 2004): "Low on memory",
              ("Winlogon", 1002): "Explorer stopped and was restarted"}


RAN = re.compile(r"^(\d+)h (\d+)m (\d+)s$")


def human_ran(text):
    """How long something ran, as a record says it ("26h 12m 45s"), the way a person would: "26 h 13 min",
    "1 min 1 s". Anything else comes back as it was."""
    m = RAN.match(str(text or ""))
    if not m:
        return text
    s = int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))
    if s < 60:
        return "%d s" % s
    if s < 3600:
        return "%d min" % (s // 60) + (" %d s" % (s % 60) if s % 60 else "")
    mins = int(round(s / 60.0))
    if mins < 1440:
        return "%d h" % (mins // 60) + (" %d min" % (mins % 60) if mins % 60 else "")
    hrs = int(round(s / 3600.0))
    return "%d d" % (hrs // 24) + (" %d h" % (hrs % 24) if hrs % 24 else "")


# what Windows Error Reporting's report names mean (the ones the service keeps)
WER_MEANING = (("RADAR_PRE_LEAK", "Windows' memory-leak check flagged it"), ("AppHang", "it stopped responding"),
               ("LiveKernelEvent", "a driver recovered from a problem (often the graphics driver)"))


def describe(rec, t, src="service"):
    """One line for a record, and how bad it is: info, warn or bad."""
    k = rec.get("kind")
    level, text = "info", k
    # (records written by AppWatch, the script HW Blackbox grew out of, where its history was brought in)
    old = src == "service" and k in ("startup", "stop", "error") and "data_dir" not in rec and "why" not in rec \
        and "trace" not in rec
    who = "AppWatch" if old else "HW Blackbox's service" if src == "service" else "The session agent (%s)" % src
    if k == "exit":
        meaning = rec.get("meaning") or ""
        level = "bad" if "crash" in meaning else ("info" if (rec.get("code") or "") == "0x00000000" else "warn")
        text = "%s ended: %s (ran %s)" % (rec.get("app"), meaning, human_ran(rec.get("ran")))
        if rec.get("ports_now"):
            text += "; its port now: %s" % ", ".join("%s %s" % kv for kv in rec["ports_now"].items())
        if rec.get("while_shutting_down"):
            text += " (Windows was shutting down)"
            level = "info"
        elif rec.get("while_session_ends"):
            text += " (its session was ending: a sign-out or restart)"
            level = "info"
    elif k == "start":
        text = "%s started" % rec.get("app")
    elif k == "winevent":
        s, eid, ins = rec.get("source"), rec.get("id"), rec.get("inserts") or []
        base = WIN_EVENTS.get((s, eid))
        if s == "User32" and eid == 1074:
            proc = os.path.basename((ins[0] if ins else "?").split(" (")[0])
            text = "%s asked for by %s: %s" % ((ins[4] if len(ins) > 4 else "shutdown").capitalize(), proc,
                                               ins[2] if len(ins) > 2 else "?")
            level = "warn"
        elif base:
            text = base
            level = "bad" if eid in (41, 6008, 4101) else ("warn" if eid in (2004, 1002) else "info")
        elif s in ("Application Error", "Application Hang"):
            text = "%s %s%s" % (rec.get("app") or (ins[0] if ins else "?"),
                                "crashed" if s == "Application Error" else "hung",
                                (" in %s" % ins[3]) if s == "Application Error" and len(ins) > 3 else "")
            level = "bad"
        elif s == "Windows Error Reporting":
            name = ins[2] if len(ins) > 2 else "?"
            meaning = next((m for p, m in WER_MEANING if name.startswith(p)), None)
            text = "Windows Error Reporting, %s: %s" % (rec.get("app") or "?",
                                                         "%s (%s)" % (meaning, name) if meaning else name)
            level = "warn"
        elif s == "Service Control Manager":
            text = "The %s service ended unexpectedly" % (ins[0] if ins else "?")
            level = "warn"
        else:
            text = "%s %s" % (s, eid)
        if rec.get("backfill"):
            text += " (read after the fact)"
    elif k == "shutdown":
        if rec.get("phase") == "services stopping":
            text = "Windows is shutting down (services stopping)"
        elif rec.get("phase") == "asked":
            text = "Windows asked the session to %s" % (rec.get("type") or "end")
        else:
            text = "Ending the session: %s" % rec.get("phase")
        level = "warn"
    elif k == "power":
        text = "The PC is %s" % rec.get("event")
    elif k == "session":
        text = "Session %s: %s%s" % (rec.get("session", "?"), rec.get("event"),
                                     " (%s)" % rec["user"] if rec.get("user") else "")
    elif k == "display":
        text = "Screens: %s -> %s" % ("; ".join(rec.get("before") or []), "; ".join(rec.get("after") or []))
    elif k == "taskbar":
        text = "The taskbar came back (Explorer restarted)"
        level = "warn"
    elif k == "port":
        ev = rec.get("event")
        if ev in ("problem", "problem over"):
            text = ("Port problem: " if ev == "problem" else "Port problem over: ") + (rec.get("problem") or "")
            level = "bad" if ev == "problem" else "info"
        else:
            holder = "%s%s" % (rec.get("exe"), " (%s)" % rec["app"] if rec.get("app") else "")
            before = str(rec.get("before") or "")
            old_exe, _, old_pid = before.rpartition("/")
            if ev == "new owner" and old_exe and old_exe == rec.get("exe"):
                # the same program, a new process: it restarted
                text = "Port %s: %s restarted (pid %s, now %s)" % (rec.get("addr"), holder, old_pid, rec.get("pid"))
            elif ev == "new owner" and before:
                text = "Port %s: now %s (before: %s)" % (rec.get("addr"), holder,
                                                          "%s, pid %s" % (old_exe, old_pid) if old_exe else before)
            else:
                text = "Port %s %s: %s" % (rec.get("addr"), ev, holder)
    elif k == "startup":
        text = "%s started (%s%s)" % (who, "v" if old else "", rec.get("version"))
        prev = rec.get("previous_run") or {}
        if prev and not prev.get("ended_cleanly"):
            text += "; its last run ended without stopping"
            level = "warn"
    elif k == "stop":
        text = "%s stopped%s" % (who, " (%s)" % rec["why"] if rec.get("why") else "")
    elif k == "error":
        text = "Error in %s (%s): %s" % (who, rec.get("where"), rec.get("error"))
        level = "warn"
    elif k == "agent":
        text = "Session agent for %s (session %s): %s, %s" % (rec.get("user"), rec.get("session"), rec.get("event"),
                                                               rec.get("why"))
        level = "warn"
    elif k == "clock":
        text = "The clock was changed"
        level = "warn"
    elif k == "sensors":
        text = "Sensors open: %s sensors, LibreHardwareMonitor %s, NVML %s" % (rec.get("sensors"), rec.get("lhm"),
                                                                              rec.get("nvml"))
    elif k == "power_off_report":
        text = "Power-off report: %s" % rec.get("summary")
        level = "bad"
    elif k == "boot_part":
        text = "AppWatch's boot part: %s (%s)" % (rec.get("event"), rec.get("why"))
    group = {"exit": "apps", "start": "apps", "taskbar": "apps", "display": "apps", "session": "sessions",
             "winevent": "windows", "shutdown": "power", "power": "power", "port": "ports", "clock": "power",
             "power_off_report": "power"}.get(k, "monitor")
    if k == "winevent" and rec.get("id") in (41, 6008, 12, 13, 1074):
        group = "power"
    return {"t": t, "kind": k, "group": group, "level": level, "text": text, "src": src, "rec": rec}


def api_ports(q):
    data = read_json(paths.P.ports) or {}
    data["age"] = age(paths.P.ports)
    data["expected"] = (settings().get("ports") or {}).get("expected") or {}
    return data


def api_incidents(q):
    out = []
    try:
        names = os.listdir(paths.P.incidents)
    except OSError:
        names = []
    for name in names:
        if not INCIDENT_NAME.match(name):
            continue
        path = os.path.join(paths.P.incidents, name)
        title = ""
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                title = f.readline().strip()
            size = os.path.getsize(path)
        except OSError:
            continue
        when = dt.datetime.strptime(name[9:24], "%Y%m%d_%H%M%S").timestamp()
        out.append({"src": "power" if POWEROFF_NAME.match(name) else "app", "name": name, "t": when, "title": title,
                    "size": size})
    out.sort(key=lambda e: -e["t"])
    return {"incidents": out}


def api_incident(q):
    name = q.get("name") or ""
    if not INCIDENT_NAME.match(name):
        raise KeyError("no such report")
    with open(os.path.join(paths.P.incidents, name), encoding="utf-8", errors="replace") as f:
        return {"name": name, "text": f.read(400000).replace("\x00", "")}


class ProcessSampler:
    """The busiest processes: their share of the whole CPU since the last look (like Task Manager), and memory."""

    def __init__(self):
        self.lock = threading.Lock()
        self.prev = None                 # (time, snapshot)
        self.cache = None

    def sample(self):
        with self.lock:
            now = time.time()
            if self.cache and self.prev and now - self.prev[0] < 2:
                return self.cache
            snap = winapi.process_snapshot()
            ncpu = psutil.cpu_count() or 1
            rows = []
            for pid, p in snap.items():
                if pid == 0:
                    continue
                cpu = None
                if self.prev:
                    old = self.prev[1].get(pid)
                    if old and old.name == p.name and p.cpu >= old.cpu:
                        cpu = (p.cpu - old.cpu) / 1e7 / max(0.001, now - self.prev[0]) / ncpu * 100
                rows.append({"pid": pid, "name": p.name, "session": p.session,
                             "cpu": None if cpu is None else round(cpu, 1), "mem_mb": round(p.private / 2**20)})
            first = self.prev is None
            total = None
            if self.prev and 0 in snap and 0 in self.prev[1]:
                idle = (snap[0].cpu - self.prev[1][0].cpu) / 1e7 / max(0.001, now - self.prev[0]) / ncpu * 100
                total = round(min(100.0, max(0.0, 100 - idle)), 1)
            self.prev = (now, snap)
            vm = psutil.virtual_memory()
            self.cache = {
                "cpu": sorted((r for r in rows if r["cpu"] is not None), key=lambda r: -r["cpu"])[:15],
                "mem": sorted(rows, key=lambda r: -r["mem_mb"])[:15],
                "total_cpu": total, "count": len(rows), "warming_up": first, "threads": ncpu,
                "ram": {"total_gb": round(vm.total / 2**30, 1), "used_pct": vm.percent}}
            return self.cache


PROCESSES = ProcessSampler()


def api_config(q):
    cfg = config.public(settings())
    cfg["data_dir"] = paths.P.data
    return cfg


def page():
    """index.html with this version stamped in: an open page compares it with the API's version, and after an update
    it offers a reload instead of running an old page against the new program."""
    with open(PAGE, "rb") as f:
        return f.read().replace(b"__HWB_VERSION__", VERSION.encode("ascii"))


ROUTES = {"/api/overview": api_overview, "/api/sensors": api_sensors, "/api/history": api_history,
          "/api/flight_columns": api_flight_columns, "/api/rails": api_rails, "/api/events": api_events,
          "/api/ports": api_ports, "/api/incidents": api_incidents, "/api/incident": api_incident,
          "/api/processes": lambda q: PROCESSES.sample(), "/api/config": api_config,
          "/api/ping": lambda q: {"app": APP, "version": VERSION, "pid": os.getpid(), "user": winapi.user_name()}}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "HWBlackbox/%s" % VERSION
    last_request = time.time()

    def log_message(self, fmt, *args):            # (quiet: pythonw has nowhere to print)
        pass

    def send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data:; frame-ancestors 'none'; form-action 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        host = (self.headers.get("Host") or "").lower()
        if host not in self.server.allowed_hosts:
            self.send(421, b"Misdirected request", "text/plain")   # (a DNS-rebinding page, or a typo)
            return
        Handler.last_request = time.time()
        url = urllib.parse.urlsplit(self.path)
        q = {k: v[-1] for k, v in urllib.parse.parse_qs(url.query).items()}
        if url.path in ("/", "/index.html"):
            try:
                self.send(200, page(), "text/html; charset=utf-8")
            except OSError:
                self.send(500, b"index.html is missing", "text/plain")
            return
        fn = ROUTES.get(url.path)
        if not fn:
            self.send(404, b"Not found", "text/plain")
            return
        try:
            body = json.dumps(clean(fn(q)), default=str, allow_nan=False)
            self.send(200, body.encode("utf-8"), "application/json")
        except KeyError as e:
            self.send(404, json.dumps({"error": str(e)}).encode(), "application/json")
        except Exception as e:
            self.send(500, json.dumps({"error": "%s: %s" % (type(e).__name__, e)}).encode(), "application/json")


def clean(o):
    """JSON has no NaN or infinity: those become null."""
    if isinstance(o, float):
        return o if math.isfinite(o) else None
    if isinstance(o, dict):
        return {k: clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, array.array)):
        return [clean(v) for v in o]
    return o


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def server_bind(self):
        # the port to itself: on Windows another program could otherwise bind it too, on a more specific address
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def start(port):
    """Serve on 127.0.0.1:port from threads of its own; the server (OSError if the port is taken)."""
    httpd = Server(("127.0.0.1", port), Handler)
    httpd.allowed_hosts = {"127.0.0.1:%d" % port, "localhost:%d" % port}
    threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.5}, name="dashboard",
                     daemon=True).start()

    def janitor():
        while True:
            time.sleep(60)
            FLIGHT_CACHE.drop_if_idle()
    threading.Thread(target=janitor, name="dashboard-cache", daemon=True).start()
    return httpd


def who_serves(port):
    """'HW Blackbox, <user>'s' if an HW Blackbox dashboard answers on the port, else None."""
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/api/ping" % port, timeout=2) as r:
            j = json.loads(r.read())
        if j.get("app") == APP:
            return "HW Blackbox, %s's" % j.get("user")
    except Exception:
        pass
    return None
