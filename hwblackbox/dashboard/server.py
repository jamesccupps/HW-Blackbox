r"""The dashboard's server: one page (index.html) and a read-only JSON API over HW Blackbox's files.

  Overview    the service and the session agents, problems, the key readings now, power-offs, disks
  Sensors     every sensor: current / minimum / maximum / average, since the page opened or since the service started
  Charts      the 5-second log and the drives' free space (a reading a minute), any range from an hour to 7 days (the
              line is the average, the band the min and max)
  Power       the 4-a-second rails (the last minutes) and every power-off caught
  Events      the records: apps closing and crashing, shutdowns and who asked, sessions, ports, Windows' own records
  Ports       who listens on which port, and port problems
  Incidents   the power-off and app incident reports, to read in place
  Processes   what's using the CPU and the memory right now, and each program's CPU use over the last week

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

from .. import NAME, VERSION, config, paths, poweroff, update, winapi
from ..events import WHEA_WORDS, disk_error, hardware_error
from ..util import age, log_path, parse_iso, read_json, read_log_bytes, tail_lines

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
    ("battery_pct", ("Battery charge", "%", "Battery")),
])
RAILS = ("v12_v", "v5_v", "v33_v", "vcore_v", "vsoc_v", "cpu_power_w", "cpu_temp_c")
# records worth a line on the Events page (the rest are bulky or minute-by-minute)
EVENT_KINDS = {"exit", "start", "winevent", "shutdown", "power", "session", "display", "taskbar", "port", "startup",
               "stop", "error", "agent", "clock", "sensors", "power_off_report", "boot_part", "logs"}
# the kinds a session agent writes: the only ones taken from sessions\ (which every user can write a folder in)
AGENT_KINDS = {"display", "taskbar", "shutdown", "startup", "stop", "error"}
POWEROFF_NAME = re.compile(r"incident_\d{8}_\d{6}\.txt$")
OFFSET = r"(?:[+-]\d\d:\d\d|Z)?"                    # (a time's offset from UTC: written since 1.1.0)
INCIDENT_NAME = re.compile(r"incident_\d{8}_\d{6}[\w.\-]*\.txt$")


def epoch(text):
    try:
        return dt.datetime.fromisoformat(text).timestamp()
    except (TypeError, ValueError):
        return None


def settings():
    return config.load()


def session_dirs():
    """[(user folder name, path)] for every session agent's folder (not one that's a link to somewhere else)."""
    try:
        return [(e.name, e.path) for e in os.scandir(paths.P.sessions)
                if e.is_dir(follow_symlinks=False) and not e.is_junction()]
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
        path = log_path(os.path.join(paths.P.logs, name))
        packed = path.endswith(".gz")                     # (a day two or more days old: whole, and it won't grow)
        try:
            size = os.path.getsize(path)
        except OSError:
            return None
        with self.lock:
            self.used = time.time()
            c = self.files.get(name)
            if c is None or size < c["size"] or packed != c.get("packed", False) or (packed and size != c["size"]):
                c = self.files[name] = {"size": 0, "pos": 0, "head": None, "t": array.array("d"), "cols": [],
                                        "packed": packed}
            self.files.move_to_end(name)
            while len(self.files) > self.KEEP:
                self.files.popitem(last=False)
            if size > c["pos"]:
                if packed:
                    chunk = read_log_bytes(path)
                    c["pos"] = size
                    end = len(chunk)
                else:
                    with open(path, "rb") as f:
                        f.seek(c["pos"])
                        chunk = f.read(size - c["pos"])
                    end = chunk.rfind(b"\n") + 1               # (a row still being written waits for next time)
                    c["pos"] += end
                lines = chunk[:end].replace(b"\x00", b"").decode("utf-8", "replace").splitlines()
                for row in csv.reader(lines):
                    if not row:
                        continue
                    if row[0] == "timestamp":
                        # (the column names again, partway down: an update that added columns. Every column keeps
                        # a value for every row: a new one starts with blanks for the rows before it)
                        c["head"] = row
                        for col in row[1:]:
                            if col not in c:
                                c[col] = array.array("d", [math.nan]) * len(c["t"])
                                c["cols"].append(col)
                        continue
                    # (the row before says which of the hour that repeats as daylight saving ends a time without an
                    # offset is: rows written before 1.1.0 have none)
                    t = parse_iso(row[0], c["t"][-1] if c["t"] else None)
                    if t is None or c["head"] is None:
                        continue
                    c["t"].append(t)
                    for i, col in enumerate(c["head"][1:], start=1):
                        v = row[i] if i < len(row) else ""
                        try:
                            c[col].append(float(v) if v != "" else math.nan)
                        except ValueError:
                            c[col].append(math.nan)
                    for col in c["cols"]:
                        if len(c[col]) < len(c["t"]):                 # (a column the newest names don't have)
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
        "drives": (read_json(paths.P.drives) or {}).get("drives") or [],
        "milestones": (cfg.get("dashboard") or {}).get("milestones") or [],
        "first_log": cached("first_log", 300, first_log_day),
    }


def first_log_day():
    try:
        names = sorted(f for f in os.listdir(paths.P.logs) if f.startswith("flight_") and f.endswith((".csv",
                                                                                                    ".csv.gz")))
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
    # (each column once: a column asked for many times over would be read that many times over, into gigabytes)
    want = list(dict.fromkeys((q.get("cols") or "cpu_temp_c,gpu_temp_c").split(",")))[:64]
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


def has_battery():
    try:
        return psutil.sensors_battery() is not None
    except Exception:
        return False


def api_flight_columns(q):
    battery = cached("battery", 300, has_battery)          # (a desktop's chart list doesn't offer a battery)
    return {"cols": [{"id": c, "label": l, "unit": u, "group": g} for c, (l, u, g) in FLIGHT.items()
                     if battery or g != "Battery"] +
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
    path = log_path(path_for(day))
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


# each program's use (logs\programs_YYYYMMDD.csv, and 1.0.7's cpu_YYYYMMDD.csv: programs) -----------------------------

_prog_files = {}                # name -> (size, rows)
_prog_lock = threading.Lock()


def _rows_of(path):
    """A log's rows, parsed again only when the file has grown."""
    from ..programs import read_rows
    path = log_path(path)
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    name = os.path.basename(path)
    with _prog_lock:
        hit = _prog_files.get(name)
        if not hit or hit[0] != size:
            hit = _prog_files[name] = (size, read_rows(path))
            while len(_prog_files) > 20:
                _prog_files.pop(next(iter(_prog_files)))
        return hit[1]


def program_rows(start, end):
    """[(epoch, seconds, program, cpu_s, mem_mb, vram_mb, gpu_pct, processes, pid)] for start <= t <= end."""
    from ..programs import OLD_PREFIX, PREFIX, path_for
    rows = []
    d = dt.date.fromtimestamp(start)
    while d <= dt.date.fromtimestamp(end):
        for prefix in (OLD_PREFIX, PREFIX):
            rows.extend(r for r in _rows_of(path_for(d, prefix)) if start <= r[0] <= end)
        d += dt.timedelta(days=1)
    rows.sort(key=lambda r: r[0])
    return rows


METRICS = {"cpu": (3, "%"), "mem": (4, "MB"), "vram": (5, "MB"), "gpu": (6, "%")}    # (the row's field, the unit)


def api_programs(q):
    """Each program's use over the last hours, of one thing ("metric": cpu, mem, vram or gpu): the leading programs
    and, for each, its value per time bucket.
      cpu    a share of the whole processor, as Task Manager's: 100 % is every logical processor flat out (one core flat
             out is 100 / threads); the busiest programs by CPU time
      gpu    a share of the busiest GPU engine, as Task Manager's GPU column; by GPU time
      mem    private memory, MB; vram: dedicated graphics memory, MB. Levels, not rates: a bucket's value is the
             average of its minutes, and the leaders are the biggest at their peak. "change" is the last minute's
             value less the first's: how much it grew."""
    from ..programs import ALL
    metric = q.get("metric") if q.get("metric") in METRICS else "cpu"
    col, unit = METRICS[metric]
    rate = metric in ("cpu", "gpu")
    hours = min(24 * 7, max(0.25, float(q.get("hours") or 6)))
    points = min(1000, max(20, int(q.get("points") or 240)))
    n = min(40, max(1, int(q.get("n") or 15)))
    end = time.time()
    start = end - hours * 3600
    st = read_json(paths.P.status) or {}
    threads = ((st.get("pc") or {}).get("threads")) or psutil.cpu_count() or 1
    rows = program_rows(start, end)
    step = max(60.0, (end - start) / points)
    nb = int(math.ceil((end - start) / step))
    covered = [0.0] * nb                         # seconds logged in each bucket with this metric (the "(all)" rows)
    minutes = [0] * nb
    total = [0.0] * nb
    per = collections.defaultdict(lambda: [0.0] * nb)
    cnt = collections.defaultdict(lambda: [0] * nb)
    stats = {}
    last_minute = None
    # a minute's amount, to add up: CPU seconds; GPU percent-seconds; MB as they are
    amount = (lambda v, secs: v) if metric == "cpu" else (lambda v, secs: v * secs) if metric == "gpu" else \
        (lambda v, secs: v)
    level = (lambda v, secs: v / secs) if metric == "cpu" else (lambda v, secs: v)    # cores, %, MB
    for r in rows:
        t, secs, prog, v = r[0], r[1], r[2], r[col]
        if v is None or secs <= 0:
            continue
        b = min(nb - 1, int((t - start) / step))
        if prog == ALL:
            covered[b] += secs
            minutes[b] += 1
            total[b] += amount(v, secs)
            last_minute = t
            continue
        per[prog][b] += amount(v, secs)
        cnt[prog][b] += 1
        s = stats.setdefault(prog, {"sum": 0.0, "peak": -1.0, "peak_at": None, "minutes": 0, "first": None,
                                    "last": None, "last_t": None})
        s["sum"] += amount(v, secs)
        s["minutes"] += 1
        if level(v, secs) > s["peak"]:
            s["peak"], s["peak_at"] = level(v, secs), t
        if s["first"] is None:
            s["first"] = v
        s["last"], s["last_t"] = v, t
    logged = sum(covered)

    def show(x, cpu_cores=False):              # cores into a share of the CPU; the rest as they are
        if x is None:
            return None
        return round(100.0 * x / threads, 2) if cpu_cores else round(x, 2)
    out = []
    for p, s in stats.items():
        e = {"name": p, "minutes": s["minutes"], "peak_at": s["peak_at"]}
        if rate:
            e["avg"] = show(s["sum"] / logged, metric == "cpu") if logged else None
            e["peak"] = show(s["peak"], metric == "cpu")
            e["key"] = s["sum"]
        else:
            e["avg"], e["peak"], e["key"] = show(s["sum"] / s["minutes"]), show(s["peak"]), s["peak"]
            e["now"] = show(s["last"]) if last_minute is not None and s["last_t"] >= last_minute - 1 else None
            e["change"] = show(s["last"] - s["first"])
        if metric == "cpu":
            e.update(cpu_s=round(s["sum"], 1), avg_cores=round(s["sum"] / logged, 3) if logged else None,
                     peak_cores=round(s["peak"], 3))
        out.append(e)
    out.sort(key=lambda e: -e.pop("key"))
    programs = out[:n]

    def bucket(sum_, k, b):                    # a bucket's value, None where nothing was logged
        if not covered[b]:
            return None
        if metric == "cpu":
            return round(100.0 * sum_ / (covered[b] * threads), 2)
        if metric == "gpu":
            return round(sum_ / covered[b], 2)
        return round(sum_ / k, 1) if k else None
    series = {p["name"]: [bucket(per[p["name"]][b], cnt[p["name"]][b], b) for b in range(nb)] for p in programs}
    return {"metric": metric, "unit": unit, "start": start, "end": end, "step": step, "threads": threads,
            "logged_s": round(logged), "t": [round(start + (b + 0.5) * step, 1) for b in range(nb)],
            "programs": programs, "series": series,
            "total": [bucket(total[b], minutes[b], b) for b in range(nb)]}


# the Diagnose tab: diagnose.py judges, this gathers --------------------------------------------------------------------

DIAG_COLS = ("cpu_temp_c", "gpu_temp_c", "v12_v", "v5_v", "v33_v", "ram_pct", "gpu_vram_mb", "battery_pct", "on_ac")
_programs = {}                  # an exe's path -> the program it belongs to (winapi.program_of)


def diagnose_inputs(now=None):
    """What the checks look at: the status, the last day of the 5-second log and of the programs log, the last week of
    the service's exits and Windows' records, every power-off, and the last day's screen changes."""
    now = now or time.time()
    day = now - 86400
    ts, flight = FLIGHT_CACHE.rows_between(day, now, list(DIAG_COLS))
    sens = read_json(paths.P.sensors) or {}
    records, displays, watched = [], [], {}
    d = dt.date.fromtimestamp(now - 7 * 86400)
    while d <= dt.date.fromtimestamp(now):
        for i, (_src, path) in enumerate(journal_files(d)):
            agent = i > 0                                # (the first is the service's own)
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if agent:
                            if '"kind": "display"' not in line:
                                continue
                        elif '"kind": "mem"' in line:
                            # the watched apps' memory every minute (older than the programs log, so a leak that
                            # began before the update still shows): {exe: [(t, MB)]}
                            try:
                                rec = json.loads(line)
                                t = epoch(rec.get("ts"))
                                if t is None or t < day or t > now + 300:
                                    continue
                                by = collections.Counter()
                                for key, v in (rec.get("private_mb") or {}).items():
                                    by[str(key).rpartition("/")[0]] += float(v)
                                for exe, v in by.items():
                                    watched.setdefault(exe, []).append((t, v))
                            except (ValueError, TypeError, AttributeError):
                                pass
                            continue
                        elif '"kind": "exit"' not in line and '"kind": "winevent"' not in line:
                            continue
                        try:
                            rec = json.loads(line)
                        except ValueError:
                            continue
                        if not isinstance(rec, dict):
                            continue
                        t = (epoch(rec.get("at")) if rec.get("kind") == "winevent" else None) or epoch(rec.get("ts"))
                        if t is None or t > now + 300:
                            continue
                        if agent and rec.get("kind") == "display" and t >= day:
                            displays.append(t)
                        elif not agent and rec.get("kind") in ("exit", "winevent"):
                            rec["t"] = t
                            ins = rec.get("inserts") or []
                            if rec.get("source") == "Application Error" and not rec.get("program") and len(ins) > 10:
                                # (recorded before 1.1.0, without the program: worked out from the exe's path now)
                                if ins[10] not in _programs:
                                    _programs[ins[10]] = winapi.program_of(ins[10])
                                rec["program"] = _programs[ins[10]]
                            records.append(rec)
            except OSError:
                continue
        d += dt.timedelta(days=1)
    from .. import drives
    drive_rows = []
    d = dt.date.fromtimestamp(now - 30 * 86400)
    while d <= dt.date.fromtimestamp(now):
        drive_rows.extend(drives.read_rows(drives.path_for(d)))
        d += dt.timedelta(days=1)
    return {"now": now, "status": read_json(paths.P.status) or {}, "status_age": age(paths.P.status),
            "cfg": settings(), "sensors": sens.get("sensors") or [], "flight_t": list(ts),
            "flight": {c: [None if v != v else v for v in vals] for c, vals in flight.items()},
            "programs": program_rows(day, now), "power_offs": power_offs(), "records": records,
            "displays": displays, "watched_mem": watched, "drives": read_json(paths.P.drives) or {},
            "drive_rows": drive_rows}


def diagnose_now():
    from .. import diagnose
    return diagnose.run(diagnose_inputs())


def api_rails(q):
    """The last minutes of the 4-a-second lane, read from the end of the file(s)."""
    minutes = min(60, max(1, float(q.get("minutes") or 10)))
    end = time.time()
    start = end - minutes * 60
    rows = []
    for d in sorted({dt.date.fromtimestamp(start), dt.date.fromtimestamp(end)}):
        path = log_path(os.path.join(paths.P.logs, "rails_%s.csv" % d.strftime("%Y%m%d")))
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        want = int(minutes * 60 * 4 * 100 * 1.3) + 4096      # (rows are about 75 bytes; with the offset, 81)
        if path.endswith(".gz"):                     # (packed: only with the clock put back days)
            data = read_log_bytes(path)
            size = len(data)
            text = data[-want:].replace(b"\x00", b"").decode("utf-8", "replace")
        else:
            with open(path, "rb") as f:
                f.seek(max(0, size - want))
                text = f.read().replace(b"\x00", b"").decode("utf-8", "replace")
        lines = text.splitlines()
        if size > want:
            lines = lines[1:]                        # (cut in half by the seek)
        last = None
        for row in csv.reader(lines):
            if not row or row[0] == "timestamp":
                continue
            t = parse_iso(row[0], last)
            if t is not None:
                last = t
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
        died, last_rails = None, None                 # (epoch, the time as written[, the rest of the row])
        for m in re.finditer(r"^(flight|rails)_\d{8}\.csv: (\d{4}-\d\d-\d\dT[\d:.]+%s),(.*)$" % OFFSET, text,
                             re.MULTILINE):
            t = parse_iso(m.group(2))
            if t is None:
                continue
            if died is None or t > died[0]:
                died = (t, m.group(2))
            if m.group(1) == "rails" and (last_rails is None or t > last_rails[0]):
                last_rails = (t, m.group(2), m.group(3))
        died = died[1] if died else None
        m = re.search(r"Went down:\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?%s)" % OFFSET, text)
        if m:
            died = m.group(1).replace(" ", "T")
        m = re.search(r"Booted at:\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d%s)" % OFFSET, text)
        boot = m.group(1).replace(" ", "T") if m else None
        if not boot:                    # (older reports are named by Windows' 6008 record, written at the boot)
            boot = dt.datetime.strptime(name[9:24], "%Y%m%d_%H%M%S").isoformat()
        est = re.search(r"previous system shutdown at ([\d:]+ [AP]M)", text)
        # how it went off (Windows' Kernel-Power 41 record): in the report since 1.0.9, looked up once for older ones
        m = re.search(r"^Why:\s+(.+?)\s+\(Windows'", text, re.MULTILINE)
        why = m.group(1) if m else WHY_41.get(name)
        if why is None:
            try:
                why = poweroff.why_near(dt.datetime.fromisoformat(boot))
            except Exception:
                why = ""
            WHY_41[name] = why
        m = re.search(r"^Battery:\s+(.+?)\s+\(the last", text, re.MULTILINE)
        battery = m.group(1) if m else None
        rails = None
        if last_rails:
            v = last_rails[2].split(",")
            rails = {k: (float(x) if x else None) for k, x in zip(RAILS, v)}
        b, d = epoch(boot), epoch(died) if died else None
        out.append({"report": name, "boot": boot, "went_down": died, "gap_s": round(b - d, 1) if b and d else None,
                    "windows_estimate": est.group(1) if est else None, "last_rails": rails, "why": why or None,
                    "battery": battery})
    return out


WHY_41 = {}             # report -> how it went off, for the reports that don't say (a record that can't change)


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
    now = time.time()
    cutoff = now - hours * 3600
    out = []
    d = dt.date.fromtimestamp(cutoff)
    while d <= dt.date.today():
        for i, (src, path) in enumerate(journal_files(d)):
            agent = i > 0                                # (the first is the service's own)
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if '"kind": "mem"' in line or '"kind": "watching"' in line or '"shutdown_snapshot"' in line:
                            continue
                        try:
                            rec = json.loads(line)
                        except ValueError:
                            continue
                        if not isinstance(rec, dict) or rec.get("kind") not in (AGENT_KINDS if agent else EVENT_KINDS):
                            continue
                        # (Windows' records at the time they happened: one read after a restart was written later)
                        t = (epoch(rec.get("at")) if rec.get("kind") == "winevent" else None) or epoch(rec.get("ts"))
                        if t is None or t < cutoff or t > now + 300:
                            continue
                        try:
                            out.append(describe(rec, t, src, agent=agent))
                        except Exception:                # (a damaged or odd record: the rest still show)
                            continue
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


def describe(rec, t, src="service", agent=None):
    """One line for a record, and how bad it is: info, warn or bad. agent: from a session agent's folder (src is then
    the folder's name, whatever it is: a folder named "service" is still a session agent's)."""
    if agent is None:
        agent = src != "service"
    k = rec.get("kind")
    level, text = "info", k
    # (records written by AppWatch, the script HW Blackbox grew out of, where its history was brought in)
    old = not agent and k in ("startup", "stop", "error") and "data_dir" not in rec and "why" not in rec \
        and "trace" not in rec
    who = "AppWatch" if old else "The session agent (%s)" % src if agent else "HW Blackbox's service"
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
        elif rec.get("shell_running"):
            text += " (an extra Explorer, started to open a folder or a program; the taskbar's kept running)"
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
        elif hardware_error(rec):
            part, fatal = hardware_error(rec)
            text = "A %s hardware error in %s (WHEA %s)" % ("fatal" if fatal else "corrected", WHEA_WORDS[part], eid)
            level = "bad" if fatal else "warn"
        elif disk_error(rec):
            what, level, disk = disk_error(rec)
            text = "%s: %s (%s %s)" % ("Disk %d" % disk if disk is not None else "A drive", what, s, eid)
        else:
            text = "%s %s" % (s, eid)
        if rec.get("skipped_before"):
            text += " (%d more like it in the hour before, left out of the records)" % rec["skipped_before"]
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
    elif k == "logs":
        text = "Packed %s old day logs into .csv.gz (a tenth of the size; read as before)" % rec.get("files")
    group = {"exit": "apps", "start": "apps", "taskbar": "apps", "display": "apps", "session": "sessions",
             "winevent": "windows", "shutdown": "power", "power": "power", "port": "ports", "clock": "power",
             "power_off_report": "power"}.get(k, "monitor")
    if k == "winevent" and rec.get("id") in (41, 6008, 12, 13, 1074):
        group = "power"
    if k == "winevent" and (hardware_error(rec) or disk_error(rec)):
        group = "hardware"
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


_checkers = {}


def checker():
    """The update check for this page's user, kept in their session folder (when the agent has made it)."""
    c = _checkers.get(paths.P.data)
    if c is None:
        d = paths.P.session_dir(winapi.user_name())
        c = _checkers[paths.P.data] = update.Checker(os.path.join(d, "update.json") if os.path.isdir(d) else None)
    return c


def api_update(q):
    v = checker().view(bool((settings().get("updates") or {}).get("check", True)), now=bool(q.get("check")))
    v["installable"] = update.installed_python() is not None
    return v


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
          "/api/processes": lambda q: PROCESSES.sample(), "/api/programs": api_programs,
          "/api/diagnose": lambda q: cached("diagnose", 0 if q.get("fresh") else 60, diagnose_now),
          "/api/config": api_config, "/api/update": api_update,
          "/api/ping": lambda q: {"app": APP, "version": VERSION, "pid": os.getpid(), "user": winapi.user_name()}}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "HWBlackbox/%s" % VERSION
    last_request = time.time()
    timeout = 15                                 # (a connection that sends nothing doesn't hold a thread for ever)

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
        url = urllib.parse.urlsplit(self.path)
        # The data only for this page itself (or a program that isn't a browser): a browser says where a request comes
        # from, and another site's page has no business asking. (Opening the page from a link elsewhere is fine.)
        site = self.headers.get("Sec-Fetch-Site")
        if url.path.startswith("/api/") and site and site not in ("same-origin", "none"):
            self.send(403, b"Cross-site request", "text/plain")
            return
        Handler.last_request = time.time()
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

    def do_POST(self):
        """The page's one action: Update. Only from this page itself: the browser says where a request comes from, and
        the X-HWB header makes any other site's page ask first (which this server never answers). Windows' admin
        prompt is the real gate, and the command it starts is fixed: nothing from the request goes into it."""
        host = (self.headers.get("Host") or "").lower()
        if host not in self.server.allowed_hosts:
            self.send(421, b"Misdirected request", "text/plain")
            return
        if self.headers.get("Sec-Fetch-Site") != "same-origin" or self.headers.get("X-HWB") != "1":
            self.send(403, b"Only from the page itself", "text/plain")
            return
        Handler.last_request = time.time()
        n = int(self.headers.get("Content-Length") or 0)
        if 0 < n <= 4096:
            self.rfile.read(n)
        if urllib.parse.urlsplit(self.path).path != "/api/update/install":
            self.send(404, b"Not found", "text/plain")
            return
        try:
            body = update.launch()
        except Exception as e:
            body = {"error": "%s: %s" % (type(e).__name__, e)}
        self.send(200, json.dumps(body).encode("utf-8"), "application/json")


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


def who_serves(port, wait=3.0):
    """'HW Blackbox, <user>'s' if an HW Blackbox dashboard answers on the port, else None. Asked from a thread of its
    own, for `wait` seconds at most: whatever holds the port can't keep the caller (the agent's only thread) waiting,
    however slowly it answers."""
    found = []

    def ask():
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))     # (straight there, no proxy)
            with opener.open("http://127.0.0.1:%d/api/ping" % port, timeout=2) as r:
                j = json.loads(r.read(4096))
            if isinstance(j, dict) and j.get("app") == APP:
                found.append("HW Blackbox, %s's" % j.get("user"))
        except Exception:
            pass
    t = threading.Thread(target=ask, name="who-serves", daemon=True)
    t.start()
    t.join(wait)
    return found[0] if found else None
