r"""Power-offs: when this boot followed a shutdown that wasn't clean, an incident report.

Windows records a boot after a power loss with Kernel-Power 41 ("rebooted without cleanly shutting down") and
EventLog 6008 ("the previous system shutdown was unexpected"). The report (incidents\incident_<boot time>.txt) has
those records, the time the PC really went down (the logs' last row before the gap: Windows' own estimate can be
half an hour off), the gap, and the last rows of both sensor logs, the 4-a-second rails trace last.
The service also says goodbye on every clean shutdown ("shutdown" record, phase "services stopping"), so the report
says whether the last thing it wrote was that goodbye."""
import csv
import datetime as dt
import json
import os
import re
import subprocess
import time

from . import paths
from .util import now_iso, read_json, write_json

CREATE_NO_WINDOW = 0x08000000


def _wevtutil(query, count):
    try:
        r = subprocess.run(["wevtutil", "qe", "System", "/q:" + query, "/c:%d" % count, "/rd:true", "/f:text"],
                           capture_output=True, text=True, timeout=20, creationflags=CREATE_NO_WINDOW)
        # (the 6008 description ends in a NUL, and its date's direction marks come out as "?")
        return re.sub(r"\?(?=\d)", "", r.stdout.replace("\x00", "")).strip()
    except Exception:
        return ""


Q41 = "*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and (EventID=41)]]"
Q6008 = "*[System[(EventID=6008)]]"


def _event_time(query):
    """The newest matching System record's local time, through the event log API: wevtutil's text names its fields
    in Windows' display language ("Date:", "Datum:", ...), so only the report shows that text."""
    from .events import newest_event
    at, _ = newest_event("System", query)
    try:
        return dt.datetime.strptime(at, "%Y-%m-%d %H:%M:%S") if at else None
    except ValueError:
        return None


def why_41(data):
    """What Windows' Kernel-Power 41 record says about how the PC went off, in words ('' when it says nothing: the power
    was cut, or the PC froze so hard that nothing was recorded)."""
    data = data or {}

    def num(key):
        v = str(data.get(key) or "0").strip()
        for base in (10, 16):
            try:
                return int(v, base)
            except ValueError:
                continue
        return 0
    if num("BugcheckCode"):
        return "Windows crashed: a blue screen, stop code 0x%08X" % num("BugcheckCode")
    if str(data.get("LongPowerButtonPressDetected")).lower() == "true" or num("PowerButtonTimestamp"):
        return "the power button was held down (a forced power-off)"
    if num("SleepInProgress"):
        return "it went off going into or coming out of sleep"
    if str(data.get("ConnectedStandbyInProgress")).lower() == "true":
        return "it went off while asleep (Modern Standby)"
    return ""


def why_near(boot):
    """why_41 for the Kernel-Power 41 record of one boot (written from 2 minutes before it to 15 after; boot is local
    time): for the reports from before 1.0.9, which don't say."""
    from .events import newest_event
    lo, hi = [(boot + dt.timedelta(minutes=m)).astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
              for m in (-2, 15)]
    at, data = newest_event("System", "*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and (EventID=41) and "
                                      "TimeCreated[@SystemTime>='%s' and @SystemTime<='%s']]]" % (lo, hi))
    return why_41(data) if at else ""


def battery_before(rows):
    """'12 %, on battery' from the 5-second log's last row that has the battery (rows as _tail_rows gives them), or
    ''. The battery's columns are the log's last two, so they're the same place in every version's rows."""
    from .sensors import COLUMNS
    i, j = COLUMNS.index("battery_pct"), COLUMNS.index("on_ac")
    for _t, text in reversed(rows):
        try:
            v = next(csv.reader([text.split(": ", 1)[1]]))
        except (IndexError, StopIteration):
            continue
        if len(v) > j and v[i] != "":
            return "%s %%, %s" % (v[i], {"1": "plugged in", "0": "on battery"}.get(v[j], "power source unknown"))
    return ""


def boot_time():
    import psutil
    return dt.datetime.fromtimestamp(psutil.boot_time())


def _rows_before(path, before, n):
    """The last n rows of one log file with a time before `before`, as (time, 'file: row'). Reads from the end,
    widening the window until it reaches back far enough, and drops the NUL bytes a power loss can leave behind."""
    name = os.path.basename(path)
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    window = 1 << 20
    while True:
        start = max(0, size - window)
        try:
            with open(path, "rb") as fh:
                fh.seek(start)
                lines = fh.read().replace(b"\x00", b"").decode("utf-8", "replace").splitlines()
        except OSError:
            return []
        if start:
            lines = lines[1:]                 # (probably cut in half by the seek)
        rows = []
        for ln in lines:
            try:
                t = dt.datetime.fromisoformat(ln.split(",", 1)[0])
            except ValueError:
                continue                      # the header, or a damaged line
            if t < before:
                rows.append((t, "%s: %s" % (name, ln.rstrip())))
        if len(rows) >= n or start == 0:
            return rows[-n:]
        window *= 8


def _tail_rows(prefix, before, n):
    """The last n rows written before `before`, from the newest files of a log (named by day, so a file written only
    after the boot is passed over)."""
    try:
        files = sorted(f for f in os.listdir(paths.P.logs) if f.startswith(prefix) and f.endswith(".csv"))
    except OSError:
        return []
    rows = []
    for name in reversed(files[-3:]):
        rows = _rows_before(os.path.join(paths.P.logs, name), before, n - len(rows)) + rows
        if len(rows) >= n:
            break
    return rows[-n:]


def _last_record_before(before):
    """The service's last record before `before` (from the newest events_*.jsonl files), or None."""
    try:
        files = sorted(f for f in os.listdir(paths.P.logs) if f.startswith("events_") and f.endswith(".jsonl"))
    except OSError:
        return None
    for name in reversed(files[-3:]):
        try:
            with open(os.path.join(paths.P.logs, name), "rb") as f:
                f.seek(0, 2)
                f.seek(max(0, f.tell() - (4 << 20)))
                lines = f.read().replace(b"\x00", b"").decode("utf-8", "replace").splitlines()
        except OSError:
            continue
        for line in reversed(lines):
            try:
                rec = json.loads(line)
                if dt.datetime.fromisoformat(rec["ts"]) < before:
                    return rec
            except (ValueError, KeyError, TypeError):
                continue
    return None


def _existing_incident(boot):
    """An incident file already written for this boot (named by this boot's time, or, in older reports, by its Event
    6008's time a few seconds later)."""
    try:
        for f in os.listdir(paths.P.incidents):
            m = re.match(r"incident_(\d{8}_\d{6})\.txt$", f)
            if m and abs((dt.datetime.strptime(m.group(1), "%Y%m%d_%H%M%S") - boot).total_seconds()) < 180:
                return f
    except (OSError, ValueError):
        pass
    return None


def last_dirty_shutdown():
    """{boot, time_of_death, incident} of the latest power-off report (state\\last_incident.json; worked out once from
    the newest report when the file is missing)."""
    data = read_json(paths.P.last_incident)
    if data:
        return data
    try:
        names = sorted(f for f in os.listdir(paths.P.incidents) if re.match(r"incident_\d{8}_\d{6}\.txt$", f))
    except OSError:
        names = []
    if not names:
        return None
    newest = names[-1]
    died = None
    try:
        with open(os.path.join(paths.P.incidents, newest), encoding="utf-8", errors="replace") as f:
            for ln in f:
                m = re.match(r"(?:flight|rails)_\d{8}\.csv: (\d{4}-\d\d-\d\dT[\d:.]+),", ln.replace("\x00", ""))
                if m and (died is None or m.group(1) > died):
                    died = m.group(1)
    except OSError:
        pass
    data = {"boot": dt.datetime.strptime(newest[9:24], "%Y%m%d_%H%M%S").isoformat(timespec="seconds"),
            "time_of_death": died, "incident": newest}
    try:
        write_json(paths.P.last_incident, data)
    except Exception:
        pass
    return data


def check(boot=None, now=None):
    """If this boot followed a shutdown that wasn't clean, write the report (once per boot). Returns a one-line
    summary ('' if the last shutdown was clean). (boot / now are for tests.)"""
    boot = boot or boot_time()
    if (now or dt.datetime.now()) - boot > dt.timedelta(hours=48):
        return ""
    margin = dt.timedelta(minutes=2)
    dirty = [t for t in (_event_time(Q41), _event_time(Q6008)) if t and t >= boot - margin]
    if not dirty:
        return ""
    existing = _existing_incident(boot)
    if existing:
        return "Dirty shutdown before this boot  ->  %s" % existing
    txt_41, txt_6008 = _wevtutil(Q41, 1), _wevtutil(Q6008, 1)      # (the records as text, for the report)
    from .events import newest_event
    at41, data41 = newest_event("System", Q41)
    why = why_41(data41) if at41 and dt.datetime.strptime(at41, "%Y-%m-%d %H:%M:%S") >= boot - margin else ""
    os.makedirs(paths.P.incidents, exist_ok=True)
    name = "incident_%s.txt" % boot.strftime("%Y%m%d_%H%M%S")
    flight = _tail_rows("flight_", boot, 120)
    rails = _tail_rows("rails_", boot, 240)
    ends = [rows[-1][0] for rows in (flight, rails) if rows]
    last = max(ends) if ends else None
    rec = _last_record_before(boot)
    desc = ""
    m = re.search(r"Description:\s*(.+)", txt_6008, re.DOTALL)
    if m:
        desc = " ".join(m.group(1).split())[:200]
    with open(os.path.join(paths.P.incidents, name), "w", encoding="utf-8") as f:
        f.write("HW Blackbox: power-off report (written %s)\n" % now_iso())
        f.write("=" * 70 + "\n\n")
        f.write("Booted at:    %s, after a shutdown that wasn't clean\n" % boot.isoformat(sep=" ", timespec="seconds"))
        if last:
            f.write("Went down:    %s  (the last sample before the gap; Windows' own\n"
                    "              estimate in the 6008 below can be many minutes off)\n"
                    % last.isoformat(sep=" ", timespec="milliseconds"))
            f.write("Gap:          %d s\n" % (boot - last).total_seconds())
        if rec:
            said = "a clean shutdown had begun" if rec.get("kind") == "shutdown" else "no shutdown had begun"
            f.write("Last record:  %s %s (%s)\n" % (rec.get("ts", "?").replace("T", " "), rec.get("kind"), said))
        if why:
            f.write("Why:          %s  (Windows' Kernel-Power 41 record)\n" % why)
        battery = battery_before(flight)
        if battery:
            f.write("Battery:      %s  (the last sample before the gap)\n" % battery)
        f.write("\nEVENT 6008 (unexpected shutdown):\n%s\n\n" % txt_6008)
        f.write("EVENT 41 (Kernel-Power, check BugcheckCode):\n%s\n\n" % txt_41)
        f.write("LAST SAMPLES BEFORE THE GAP (last %d rows):\n" % len(flight))
        f.write("\n".join(r for _, r in flight) + "\n")
        if rails:
            f.write("\nSUB-SECOND RAIL TRACE BEFORE THE GAP (last %d rows):\n" % len(rails))
            f.write("\n".join(r for _, r in rails) + "\n")
        f.flush()
        os.fsync(f.fileno())
    try:
        write_json(paths.P.last_incident, {"boot": boot.isoformat(timespec="seconds"),
                                           "time_of_death": last.isoformat(timespec="milliseconds") if last else None,
                                           "incident": name})
    except Exception:
        pass
    return "Dirty shutdown detected: %s  ->  %s" % (desc or boot, name)


def rechecks(stop, jrnl=None):
    """A boot's Event 41 / 6008 can land after the service has started (it starts at boot too): look again at 1 and
    3 minutes of uptime."""
    boot = boot_time().timestamp()
    for at in (60, 180):
        wait = boot + at - time.time()
        if wait > 0 and stop.wait(wait):
            return
        try:
            found = check()
            if found:
                if jrnl:
                    jrnl.write("power_off_report", {"summary": found})
                return
        except Exception:
            pass
