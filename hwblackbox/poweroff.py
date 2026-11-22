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
from .util import iso_at, now_iso, parse_iso, read_json, read_log_bytes, write_json

CREATE_NO_WINDOW = 0x08000000


def _wevtutil(query, count):
    try:
        r = subprocess.run([os.path.join(paths.system_dir(), "wevtutil.exe"), "qe", "System", "/q:" + query, "/c:%d" % count, "/rd:true", "/f:text"],
                           capture_output=True, text=True, timeout=20, creationflags=CREATE_NO_WINDOW)
        # (the 6008 description ends in a NUL, and its date's direction marks come out as "?")
        return re.sub(r"\?(?=\d)", "", r.stdout.replace("\x00", "")).strip()
    except Exception:
        return ""


Q41 = "*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and (EventID=41)]]"
Q6008 = "*[System[(EventID=6008)]]"


def _event_time(query):
    """The newest matching System record's time (local, with its offset), through the event log API: wevtutil's text
    names its fields in Windows' display language ("Date:", "Datum:", ...), so only the report shows that text. Until
    1.2.0 it came without the offset: in the hour that repeats as daylight saving ends, a record from the second one
    was taken for an hour older, and a power loss and boot then got no report."""
    from .events import newest_event
    at, data = newest_event("System", query)
    if not at:
        return None
    if isinstance(data.get("_t"), (int, float)):
        return dt.datetime.fromtimestamp(data["_t"]).astimezone()
    try:
        return dt.datetime.strptime(at, "%Y-%m-%d %H:%M:%S").astimezone()
    except ValueError:
        return None


def event_epoch(at, data):
    """A record's time from newest_event, as epoch seconds (its exact "_t", else its local time read as such)."""
    if isinstance((data or {}).get("_t"), (int, float)):
        return data["_t"]
    try:
        return dt.datetime.strptime(at, "%Y-%m-%d %H:%M:%S").timestamp() if at else None
    except ValueError:
        return None


# The common blue screens' stop codes: their names (Microsoft's "Bug check code reference") and what they usually point
# at. A name is a hint where to look, not a diagnosis.
STOP_CODES = {
    0x0A: ("IRQL_NOT_LESS_OR_EQUAL", "usually a driver, sometimes the memory"),
    0x1A: ("MEMORY_MANAGEMENT", "often the memory (RAM) or its speed settings"),
    0x1E: ("KMODE_EXCEPTION_NOT_HANDLED", "usually a driver"),
    0x3B: ("SYSTEM_SERVICE_EXCEPTION", "usually a driver"),
    0x4E: ("PFN_LIST_CORRUPT", "often the memory (RAM)"),
    0x50: ("PAGE_FAULT_IN_NONPAGED_AREA", "a driver, or the memory"),
    0x7A: ("KERNEL_DATA_INPAGE_ERROR", "reading from the drive failed: the drive, its cable or controller"),
    0x7E: ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "usually a driver"),
    0x9F: ("DRIVER_POWER_STATE_FAILURE", "a driver failed going to sleep, waking, or a power change"),
    0xD1: ("DRIVER_IRQL_NOT_LESS_OR_EQUAL", "a driver (often network or storage)"),
    0xEF: ("CRITICAL_PROCESS_DIED", "a core Windows process ended: often the drive or a damaged Windows"),
    0x101: ("CLOCK_WATCHDOG_TIMEOUT", "a CPU core stopped answering: often an unstable CPU overclock or undervolt"),
    0x116: ("VIDEO_TDR_FAILURE", "the graphics driver or card couldn't be recovered"),
    0x119: ("VIDEO_SCHEDULER_INTERNAL_ERROR", "the graphics driver or card"),
    0x124: ("WHEA_UNCORRECTABLE_ERROR", "the hardware reported an error it couldn't correct (the CPU, memory or "
                                        "PCIe): often an unstable overclock, XMP / EXPO, or a failing part"),
    0x133: ("DPC_WATCHDOG_VIOLATION", "a driver took too long: often storage (SSD firmware) or graphics"),
    0x139: ("KERNEL_SECURITY_CHECK_FAILURE", "a driver, or damaged memory"),
    0x154: ("UNEXPECTED_STORE_EXCEPTION", "the drive (or its driver)"),
}


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
        code = num("BugcheckCode")
        name = STOP_CODES.get(code)
        return "Windows crashed: a blue screen, stop code 0x%08X%s" % (code, " (%s: %s)" % name if name else "")
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
    """The last n rows of one log file with a time before `before` (epoch seconds), as (epoch, 'file: row'). Reads
    from the end, widening the window until it reaches back far enough, and drops the NUL bytes a power loss can leave
    behind. A packed day (.csv.gz) is read whole."""
    name = os.path.basename(path)
    if name.endswith(".gz"):
        name = name[:-3]
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    window = 1 << 20
    while True:
        start = 0 if path.endswith(".gz") else max(0, size - window)
        try:
            if path.endswith(".gz"):
                data = read_log_bytes(path)
            else:
                with open(path, "rb") as fh:
                    fh.seek(start)
                    data = fh.read()
            lines = data.replace(b"\x00", b"").decode("utf-8", "replace").splitlines()
        except OSError:
            return []
        if start:
            lines = lines[1:]                 # (probably cut in half by the seek)
        rows, last = [], None
        for ln in lines:
            t = parse_iso(ln.split(",", 1)[0], last)
            if t is None:
                continue                      # the header, or a damaged line
            last = t
            if t < before:
                rows.append((t, "%s: %s" % (name, ln.rstrip())))
        if len(rows) >= n or start == 0:
            return rows[-n:]
        window *= 8


def _day_logs(prefix):
    """A log's day files, oldest first, each day once: its .csv, else its .csv.gz."""
    try:
        names = os.listdir(paths.P.logs)
    except OSError:
        return []
    days = {}
    for f in names:
        if f.startswith(prefix) and f.endswith((".csv", ".csv.gz")):
            day = f[len(prefix):len(prefix) + 8]
            if f.endswith(".csv") or day not in days:
                days[day] = f
    return [days[d] for d in sorted(days)]


def _tail_rows(prefix, before, n):
    """The last n rows written before `before` (epoch seconds), from the newest files of a log (named by day, so a
    file written only after the boot is passed over)."""
    files = _day_logs(prefix)
    rows = []
    for name in reversed(files[-3:]):
        rows = _rows_before(os.path.join(paths.P.logs, name), before, n - len(rows)) + rows
        if len(rows) >= n:
            break
    return rows[-n:]


def clock_set_back(now):
    """The newest row of the 5-second log (and the rails log) when it's later than `now`: rows from the future mean
    the clock now reads earlier than it did when they were written, so it was set back. A PC whose clock battery
    (the CMOS battery) has run flat boots after a power cut with its date years back, and Windows puts it right only
    once the network is up: the service starts before that. Returns (epoch of that row) or None."""
    newest = None
    for prefix in ("flight_", "rails_"):
        rows = _tail_rows(prefix, float("inf"), 1)
        if rows and (newest is None or rows[-1][0] > newest):
            newest = rows[-1][0]
    return newest if newest is not None and newest > now + 60 else None


# A blue screen's own record: Windows Error Reporting's BugCheck (System log, event 1001), written at the boot after it
# once the dump is saved, which can be minutes after the service started. Its values: the stop code with its four
# parameters, where the dump was saved, the report's id.
Q1001 = "*[System[Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] and (EventID=1001)]]"
LATER = None             # {"name", "boot", "last"}: a report written before its blue screen's record (bugcheck_later)


def bugcheck_record(since):
    """The newest BugCheck record written at or after `since` (epoch seconds): {"at", "bugcheck", "dump", "report"}, or
    None. The dump's path is Windows' own words, quoted, never opened: the service never follows a path from another
    program's record."""
    from .events import newest_event
    at, data = newest_event("System", Q1001)
    t = event_epoch(at, data)
    if t is None or t < since:
        return None
    vals = data.get("_values") or []
    pick = lambda name, i: str(data.get(name) or (vals[i] if len(vals) > i else "") or "").strip()   # noqa: E731
    return {"at": at, "bugcheck": pick("param1", 0)[:300], "dump": pick("param2", 1)[:260],
            "report": pick("param3", 2)[:80]}


def dump_files(since, folder=None):
    """The crash dumps Windows saved at or after `since` (epoch seconds): its Minidump folder's files and MEMORY.DMP,
    in Windows' own folder (from Windows, not a variable), as [(path, MB, epoch written)], newest first."""
    windir = folder or os.path.dirname(paths.system_dir())
    found = []
    candidates = [os.path.join(windir, "MEMORY.DMP")]
    try:
        candidates += [os.path.join(windir, "Minidump", f) for f in os.listdir(os.path.join(windir, "Minidump"))
                       if f.lower().endswith(".dmp")]
    except OSError:
        pass
    for p in candidates:
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if st.st_mtime >= since and not getattr(st, "st_file_attributes", 0) & 0x400:
            found.append((p, round(st.st_size / 2**20, 1), st.st_mtime))
    return sorted(found, key=lambda d: -d[2])[:5]


def bugcheck_text(rec, dumps):
    """The report's section on a blue screen: Windows' record and the dump files, or '' when there's neither."""
    if not rec and not dumps:
        return ""
    out = ["BLUE SCREEN (Windows Error Reporting's BugCheck record, event 1001, and the dump it saved):"]
    if rec:
        out.append("Recorded:     %s" % rec["at"])
        if rec["bugcheck"]:
            out.append("The bugcheck: %s  (the stop code, then its four parameters)" % rec["bugcheck"])
        if rec["dump"]:
            out.append("Dump saved:   %s  (as Windows recorded it)" % rec["dump"])
        if rec["report"]:
            out.append("Report id:    %s" % rec["report"])
    for p, size, t in dumps:
        out.append("Dump file:    %s  %.1f MB, written %s" % (p, size, iso_at(t).replace("T", " ")))
    if dumps:
        out.append("              (WinDbg, from the Microsoft Store, opens it: !analyze -v names the driver it "
                   "blames. Share it only with someone you trust: it holds part of what was in memory.)")
    return "\n".join(out) + "\n"


def _last_record_before(before):
    """The service's last record before `before` (epoch seconds) from the newest events_*.jsonl files, or None."""
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
                t = parse_iso(rec["ts"])
                if t is not None and t < before:
                    return rec
            except (ValueError, KeyError, TypeError):
                continue
    return None


def _existing_incident(boot):
    """An incident file already written for this boot (epoch seconds): named by this boot's time, or, in older
    reports, by its Event 6008's time a few seconds later."""
    try:
        for f in os.listdir(paths.P.incidents):
            m = re.match(r"incident_(\d{8}_\d{6})\.txt$", f)
            if m and abs(dt.datetime.strptime(m.group(1), "%Y%m%d_%H%M%S").timestamp() - boot) < 180:
                return f
    except (OSError, ValueError):
        pass
    return None


# a log row quoted in a report: "rails_20261023.csv: 2026-10-23T22:24:22.800,..." (since 1.1.0 with the offset)
ROW_TIME = re.compile(r"(?:flight|rails)_\d{8}\.csv: (\d{4}-\d\d-\d\dT[\d:.]+(?:[+-]\d\d:\d\d|Z)?),")


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
    died = None                                       # (epoch, the row's time as written)
    try:
        with open(os.path.join(paths.P.incidents, newest), encoding="utf-8", errors="replace") as f:
            for ln in f:
                m = ROW_TIME.match(ln.replace("\x00", ""))
                t = parse_iso(m.group(1)) if m else None
                if t is not None and (died is None or t > died[0]):
                    died = (t, m.group(1))
    except OSError:
        pass
    data = {"boot": dt.datetime.strptime(newest[9:24], "%Y%m%d_%H%M%S").isoformat(timespec="seconds"),
            "time_of_death": died[1] if died else None, "incident": newest}
    try:
        write_json(paths.P.last_incident, data)
    except Exception:
        pass
    return data


def check(boot=None, now=None):
    """If this boot followed a shutdown that wasn't clean, write the report (once per boot). Returns a one-line
    summary ('' if the last shutdown was clean). (boot / now are for tests.)"""
    boot = boot or boot_time()
    b = boot.timestamp()                              # (epoch seconds: the logs' times have an offset since 1.1.0)
    if (now or dt.datetime.now()).timestamp() - b > 48 * 3600:
        return ""
    margin = 120
    dirty = [t for t in (_event_time(Q41), _event_time(Q6008)) if t and t.timestamp() >= b - margin]
    if not dirty:
        return ""
    existing = _existing_incident(b)
    if existing:
        return "Dirty shutdown before this boot  ->  %s" % existing
    txt_41, txt_6008 = _wevtutil(Q41, 1), _wevtutil(Q6008, 1)      # (the records as text, for the report)
    from .events import hardware_records, newest_event
    at41, data41 = newest_event("System", Q41)
    t41 = event_epoch(at41, data41)
    why = why_41(data41) if t41 is not None and t41 >= b - margin else ""
    os.makedirs(paths.P.incidents, exist_ok=True)
    name = "incident_%s.txt" % boot.strftime("%Y%m%d_%H%M%S")
    # The last rows before the boot, by their times. With the clock set back (clock_set_back) every row is "after" the
    # boot by time: then the newest rows are taken whatever their time (until 1.2.0 the report had none).
    back = clock_set_back((now or dt.datetime.now()).timestamp())
    before = float("inf") if back else b
    flight = _tail_rows("flight_", before, 120)
    rails = _tail_rows("rails_", before, 240)
    ends = [rows[-1][0] for rows in (flight, rails) if rows]
    last = max(ends) if ends else None
    rec = _last_record_before(before)
    # the hardware's own error records (WHEA) from an hour before it went down to 15 minutes after the boot: a fatal
    # one is written at the boot after the crash it caused
    hw = hardware_records(last - 3600, last + 3600) + hardware_records(b - 120, b + 900) if back and last else \
        hardware_records((last or b) - 3600, b + 900)
    # a blue screen's own record and dump (the record may come minutes later: then bugcheck_later adds it). With the
    # clock set back, a dump's time can't say whether it's this one's: none listed.
    bsod = bugcheck_record(b - margin)
    dumps = dump_files(min(b, last or b) - 600) if not back else []
    desc = ""
    m = re.search(r"Description:\s*(.+)", txt_6008, re.DOTALL)
    if m:
        desc = " ".join(m.group(1).split())[:200]
    with open(os.path.join(paths.P.incidents, name), "w", encoding="utf-8") as f:
        f.write("HW Blackbox: power-off report (written %s)\n" % now_iso())
        f.write("=" * 70 + "\n\n")
        f.write("Booted at:    %s, after a shutdown that wasn't clean\n" % iso_at(b).replace("T", " "))
        if back:
            f.write("The clock:    it read the time above at the boot, earlier than the last rows (%s): it was set\n"
                    "              back, most likely by a flat clock battery (the CMOS battery on the board). The rows\n"
                    "              below are the last ones written, with the times the clock had then; the gap\n"
                    "              can't be told.\n" % iso_at(back).replace("T", " "))
        if last:
            f.write("Went down:    %s  (the last sample before the gap; Windows' own\n"
                    "              estimate in the 6008 below can be many minutes off)\n"
                    % iso_at(last, ms=True).replace("T", " "))
            if not back:
                f.write("Gap:          %d s\n" % (b - last))
        if rec:
            said = "a clean shutdown had begun" if rec.get("kind") == "shutdown" else "no shutdown had begun"
            f.write("Last record:  %s %s (%s)\n" % (rec.get("ts", "?").replace("T", " "), rec.get("kind"), said))
        if why:
            f.write("Why:          %s  (Windows' Kernel-Power 41 record)\n" % why)
        battery = battery_before(flight)
        if battery:
            f.write("Battery:      %s  (the last sample before the gap)\n" % battery)
        if hw:
            fatal = sum(1 for r in hw if r["fatal"])
            f.write("Hardware:     %d hardware error record%s around it%s  (Windows' WHEA records, below)\n" % (
                len(hw), "" if len(hw) == 1 else "s", ", %d of them fatal" % fatal if fatal else ""))
        if hw:
            f.write("\nHARDWARE ERRORS (WHEA-Logger, from an hour before to 15 minutes after the boot):\n")
            for r in hw:
                f.write("%s  WHEA %d, %s: %s\n" % (r["at"], r["id"], "fatal" if r["fatal"] else "corrected",
                                                  r["text"]))
            f.write("\n")
        if bsod or dumps:
            f.write("\n" + bugcheck_text(bsod, dumps))
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
        write_json(paths.P.last_incident, {"boot": iso_at(b), "time_of_death": iso_at(last, ms=True) if last else None,
                                           "incident": name})
    except Exception:
        pass
    global LATER
    LATER = {"name": name, "boot": b, "last": last} if why.startswith("Windows crashed") and not bsod else None
    return "Dirty shutdown detected: %s  ->  %s" % (desc or boot, name)


def bugcheck_later(stop, waits=(120, 300, 600, 900)):
    """A report written after a blue screen before Windows had written the BugCheck record: look again at 2, 5, 10 and
    15 minutes of uptime, and add the record (and the dump files) to the end of the report when it comes."""
    global LATER
    want, LATER = LATER, None
    if not want:
        return
    path = os.path.join(paths.P.incidents, want["name"])
    for at in waits:
        wait = want["boot"] + at - time.time()
        if wait > 0 and stop.wait(wait):
            return
        rec = bugcheck_record(want["boot"] - 120)
        if rec or at == waits[-1]:
            text = bugcheck_text(rec, dump_files(min(want["boot"], want["last"] or want["boot"]) - 600))
            if text:
                try:
                    with open(path, "a", encoding="utf-8") as f:
                        f.write("\n(added %s, %s)\n%s" % (
                            now_iso().replace("T", " "), "once Windows had written its record" if rec else
                            "15 minutes after the boot: Windows wrote no BugCheck record", text))
                        f.flush()
                        os.fsync(f.fileno())
                except OSError:
                    pass
            return


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
                if LATER:
                    bugcheck_later(stop)
                return
        except Exception:
            pass
