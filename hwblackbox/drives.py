r"""The drives' health, once an hour, from Windows' own storage counters (the ones Get-PhysicalDisk and
Get-StorageReliabilityCounter show): what Windows thinks of each drive, its temperature, how worn it is, and the errors
it has counted. SYSTEM can read them; a standard user can't (so HW Blackbox's page reads them from here).

  state\drives.json          the latest look: {"ts", "drives": [...], "error"}
  logs\drives_YYYYMMDD.csv   a row per drive an hour: timestamp, disk, model, health, temp_c, wear_pct,
                             read_err_unc, write_err_unc, read_err_total, write_err_total, power_on_h

A drive's number is Windows' (Disk Management's "Disk 1", and \Device\Harddisk1 in the drives' error records).
Counters a drive doesn't report are blank. Nothing here changes anything on a drive: it's reading only."""
import csv
import os
import threading
import time

from . import paths
from .util import ensure_line_end, now_iso, open_log, parse_iso, prune, write_json

COLUMNS = ["timestamp", "disk", "model", "health", "temp_c", "wear_pct", "read_err_unc", "write_err_unc",
           "read_err_total", "write_err_total", "power_on_h"]
EVERY = 3600                     # seconds between looks
FIRST = 120                      # seconds after the service starts: the first look
HEALTH = {0: "healthy", 1: "warning", 2: "unhealthy", 5: "unknown"}
MEDIA = {3: "HDD", 4: "SSD", 5: "SCM"}
BUS = {1: "SCSI", 2: "ATAPI", 3: "ATA", 6: "Fibre Channel", 7: "USB", 8: "RAID", 9: "iSCSI", 10: "SAS", 11: "SATA",
       12: "SD", 13: "MMC", 15: "File-backed virtual", 16: "Storage Spaces", 17: "NVMe"}


def path_for(day):
    return os.path.join(paths.P.logs, "drives_%s.csv" % str(day).replace("-", ""))


def _num(v):
    try:
        return None if v is None else int(v)
    except (TypeError, ValueError):
        return None


def look():
    """Every physical drive Windows knows, with its counters: [{disk, model, media, bus, size_gb, health, temp_c,
    temp_max_c, wear_pct, read_err_unc, write_err_unc, read_err_total, write_err_total, power_on_h}], and an error
    (None, or why the counters couldn't be read: they need SYSTEM or an admin)."""
    from .agents import com_cache_ok
    if not com_cache_ok():
        return [], "pywin32's COM cache isn't the program's own: not asking Windows"
    import pythoncom
    import win32com.client
    # (COM stays set up on the calling thread: undone here, the objects released after it print an error each)
    pythoncom.CoInitialize()
    wmi = win32com.client.GetObject(r"winmgmts:{impersonationLevel=impersonate}!\\.\root\Microsoft\Windows\Storage")
    out, by_id = [], {}
    for d in wmi.ExecQuery("SELECT DeviceId, FriendlyName, MediaType, BusType, HealthStatus, Size "
                           "FROM MSFT_PhysicalDisk"):
        e = {"disk": _num(d.DeviceId), "model": (d.FriendlyName or "?").strip()[:80],
             "media": MEDIA.get(_num(d.MediaType)), "bus": BUS.get(_num(d.BusType)),
             "size_gb": round(int(d.Size or 0) / 1e9), "health": HEALTH.get(_num(d.HealthStatus), "unknown")}
        out.append(e)
        by_id[str(d.DeviceId)] = e
    error = None
    try:
        for r in wmi.ExecQuery("SELECT * FROM MSFT_StorageReliabilityCounter"):
            e = by_id.get(str(r.DeviceId))
            if e is None:
                continue
            e.update(temp_c=_num(r.Temperature) or None, temp_max_c=_num(r.TemperatureMax) or None,
                     wear_pct=_num(r.Wear), read_err_unc=_num(r.ReadErrorsUncorrected),
                     write_err_unc=_num(r.WriteErrorsUncorrected), read_err_total=_num(r.ReadErrorsTotal),
                     write_err_total=_num(r.WriteErrorsTotal), power_on_h=_num(r.PowerOnHours))
    except Exception as ex:                      # (a standard user: WBEM_E_ACCESS_DENIED)
        denied = "0x80041003" in str(ex) or "-2147217405" in str(ex)
        error = "the drives' counters need SYSTEM or an admin" if denied else ("the drives' counters: %s" % ex)[:200]
    out.sort(key=lambda e: (e["disk"] is None, e["disk"]))
    return out, error


def read_rows(path):
    """[(epoch, disk, {column: value})] from a day's log (packed or not)."""
    out, last = [], None
    try:
        with open_log(path) as f:
            for row in csv.reader(line.replace("\x00", "") for line in f):
                if len(row) < len(COLUMNS) or row[0] == "timestamp":
                    continue
                t = parse_iso(row[0], last)
                if t is None:
                    continue
                last = t
                vals = {}
                for k, v in zip(COLUMNS[3:], row[3:]):
                    vals[k] = v if k == "health" else (_num(v) if v != "" else None)
                vals["model"] = row[2]
                out.append((t, _num(row[1]), vals))
    except OSError:
        pass
    return out


class DriveWatch:
    """The hourly look, on a thread of its own (a slow WMI answer never holds the watcher up)."""

    def __init__(self, jrnl, keep_days):
        self.jrnl = jrnl
        self.keep_days = keep_days
        self.latest = None               # (time, drives, error)
        self.day = None
        self.noted = None

    def start(self, stop):
        threading.Thread(target=self._run, args=(stop,), name="drives", daemon=True).start()

    def _run(self, stop):
        if stop.wait(FIRST):
            return
        while True:
            self.sample()
            if stop.wait(EVERY):
                return

    def sample(self):
        try:
            drives, error = look()
        except Exception as e:
            drives, error = [], ("%s: %s" % (type(e).__name__, e))[:200]
        self.latest = (time.time(), drives, error)
        try:
            write_json(paths.P.drives, {"ts": now_iso(), "drives": drives, "error": error})
            if drives:
                self.write(drives)
        except Exception as e:
            error = error or ("%s: %s" % (type(e).__name__, e))[:200]
        if error != self.noted:
            self.noted = error
            if error:
                self.jrnl.write("error", {"where": "drive health", "error": error})

    def write(self, drives):
        ts = now_iso()
        day = ts[:10]
        path = path_for(day)
        new = not os.path.exists(path)
        if day != self.day and not new:
            ensure_line_end(path)
        with open(path, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new:
                w.writerow(COLUMNS)
            for d in drives:
                w.writerow([ts, "" if d["disk"] is None else d["disk"], d["model"], d["health"]] +
                           ["" if d.get(k) is None else d[k] for k in COLUMNS[4:]])
        if day != self.day:
            if self.day is not None:
                prune(paths.P.logs, "drives_", ".csv", self.keep_days)
            self.day = day

    def problems(self):
        """A drive Windows itself calls unhealthy: back it up now. (Wear, errors and heat are the Diagnose tab's.)"""
        if not self.latest:
            return []
        return ["Windows says disk %s (%s) is failing: back it up now" % (d["disk"], d["model"])
                for d in self.latest[1] if d.get("health") == "unhealthy"]
