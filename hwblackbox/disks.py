r"""The drives' free space: every fixed drive once a minute into a log, and the Windows drive's problems for the status.

  logs\disks_YYYYMMDD.csv   timestamp, drive, free_gb, total_gb: a row per fixed drive a minute (about 100 KB a day
                            for two drives). One drive a row, so drives can come and go without the columns changing.

The problems (the Windows drive only): less than disk_warn_gb free, or filling up fast: disk_drop_gb gone within the
last hour AND, at that rate, under disk_warn_gb within SOON (a download, a build, an update unpacking). A drive with
room to spare that swings by tens of GB (temporary files written and deleted all day) isn't in danger, and
2026-10-23 showed it: a dozen phone alerts for that, from the drop alone. Once on, "filling up fast" stays on for
HOLD after it's last true, so a swing doesn't make it flicker. Other drives are logged and charted, not judged: a
data drive that's nearly full is often meant to be."""
import collections
import csv
import datetime as dt
import os
import shutil
import time

import psutil

from . import paths
from .util import now_iso, parse_iso, prune

COLUMNS = ["timestamp", "drive", "free_gb", "total_gb"]
WINDOW = 3600          # seconds "filling fast" looks back
SOON = 7200            # ... and how soon, at that rate, the drive must be headed under disk_warn_gb for it to count
HOLD = 900             # seconds "filling fast" stays on after it was last true
LIST_EVERY = 600       # seconds between looks at which drives there are (slow with a network or removable drive)


def fmt_minutes(m):
    return "%d min" % max(1, round(m)) if m < 60 else "%d h %02d min" % (m // 60, m % 60)


def system_drive():
    return (os.environ.get("SystemDrive") or "C:").rstrip("\\").upper()


def fixed_drives():
    """['C:', 'G:', ...]: the fixed drives (not removable, network or optical)."""
    return [p.mountpoint.rstrip("\\").upper() for p in psutil.disk_partitions(all=False) if "fixed" in (p.opts or "")]


def path_for(day):
    """The log for a day ("2026-10-21" or a date)."""
    return os.path.join(paths.P.logs, "disks_%s.csv" % str(day).replace("-", ""))


def read_rows(path):
    """[(epoch, drive, free_gb, total_gb)] from a day's log; damaged rows skipped."""
    out = []
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            for row in csv.reader(line.replace("\x00", "") for line in f):
                if len(row) < 4 or row[0] == "timestamp":
                    continue
                t = parse_iso(row[0])
                try:
                    if t:
                        out.append((t, row[1], float(row[2]), float(row[3])))
                except ValueError:
                    continue
    except OSError:
        pass
    return out


class DiskWatch:
    def __init__(self, jrnl, keep_days):
        self.jrnl = jrnl
        self.keep_days = keep_days
        self.drives = []
        self.listed = 0.0
        self.now = {}                           # drive -> (free GB, total GB): the latest look
        self.history = collections.deque()      # (epoch, free GB) of the Windows drive over the last WINDOW seconds
        self.day = None
        self.noted = None                       # the last error written to the journal (each one once)
        self.fast = None                        # (text, until): "filling up fast", held on for HOLD
        self.seed()

    def seed(self):
        """The last hour from the log, so a restart doesn't forget a drop that's under way."""
        sysd, cutoff = system_drive(), time.time() - WINDOW
        for day in sorted({dt.date.fromtimestamp(cutoff), dt.date.today()}):
            for t, drive, free, _total in read_rows(path_for(day)):
                if drive == sysd and t >= cutoff:
                    self.history.append((t, free))

    def sample(self, now=None):
        now = now or time.time()
        try:
            if not self.drives or now - self.listed > LIST_EVERY:
                self.drives = fixed_drives() or [system_drive()]
                self.listed = now
            seen, rows, ts = {}, [], now_iso()
            for d in self.drives:
                try:
                    u = shutil.disk_usage(d + "\\")
                except OSError:
                    continue
                seen[d] = (round(u.free / 2**30, 2), round(u.total / 2**30, 1))
                rows.append([ts, d, seen[d][0], seen[d][1]])
            self.now = seen
            sysd = system_drive()
            if sysd in seen:
                self.history.append((now, seen[sysd][0]))
            while self.history and self.history[0][0] < now - WINDOW:
                self.history.popleft()
            self.write(ts[:10], rows)
        except Exception as e:
            msg = ("%s: %s" % (type(e).__name__, e))[:300]
            if msg != self.noted:
                self.noted = msg
                self.jrnl.write("error", {"where": "disk space", "error": msg})

    def write(self, day, rows):
        path = path_for(day)
        new = not os.path.exists(path)
        with open(path, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new:
                w.writerow(COLUMNS)
            w.writerows(rows)
        if day != self.day:
            if self.day is not None:            # a new day: the clean-up
                prune(paths.P.logs, "disks_", ".csv", self.keep_days)
            self.day = day

    def free_gb(self):
        """The Windows drive's free space at the latest look (None before the first)."""
        return (self.now.get(system_drive()) or (None,))[0]

    def problems(self, cfg, now=None):
        """The Windows drive's problems, in words."""
        sysd, free, now = system_drive(), self.free_gb(), now or time.time()
        if free is None:
            return []
        out = []
        warn = cfg.get("disk_warn_gb") or 10
        if free < warn:
            out.append("%s has only %.1f GB free" % (sysd, free))
        drop, fast = cfg.get("disk_drop_gb") or 0, None
        if drop > 0 and self.history and free >= warn:
            t_hi, hi = max(self.history, key=lambda x: x[1])
            gone, mins = hi - free, max(1.0, (now - t_hi) / 60)
            left = (free - warn) / (gone / mins) if gone > 0 else None      # minutes until under warn, at this rate
            if gone >= drop and left is not None and left * 60 <= SOON:
                fast = "%s is filling up fast: %.1f GB gone in %s; at that rate it's under %g GB free in about %s" % (
                    sysd, gone, fmt_minutes(mins), warn, fmt_minutes(left))
        if fast:
            self.fast = (fast, now + HOLD)
        elif self.fast and now < self.fast[1] and drop > 0 and free >= warn:
            fast = self.fast[0]                                              # (held on: no flicker)
        else:
            self.fast = None
        if fast:
            out.append(fast)
        return out
