r"""How much of the CPU each program used, minute by minute. Windows keeps no such history: Task Manager shows now,
and its App history only totals. This comes from the process list the watcher takes every 2 s anyway (one call to
Windows, which hands over every process's CPU time with it), so it costs next to nothing.

  logs\cpu_YYYYMMDD.csv   timestamp, seconds, program, cpu_s, processes, pid: a row per busy program a minute

  timestamp   the end of the minute
  seconds     how long that "minute" was (a little more after a stall)
  program     the exe name: all of a program's processes together (Chrome's dozens are one row)
  cpu_s       the CPU time they used in it, all cores together: 60 in a minute is one core flat out
  processes   how many of its processes used any; pid: the busiest one

A program under MIN_SHARE of one core in a minute isn't written for that minute. Two rows that aren't programs are
written every minute: "System interrupts", the time the processors spent on drivers' interrupts and DPCs, which Windows
charges to no process (Task Manager's row of that name), and "(all)", everything together. A process that ends
between two looks loses at most its last 2 s.

On 2026-11-05 a core was kept busy all night by something, and only Windows' running totals were left to point at
the desktop compositor (dwm.exe), most likely. This log would have shown it, minute by minute."""
import collections
import csv
import os
import time

import psutil

from . import paths
from .util import now_iso, prune

COLUMNS = ["timestamp", "seconds", "program", "cpu_s", "processes", "pid"]
MIN_SHARE = 0.01                 # of one core over the minute: a program under that isn't written for it
TOP = 12                         # programs written a minute at most (besides the two rows that aren't programs)
INTERRUPTS = "System interrupts"
ALL = "(all)"
RECENT = 60                      # minutes kept in memory (for the incident reports)


def path_for(day):
    """The log for a day ("2026-11-06" or a date)."""
    return os.path.join(paths.P.logs, "cpu_%s.csv" % str(day).replace("-", ""))


def interrupt_seconds():
    """The processors' time on interrupts and DPCs since boot, all of them together (None if Windows won't say)."""
    try:
        t = psutil.cpu_times()
        return t.interrupt + t.dpc
    except Exception:
        return None


def read_rows(path):
    """[(epoch, seconds, program, cpu_s, processes, pid)] from a day's log; damaged rows skipped."""
    from .util import parse_iso
    out = []
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            for row in csv.reader(line.replace("\x00", "") for line in f):
                if len(row) < 6 or row[0] == "timestamp":
                    continue
                t = parse_iso(row[0])
                try:
                    if t:
                        out.append((t, float(row[1]), row[2], float(row[3]), int(row[4] or 0),
                                    int(row[5]) if row[5] else None))
                except ValueError:
                    continue
    except OSError:
        pass
    return out


class CpuLog:
    def __init__(self, keep_days):
        self.keep_days = keep_days
        self.prev = None             # the last look: (time.monotonic(), epoch, {pid: (created, CPU time in 100 ns)})
        self.began = None            # time.monotonic() of the look the minute began with
        self.irq_mark = None         # interrupt + DPC seconds then
        self.acc = {}                # program -> [CPU time in 100 ns, {pid: CPU time}] since then
        self.names = {}              # pid -> name, of the processes that used any this minute
        self.recent = collections.deque(maxlen=RECENT)    # (epoch, seconds, [(program, cpu_s, processes, pid)])
        self.day = None

    def look(self, snap, now=None, wall=None):
        """Count a process snapshot (winapi.process_snapshot(): every process with its CPU time so far): what each
        process used since the last look."""
        now = time.monotonic() if now is None else now
        wall = time.time() if wall is None else wall
        cur = {pid: (p.created, p.cpu) for pid, p in snap.items() if pid}       # (pid 0: the idle time)
        if self.prev is None:
            self.prev, self.began, self.irq_mark = (now, wall, cur), now, interrupt_seconds()
            return
        _then, then_wall, old = self.prev
        for pid, (created, cpu) in cur.items():
            o = old.get(pid)
            if o is not None and abs(o[0] - created) < 1:
                used = cpu - o[1]
            elif created >= then_wall - 2:
                used = cpu                   # started since the last look: all its time is new
            else:
                used = 0                     # (missing from the last look, yet older than it: not counted)
            if used > 0:
                name = snap[pid].name
                a = self.acc.get(name)
                if a is None:
                    a = self.acc[name] = [0, {}]
                a[0] += used
                a[1][pid] = a[1].get(pid, 0) + used
        self.prev = (now, wall, cur)

    def minute(self):
        """The minute's rows into the log (the watcher calls this once a minute), and a new minute begins."""
        if self.prev is None or self.began is None:
            return None
        secs = self.prev[0] - self.began
        if secs <= 0:
            return None
        irq = interrupt_seconds()
        irq_s = max(0.0, irq - self.irq_mark) if irq is not None and self.irq_mark is not None else 0.0
        progs = sorted(((name, a[0] / 1e7, len(a[1]), max(a[1], key=a[1].get)) for name, a in self.acc.items()),
                       key=lambda r: -r[1])
        total = sum(r[1] for r in progs) + irq_s
        rows = [r for r in progs if r[1] >= MIN_SHARE * secs][:TOP]
        rows += [(INTERRUPTS, irq_s, 0, None), (ALL, total, len(self.prev[2]), None)]
        ts = now_iso()
        self.write(ts, secs, rows)
        self.recent.append((time.time(), secs, rows))
        self.acc, self.began, self.irq_mark = {}, self.prev[0], irq
        return rows

    def write(self, ts, secs, rows):
        day = ts[:10]
        path = path_for(day)
        new = not os.path.exists(path)
        with open(path, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new:
                w.writerow(COLUMNS)
            w.writerows([ts, round(secs, 1), name, round(cpu_s, 2), n, "" if pid is None else pid]
                        for name, cpu_s, n, pid in rows)
        if day != self.day:
            if self.day is not None:            # a new day: the clean-up
                prune(paths.P.logs, "cpu_", ".csv", self.keep_days)
            self.day = day

    def busiest(self, minutes=3, n=8):
        """The programs that used the most CPU over the last few minutes (the minute under way too), as lines for a
        report: "dwm.exe: 98 % of one core (1 process, pid 1752)"."""
        used, secs, procs = collections.Counter(), 0.0, {}
        for _t, s, rows in list(self.recent)[-minutes:]:
            secs += s
            for name, cpu_s, k, pid in rows:
                if name != ALL:
                    used[name] += cpu_s
                    procs[name] = (k, pid)
        if self.prev is not None and self.began is not None:
            secs += self.prev[0] - self.began
            for name, a in self.acc.items():
                used[name] += a[0] / 1e7
                procs[name] = (len(a[1]), max(a[1], key=a[1].get))
        if secs <= 0:
            return []
        out = []
        for name, cpu_s in used.most_common(n):
            k, pid = procs.get(name, (0, None))
            out.append("%s: %.0f %% of one core%s" % (name, 100 * cpu_s / secs, "" if pid is None else
                       " (%d process%s, the busiest pid %d)" % (k, "" if k == 1 else "es", pid)))
        return out
