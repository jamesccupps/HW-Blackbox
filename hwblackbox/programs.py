r"""What each program used, minute by minute: the CPU, memory, graphics memory and the GPU. Windows keeps no such
history: Task Manager shows now, and its App history only totals.

The CPU and memory come from the process list the watcher takes every 2 s anyway (one call to Windows, which hands
over every process's CPU time and memory with it). The GPU's come from Windows' own GPU counters (the ones Task
Manager's GPU columns use, for any make of GPU), read once a minute on a thread of their own.

  logs\programs_YYYYMMDD.csv   timestamp, seconds, program, cpu_s, mem_mb, vram_mb, gpu_pct, processes, pid

  timestamp   the end of the minute
  seconds     how long that "minute" was (a little more after a stall)
  program     the exe name: all of a program's processes together (Chrome's dozens are one row)
  cpu_s       the CPU time they used in the minute, all cores together: 60 is one core flat out
  mem_mb      their private memory (what they've committed: Task Manager's "commit size"), the most in the minute
  vram_mb     their dedicated graphics memory (blank when Windows' GPU counters can't be read)
  gpu_pct     their share of the busiest GPU engine (3D, video decode, copy...), as Task Manager's GPU column
  processes   how many processes it had; pid: the busiest one (by CPU, else by memory)

A program is written for a minute when it's among the TOP busiest or biggest in any of these (and over that one's
threshold). Two rows that aren't programs are written every minute: "System interrupts", the time the processors
spent on drivers' interrupts and DPCs, which Windows charges to no process (Task Manager's row of that name), and
"(all)", everything together. A process that ends between two looks loses at most its last 2 s of CPU.

1.0.7 wrote logs\cpu_YYYYMMDD.csv (the CPU alone: timestamp, seconds, program, cpu_s, processes, pid); read_rows
reads both. On 2026-11-05 a core was kept busy all night by something, and only Windows' running totals were left to
point at the desktop compositor (dwm.exe), most likely: this log shows that kind of thing minute by minute."""
import collections
import csv
import os
import re
import threading
import time

import psutil

from . import paths
from .util import ensure_line_end, now_iso, open_log, parse_iso, prune

PREFIX = "programs_"
OLD_PREFIX = "cpu_"                                  # (1.0.7)
COLUMNS = ["timestamp", "seconds", "program", "cpu_s", "mem_mb", "vram_mb", "gpu_pct", "processes", "pid"]
OLD_COLUMNS = ["timestamp", "seconds", "program", "cpu_s", "processes", "pid"]
# what makes a program worth a row for the minute: among the TOP in one of these, and over its threshold
TOP = 12
MIN_SHARE = 0.01                 # of one core over the minute
MIN_MEM_MB = 200
MIN_VRAM_MB = 64
MIN_GPU_PCT = 1.0
INTERRUPTS = "System interrupts"
ALL = "(all)"
RECENT = 60                      # minutes kept in memory (for the incident reports)
GPU_EVERY = 60.0                 # seconds between reads of the GPU counters
GPU_FRESH = 150.0                # the oldest GPU read a minute's rows take


def path_for(day, prefix=PREFIX):
    """The log for a day ("2026-11-06" or a date)."""
    return os.path.join(paths.P.logs, "%s%s.csv" % (prefix, str(day).replace("-", "")))


def interrupt_seconds():
    """The processors' time on interrupts and DPCs since boot, all of them together (None if Windows won't say)."""
    try:
        t = psutil.cpu_times()
        return t.interrupt + t.dpc
    except Exception:
        return None


def _num(text, kind=float):
    return kind(text) if text not in ("", None) else None


def read_rows(path):
    """[(epoch, seconds, program, cpu_s, mem_mb, vram_mb, gpu_pct, processes, pid)] from a day's log, this version's
    or 1.0.7's (no memory or GPU: None); damaged rows skipped."""
    out = []
    last = None
    try:
        with open_log(path) as f:
            for row in csv.reader(line.replace("\x00", "") for line in f):
                if not row or row[0] == "timestamp":
                    continue
                t = parse_iso(row[0], last)
                if not t:
                    continue
                last = t
                try:
                    if len(row) == len(COLUMNS):
                        out.append((t, float(row[1]), row[2], float(row[3]), _num(row[4]), _num(row[5]),
                                    _num(row[6]), int(row[7] or 0), _num(row[8], int)))
                    elif len(row) == len(OLD_COLUMNS):
                        out.append((t, float(row[1]), row[2], float(row[3]), None, None, None, int(row[4] or 0),
                                    _num(row[5], int)))
                except ValueError:
                    continue
    except OSError:
        pass
    return out


def day_rows(day):
    """A day's rows from both logs (1.0.7's and this one's: on the day of the update, both)."""
    return read_rows(path_for(day, OLD_PREFIX)) + read_rows(path_for(day))


# Windows' GPU counters ------------------------------------------------------------------------------------------------

MEM_INSTANCE = re.compile(r"pid_(\d+)_")
ENGINE_INSTANCE = re.compile(r"pid_(\d+)_(luid_\w+?_phys_\d+_eng_\d+)_engtype_")


def gpu_by_pid(mem, engines):
    """From the counters' instances ({"pid_1752_luid_..._phys_0": bytes} and {"pid_1752_luid_..._eng_0_engtype_3D":
    percent}): ({pid: dedicated bytes}, {pid: {engine: percent}})."""
    vram = collections.Counter()
    for name, v in (mem or {}).items():
        m = MEM_INSTANCE.match(name)
        if m and v:
            vram[int(m.group(1))] += v
    eng = collections.defaultdict(dict)
    for name, v in (engines or {}).items():
        m = ENGINE_INSTANCE.match(name)
        if m and v and v > 0:
            e = eng[int(m.group(1))]
            e[m.group(2)] = e.get(m.group(2), 0.0) + v
    return dict(vram), dict(eng)


class GpuCounters:
    """Windows' "GPU Process Memory" and "GPU Engine" counters, read every GPU_EVERY seconds on a thread of its own.
    The engines' percentages are averages since the read before, so each read covers the last minute."""

    def __init__(self):
        self.latest = None               # (time.monotonic(), {pid: bytes}, {pid: {engine: percent}})
        self.error = None

    def start(self, stop):
        threading.Thread(target=self._loop, args=(stop,), name="gpu-counters", daemon=True).start()

    def _loop(self, stop):
        try:
            import win32pdh
            q = win32pdh.OpenQuery()
            mem = win32pdh.AddEnglishCounter(q, r"\GPU Process Memory(*)\Dedicated Usage")
            eng = win32pdh.AddEnglishCounter(q, r"\GPU Engine(*)\Utilization Percentage")
            win32pdh.CollectQueryData(q)
        except Exception as e:
            self.error = ("Windows' GPU counters can't be read: %s: %s" % (type(e).__name__, e))[:300]
            return
        while not stop.wait(GPU_EVERY):
            try:
                win32pdh.CollectQueryData(q)
                m = win32pdh.GetFormattedCounterArray(mem, win32pdh.PDH_FMT_LARGE)
                try:
                    e = win32pdh.GetFormattedCounterArray(eng, win32pdh.PDH_FMT_DOUBLE | win32pdh.PDH_FMT_NOCAP100)
                except Exception:
                    e = {}                   # (no engine with two reads yet)
                vram, engines = gpu_by_pid(m, e)
                self.latest = (time.monotonic(), vram, engines)
                self.error = None
            except Exception as ex:
                self.error = ("Windows' GPU counters: %s: %s" % (type(ex).__name__, ex))[:300]

    def now(self):
        """The newest read if it's recent enough, else None."""
        last = self.latest
        return last if last and time.monotonic() - last[0] <= GPU_FRESH else None


# the log ------------------------------------------------------------------------------------------------------------

class ProgramLog:
    def __init__(self, keep_days):
        self.keep_days = keep_days
        self.prev = None             # the last look: (time.monotonic(), epoch, {pid: (created, CPU time in 100 ns)})
        self.began = None            # time.monotonic() of the look the minute began with
        self.irq_mark = None         # interrupt + DPC seconds then
        self.acc = {}                # program -> [CPU time in 100 ns, {pid: CPU time}] since then
        self.mem = {}                # program -> the most private bytes it held at a look this minute
        self.last = {}               # program -> (processes, the biggest pid by memory) at the latest look
        self.names = {}              # pid -> program, at the latest look
        self.gpu = GpuCounters()
        self.recent = collections.deque(maxlen=RECENT)    # (epoch, seconds, rows)
        self.day = None

    def start_gpu(self, stop):
        self.gpu.start(stop)

    def look(self, snap, now=None, wall=None):
        """Count a process snapshot (winapi.process_snapshot(): every process with its CPU time so far and its private
        bytes): what each process used since the last look, and each program's memory now."""
        now = time.monotonic() if now is None else now
        wall = time.time() if wall is None else wall
        cur = {pid: (p.created, p.cpu) for pid, p in snap.items() if pid}       # (pid 0: the idle time)
        mem, big, names = collections.Counter(), {}, {}
        for pid, p in snap.items():
            if not pid:
                continue
            names[pid] = p.name
            mem[p.name] += p.private
            n, top = big.get(p.name, (0, None))
            big[p.name] = (n + 1, pid if top is None or p.private > snap[top].private else top)
        for name, b in mem.items():
            if b > self.mem.get(name, 0):
                self.mem[name] = b
        self.last, self.names = big, names
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

    def gpu_by_program(self):
        """({program: VRAM MB}, {program: GPU %}, all programs' (VRAM MB, GPU %)) from the newest GPU read, by the
        latest look's names; (None, None, None) without one. A program's GPU % is its processes added up on each
        engine, then its busiest engine (as Task Manager does it)."""
        g = self.gpu.now()
        if g is None:
            return None, None, None
        _t, vram, engines = g
        vmb = collections.Counter()
        for pid, b in vram.items():
            if pid in self.names:
                vmb[self.names[pid]] += b / 2**20
        per = collections.defaultdict(collections.Counter)    # program -> engine -> percent
        every = collections.Counter()
        for pid, eng in engines.items():
            name = self.names.get(pid)
            for e, v in eng.items():
                every[e] += v
                if name:
                    per[name][e] += v
        gpu = {name: min(100.0, max(c.values())) for name, c in per.items() if c}
        return dict(vmb), gpu, (sum(vram.values()) / 2**20, min(100.0, max(every.values())) if every else 0.0)

    def minute(self):
        """The minute's rows into the log (the watcher calls this once a minute), and a new minute begins."""
        if self.prev is None or self.began is None:
            return None
        secs = self.prev[0] - self.began
        if secs <= 0:
            return None
        irq = interrupt_seconds()
        irq_s = max(0.0, irq - self.irq_mark) if irq is not None and self.irq_mark is not None else 0.0
        cpu = {name: a[0] / 1e7 for name, a in self.acc.items()}
        mem = {name: b / 2**20 for name, b in self.mem.items()}
        vram, gpu, every = self.gpu_by_program()
        pick = set()

        def top(values, least):
            pick.update(n for n, v in sorted(values.items(), key=lambda kv: -kv[1])[:TOP] if v >= least)
        top(cpu, MIN_SHARE * secs)
        top(mem, MIN_MEM_MB)
        if vram is not None:
            top(vram, MIN_VRAM_MB)
            top(gpu, MIN_GPU_PCT)
        rows = []
        for name in pick:
            a = self.acc.get(name)
            pid = max(a[1], key=a[1].get) if a else (self.last.get(name) or (0, None))[1]
            rows.append((name, cpu.get(name, 0.0), mem.get(name), None if vram is None else vram.get(name, 0.0),
                         None if gpu is None else gpu.get(name, 0.0), (self.last.get(name) or (0, None))[0], pid))
        rows.sort(key=lambda r: (-r[1], -(r[2] or 0)))
        rows.append((INTERRUPTS, irq_s, None, None, None, 0, None))
        rows.append((ALL, sum(cpu.values()) + irq_s, sum(mem.values()), None if every is None else every[0],
                     None if every is None else every[1], len(self.prev[2]), None))
        self.write(now_iso(), secs, rows)
        self.recent.append((time.time(), secs, rows))
        self.acc, self.mem, self.began, self.irq_mark = {}, {}, self.prev[0], irq
        return rows

    def write(self, ts, secs, rows):
        day = ts[:10]
        path = path_for(day)
        new = not os.path.exists(path)
        if day != self.day and not new:
            ensure_line_end(path)               # (a row cut off by a power loss stays on a line of its own)
        r = lambda v, nd: "" if v is None else round(v, nd)                      # noqa: E731
        with open(path, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new:
                w.writerow(COLUMNS)
            w.writerows([ts, round(secs, 1), name, round(cpu_s, 2), r(mem, 1), r(vram, 1), r(gpu, 1), n,
                         "" if pid is None else pid] for name, cpu_s, mem, vram, gpu, n, pid in rows)
        if day != self.day:
            if self.day is not None:            # a new day: the clean-up
                prune(paths.P.logs, PREFIX, ".csv", self.keep_days)
                prune(paths.P.logs, OLD_PREFIX, ".csv", self.keep_days)
            self.day = day

    def busiest(self, minutes=3, n=8):
        """The programs that used the most CPU over the last few minutes (the minute under way too), as lines for a
        report: "dwm.exe: 98 % of one core (1 process, the busiest pid 1752)"."""
        used, secs, procs = collections.Counter(), 0.0, {}
        for _t, s, rows in list(self.recent)[-minutes:]:
            secs += s
            for name, cpu_s, _m, _v, _g, k, pid in rows:
                if name != ALL and cpu_s > 0:
                    used[name] += cpu_s
                    procs[name] = (k, pid)
        if self.prev is not None and self.began is not None:
            secs += self.prev[0] - self.began
            for name, a in self.acc.items():
                used[name] += a[0] / 1e7
                procs[name] = ((self.last.get(name) or (len(a[1]), None))[0], max(a[1], key=a[1].get))
        if secs <= 0:
            return []
        out = []
        for name, cpu_s in used.most_common(n):
            k, pid = procs.get(name, (0, None))
            out.append("%s: %.0f %% of one core%s" % (name, 100 * cpu_s / secs, "" if pid is None else
                       " (%d process%s, the busiest pid %d)" % (k, "" if k == 1 else "es", pid)))
        return out
