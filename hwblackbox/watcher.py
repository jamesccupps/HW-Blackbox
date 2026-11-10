r"""The apps on the watch list, in every session: when they start and end, with the exit code and what it means, how
much memory they hold, and an incident report when one crashes or ends badly. Windows' own records too (see events).

Records ("kind"): start, exit, mem (every minute), watching (at start), winevent, and through the ports: ports, port.
Every program's CPU, memory and GPU use, minute by minute, from the same process list: logs\programs_*.csv
(programs).
Reports: incidents\incident_<time>_<app>.txt with the record, the last 3 minutes of everything (the service's records,
the session agents' records, the app in front), the screens, the biggest processes and the busiest programs.

Watching is reading only: other processes are opened for SYNCHRONIZE and limited query (to learn their exit code),
never more."""
import collections
import datetime as dt
import json
import os
import re
import time

import psutil
import win32api
import win32event
import win32process

from . import paths, winapi
from .programs import ProgramLog
from .events import (DRIVE_QUERY, WHEA, WHEA_QUERY, EventReader, describe_1074, drive_note, event_app, hardware_note,
                     newest_event, wanted)
from .util import fmt_dur, local_text, now_iso, safe_name

SYNCHRONIZE = 0x00100000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
STILL_ACTIVE = 259

# What an exit code says. Anything from 0xC0000000 up is a crash (an NTSTATUS error).
EXIT_MEANING = {
    0: "clean exit",
    1: "exit code 1: an error, or ended by another program (TerminateProcess)",
    0xC0000005: "crash: access violation",
    0xC0000409: "crash: fail-fast (__fastfail / stack buffer overrun)",
    0xC0000374: "crash: heap corruption",
    0xC00000FD: "crash: stack overflow",
    0xC000001D: "crash: illegal instruction (a deliberate crash)",
    0x80000003: "crash: breakpoint (a deliberate crash)",
    0xE0000008: "crash: out of memory (Chromium/Electron)",
    0xC0000142: "failed to start (DLL initialisation)",
    0xC000013A: "ended by Ctrl+C or its console closing",
    0x40010004: "ended by Windows (sign-out, or a debugger)",
    0xCFFFFFFF: "ended by the Windows app container",
    0xFFFFFFFF: "killed by another program (Task Manager, Stop-Process, Kill(): TerminateProcess with -1)",
}


def meaning(code):
    if code is None:
        return "unknown (its exit code couldn't be read)"
    if code in EXIT_MEANING:
        return EXIT_MEANING[code]
    if code >= 0xC0000000 and code != 0xFFFFFFFF:
        return "crash (NTSTATUS 0x%08X)" % code
    return "exit code %d" % code


# Error-range codes that aren't crashes: Ctrl+C or the console closing (how a console program ends when its session
# does: on 2026-10-21 a restart wrote an incident for a desktop app's helper), and the app container ending an app.
NOT_CRASHES = (0xC000013A, 0xCFFFFFFF)
REPORTS_PER_HOUR = 20
FLOOD = 30                  # records of one kind of Windows record an hour, at most
APP_REPORT = re.compile(r"incident_(\d{8})_\d{6}_.+\.txt$")     # (a power-off report has no app name)


def crashed(code):
    return code is not None and code != 0xFFFFFFFF and code not in NOT_CRASHES and \
        (code >= 0xC0000000 or code in (0x80000003, 0xE0000008))


def is_venv_launcher(pid):
    """A venv's Scripts\\pythonw.exe is a small launcher that starts the real interpreter as its child with the same
    command line; watching both would count everything twice."""
    try:
        folder = os.path.dirname(psutil.Process(pid).exe())
    except Exception:
        return False
    if folder.startswith(("\\\\", "//")):
        return False      # (a program run from a network share: SYSTEM doesn't go looking there, as the PC's account)
    return os.path.basename(folder).lower() == "scripts" and \
        os.path.isfile(os.path.join(os.path.dirname(folder), "pyvenv.cfg"))


class Tracked:
    __slots__ = ("pid", "exe", "label", "started", "main", "handle", "mem", "by_port", "policy", "ports", "session")


class Watcher:
    def __init__(self, jrnl, cfg, ports, agents, test=False):
        self.jrnl = jrnl
        self.cfg = cfg
        self.ports = ports
        self.agents = agents
        self.test = test
        self.watch = cfg["watch"]
        self.by_exe = {}
        for w in self.watch:
            self.by_exe.setdefault(w["exe"].lower(), []).append(w)
        self.tracked = {}                                   # pid -> Tracked
        self.skipped = {}                                   # pid -> create time: looked at, not watched
        self.snapshot = {}                                  # the last process snapshot
        self.users = {}                                     # session -> user
        self.events = EventReader(paths.P.eventpos)
        self.last_incident = {}
        self.reports = collections.deque()                  # when the app reports of the last hour were written
        self.capped_at = 0
        self.ending = False                                # Windows is shutting down: exits are expected now
        self.signed_out = {}                                # session -> when Windows said it signed out
        self.notes = {"last_incident": None, "last_shutdown": None, "last_power_loss": None,
                      "last_hardware_error": None, "last_drive_error": None}
        self.logs_mb = None
        self.programs = ProgramLog(((cfg.get("sensors") or {}).get("keep_days")) or 183)
        self.noted = {}                                     # the program log's last errors (each written once)
        self.flood = {}                                     # (source, id) -> when its records were written, last hour
        self.flood_skipped = {}                             # (source, id) -> how many were left out since

    # which watched app a process is, if any, and whether it may still become one (a port rule's process that isn't
    # listening yet: a server that has only just started). `listening()` gives {pid: {ports}}, asked only when needed.
    def match(self, pid, p, listening):
        rules = self.by_exe.get(p.name.lower())
        if not rules:
            return None, False
        cl = None
        later = False
        for r in rules:
            if r.get("ports"):
                if listening().get(pid, set()) & set(r["ports"]):
                    return r, False
                later = True
                continue
            if not r.get("match"):
                return r, False
            if cl is None:
                try:
                    cl = " ".join(psutil.Process(pid).cmdline()).lower()
                except Exception:
                    cl = ""
            if r["match"].lower() in cl and not (r.get("exclude") and r["exclude"].lower() in cl):
                return r, False
        return None, later

    def track(self, pid, p, rule, label, main, startup):
        t = Tracked()
        t.pid, t.exe, t.label, t.started, t.main = pid, p.name, label, p.created or time.time(), main
        t.by_port = bool(rule.get("ports"))
        t.ports = rule.get("ports")
        t.policy = rule.get("incidents") or "nonzero"
        t.session = p.session
        t.mem = p.private
        try:
            t.handle = win32api.OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        except Exception:
            t.handle = None   # (can't open it: its end is seen as it leaves the list, without its exit code)
        self.tracked[pid] = t
        if t.main and not startup:
            self.jrnl.write("start", {"app": t.label, "exe": t.exe, "pid": pid, "session": t.session,
                                      "user": self.users.get(t.session)})
        return t

    def scan(self, startup=False):
        snap = winapi.process_snapshot()
        self.snapshot = snap
        try:
            self.programs.look(snap)                        # (each program's CPU and memory: programs)
        except Exception:
            pass
        cache = {}
        now = time.time()

        def listening():
            # every port a process listens on, from Windows' listener table (see winapi.tcp_listeners)
            if "l" not in cache:
                cache["l"] = collections.defaultdict(set)
                try:
                    for (_ip, port), pid in winapi.tcp_listeners().items():
                        cache["l"][pid].add(port)
                except Exception as e:
                    cache["err"] = ("%s: %s" % (type(e).__name__, e))[:200]
            return cache["l"]

        for pid, p in snap.items():
            if pid in (0, 4):
                continue
            t = self.tracked.get(pid)
            if t and abs(t.started - p.created) < 1:
                t.mem = p.private
                continue
            if self.skipped.get(pid) == p.created:
                continue
            rule, later = self.match(pid, p, listening)
            if not rule:
                if not (later and now - p.created < 60):     # (a young server gets a minute to open its port)
                    self.skipped[pid] = p.created
                continue
            if rule.get("match") and is_venv_launcher(pid):
                self.skipped[pid] = p.created               # the real interpreter is its child, and is watched
                continue
            parent = snap.get(p.ppid)
            # an app found by its command line or port is one; otherwise a child of the same program is a helper
            main = bool(rule.get("match") or rule.get("ports")) or parent is None or \
                parent.name.lower() != p.name.lower() or parent.created > p.created
            t = self.track(pid, p, rule, rule["label"], main, startup)
            # a server found by its port: the process of the same program that started it is its supervisor
            if t.by_port and parent is not None and p.ppid not in self.tracked and \
                    parent.name.lower() == p.name.lower() and parent.created <= p.created:
                self.skipped.pop(p.ppid, None)
                self.track(p.ppid, parent, rule, rule["label"] + " (supervisor)", True, startup)
        for pid in list(self.skipped):
            if pid not in snap:
                del self.skipped[pid]
        # no handle: gone from the list means it ended (its exit code unknown)
        for pid, t in list(self.tracked.items()):
            if t.handle is None and (pid not in snap or abs(snap[pid].created - t.started) >= 1):
                self.ended(t, None)
        if startup:
            mains = sorted("%s (%s, pid %d, session %d)" % (t.label, t.exe, t.pid, t.session)
                           for t in self.tracked.values() if t.main)
            lst = listening()
            ports = {str(port): sorted(pid for pid, ps in lst.items() if port in ps)
                     for port in sorted({x for r in self.watch for x in (r.get("ports") or [])})}
            self.jrnl.write("watching", {"apps": mains, "helpers": sum(1 for t in self.tracked.values() if not t.main),
                                         "ports": ports, "ports_error": cache.get("err"),
                                         "event_logs": {log: pos is not None for log, pos in self.events.last.items()}})

    def check_exits(self):
        for pid, t in list(self.tracked.items()):
            if t.handle is None:
                continue
            try:
                if win32event.WaitForSingleObject(t.handle, 0) != win32event.WAIT_OBJECT_0:
                    continue
                code = win32process.GetExitCodeProcess(t.handle) & 0xFFFFFFFF
            except Exception:
                code = None
            self.ended(t, None if code == STILL_ACTIVE else code)

    def ended(self, t, code):
        self.tracked.pop(t.pid, None)
        if t.handle is not None:
            try:
                win32api.CloseHandle(t.handle)
            except Exception:
                pass
        if not t.main and not crashed(code):
            return   # a helper ending normally (Chromium closes renderers all the time)
        rec = {"app": t.label, "exe": t.exe, "pid": t.pid, "main": t.main, "session": t.session,
               "user": self.users.get(t.session), "taskbar": (t.pid in self.agents.taskbar_pids()) or None,
               "code": None if code is None else "0x%08X" % code, "meaning": meaning(code),
               "ran": fmt_dur(time.time() - t.started), "mem_mb": None if t.mem is None else t.mem // 2**20,
               "still_running": sum(1 for x in self.tracked.values() if x.exe.lower() == t.exe.lower())}
        if t.ports:
            # who holds its ports now: another program on a server's port is why a server keeps failing to start
            rec["ports_now"] = self.ports.holders(t.ports, but=t.pid) or None
        if self.ending:
            rec["while_shutting_down"] = True
        report = crashed(code) or (t.main and t.policy != "crash" and code != 0)
        shell = self.shell_running(t, code) if report else None
        if shell:
            rec["shell_running"] = shell
            report = False
        if report and not crashed(code) and not self.ending and self.session_ending(t.session):
            # Windows ending the session's apps (a sign-out, or a restart before the services stop) is expected:
            # recorded, not an incident. A crash still is one.
            rec["while_session_ends"] = True
            report = False
        self.jrnl.write("exit", rec)
        if report:
            self.incident(t.exe, "%s ended: %s" % (t.label, meaning(code)), rec)

    def shell_running(self, t, code):
        """An Explorer that isn't its session's taskbar, ending without a crash while the taskbar's Explorer runs on:
        the taskbar's pid, else None. An explorer.exe started to open a folder or a program hands it to the running
        shell and ends with exit code 1 (2026-11-09: the Ollama updater starting Ollama that way wrote an incident).
        The taskbar's Explorer ending, a crash, or a session whose taskbar isn't known still counts."""
        if t.exe.lower() != "explorer.exe" or crashed(code):
            return None
        try:
            shell = self.agents.taskbar_of(t.session)
        except Exception:
            return None
        s = self.tracked.get(shell) if shell and shell != t.pid else None
        if s is None or s.exe.lower() != "explorer.exe" or s.session != t.session:
            return None
        if s.handle is not None:
            try:
                if win32event.WaitForSingleObject(s.handle, 0) == win32event.WAIT_OBJECT_0:
                    return None                             # (the taskbar's Explorer has just ended too)
            except Exception:
                return None
        return shell

    def session_ending(self, sid, window=120):
        """Whether the session is ending: Windows told the service it signed out, or asked the session's agent to end
        it (and didn't cancel), in the last two minutes."""
        if time.time() - self.signed_out.get(sid, 0) < window:
            return True
        try:
            asked = [r for r in self.agents.recent_records(window) if r.get("session") == sid and r.get("kind") == "shutdown"]
        except Exception:
            return False
        return bool(asked) and asked[-1].get("phase") != "cancelled"

    def sample_memory(self):
        apps = {"%s/%d" % (t.exe, t.pid): t.mem // 2**20 for t in self.tracked.values() if t.main and t.mem}
        try:
            apps["HW Blackbox service/%d" % os.getpid()] = psutil.Process().memory_info().private // 2**20
        except Exception:
            pass
        if apps:
            self.jrnl.write("mem", {"private_mb": apps}, hard=False)

    def sample_programs(self):
        """The minute's use by program into logs\\programs_*.csv (programs)."""
        try:
            self.programs.minute()
            self.note_once("by program", None)
        except Exception as e:
            self.note_once("by program", ("%s: %s" % (type(e).__name__, e))[:300])
        self.note_once("GPU by program", self.programs.gpu.error)

    def note_once(self, where, error):
        """An error into the journal the first time it's seen (and again only after it has gone away)."""
        if error and error != self.noted.get(where):
            self.jrnl.write("error", {"where": where, "error": error})
        self.noted[where] = error

    def label_for(self, pid, port, exe):
        """What a listening process is, for the ports: the watched app's label, else the expected owner's (when it's
        the right program), else nothing."""
        from .ports import same_program
        t = self.tracked.get(pid)
        if t is not None:
            return t.label
        want = ((self.cfg.get("ports") or {}).get("expected") or {}).get(str(port)) or {}
        if want.get("label") and same_program(exe, want.get("exe")):
            return want["label"]
        return None

    def check_events(self):
        now = time.time()
        for rec in self.events.new_records():
            if not wanted(rec):
                continue
            app, crash = event_app(rec)
            rec["app"] = app
            ins = rec.get("inserts") or []
            if rec.get("source") == "Application Error" and len(ins) > 10:
                prog = winapi.program_of(ins[10])        # (which program's exe it was: its folder says)
                if prog:
                    rec["program"] = prog
            # Some boards report a corrected hardware error (or a drive a retry) hundreds of times an hour: each kind
            # goes into the records FLOOD times an hour at most, and the next one written says how many were left out.
            key = (rec.get("source"), rec.get("id"))
            times = self.flood.setdefault(key, collections.deque())
            while times and now - times[0] > 3600:
                times.popleft()
            if len(times) >= FLOOD:
                self.flood_skipped[key] = self.flood_skipped.get(key, 0) + 1
                self.note_event(rec)
                continue
            times.append(now)
            if self.flood_skipped.get(key):
                rec["skipped_before"] = self.flood_skipped.pop(key)
            self.jrnl.write("winevent", rec)
            self.note_event(rec)
            if crash and app and not rec.get("backfill"):
                self.incident(app, "Windows recorded a crash of %s (%s %d)" % (app, rec["source"], rec["id"]), rec)
        self.events.save()

    def load_notes(self):
        """The latest shutdown request and power loss, straight from the System log, and the latest app incident from
        incidents\\ (so they survive a restart)."""
        at, d = newest_event("System", "*[System[Provider[@Name='User32'] and (EventID=1074)]]")
        if at:
            self.notes["last_shutdown"] = describe_1074(at, d.get("param1"), d.get("param5"), d.get("param3"))
        at, _ = newest_event("System", "*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and (EventID=41)]]")
        self.notes["last_power_loss"] = at
        at, d = newest_event("System", WHEA_QUERY)
        if at and d.get("_id") is not None:
            self.notes["last_hardware_error"] = "%s: %s" % (at, hardware_note(WHEA, d["_id"], d.get("_level")))
        at, d = newest_event("System", DRIVE_QUERY)
        note = drive_note({"source": d.get("_provider"), "id": d.get("_id"), "inserts": d.get("_values")}) if at \
            else None
        if note:
            self.notes["last_drive_error"] = "%s: %s" % (at, note)
        try:
            newest = max(f for f in os.listdir(paths.P.incidents) if re.match(r"incident_\d{8}_\d{6}_", f))
            with open(os.path.join(paths.P.incidents, newest), encoding="utf-8", errors="replace") as f:
                title = f.readline().strip()
            when = dt.datetime.strptime(newest[9:24], "%Y%m%d_%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
            self.notes["last_incident"] = "%s: %s" % (when, title)
        except (ValueError, OSError):
            pass

    def note_event(self, rec):
        """Keep the latest shutdown request and power loss for the status. A power loss is known by its Kernel-Power
        41, written at the boot after it: one value per loss, which is what Home Assistant's alert keys on."""
        src, eid, ins = rec["source"], rec["id"], rec.get("inserts") or []
        # (local time without the offset: the same text load_notes gives after a restart, so the status's facts, and
        # Home Assistant's, don't change just because the service started again)
        at = rec["at"][:19].replace("T", " ")
        if src == "User32" and eid == 1074 and ins:
            self.notes["last_shutdown"] = describe_1074(at, ins[0], ins[4] if len(ins) > 4 else None,
                                                        ins[2] if len(ins) > 2 else None)
        elif src == "Microsoft-Windows-Kernel-Power" and eid == 41:
            self.notes["last_power_loss"] = at
        elif src == WHEA:
            self.notes["last_hardware_error"] = "%s: %s" % (at, hardware_note(src, eid, rec.get("level")))
        else:
            note = drive_note(rec)
            if note:
                self.notes["last_drive_error"] = "%s: %s" % (at, note)

    def biggest(self, n=8):
        rows = sorted(((p.private, p.name, pid, p.session) for pid, p in self.snapshot.items() if pid), reverse=True)
        return ["%s (pid %d, session %d): %d MB private" % (name, pid, s, mem // 2**20) for mem, name, pid, s in rows[:n]]

    def incident(self, app, title, rec):
        if self.ending:
            return   # (Windows is closing everything: exits now are expected, and there's no time for this)
        key = app.lower()
        now = time.time()
        if now - self.last_incident.get(key, 0) < 60:
            return   # (a crash loop writes one a minute)
        # and REPORTS_PER_HOUR in all: Windows' crash records can be written by any program, under any app's name
        while self.reports and now - self.reports[0] > 3600:
            self.reports.popleft()
        if len(self.reports) >= REPORTS_PER_HOUR:
            if now - self.capped_at > 3600:
                self.capped_at = now
                self.jrnl.write("error", {"where": "incident report", "error": "%d app reports in the last hour: no "
                                          "more this hour (the records are still kept)" % REPORTS_PER_HOUR})
            return
        self.reports.append(now)
        self.last_incident[key] = now
        self.notes["last_incident"] = "%s: %s" % (local_text(now), title)
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(paths.P.incidents, "incident_%s_%s.txt" % (stamp, safe_name(app)))
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("%s\n%s\n\n" % (title, now_iso(ms=True)))
                f.write("The record:\n%s\n\n" % json.dumps(rec, indent=2, default=str))
                for sid, scr in sorted(self.agents.screens().items()):
                    f.write("The screens now (session %d):\n  %s\n\n" % (sid, "\n  ".join(scr) or "?"))
                f.write("The biggest processes now (private memory):\n  %s\n\n" % "\n  ".join(self.biggest()))
                busy = self.programs.busiest(3)
                if busy:
                    f.write("The busiest programs, the last 3 minutes (CPU):\n  %s\n\n" % "\n  ".join(busy))
                f.write("The last 3 minutes (everything the service wrote):\n")
                for r in self.jrnl.recent(180):
                    f.write("  %s\n" % json.dumps(r, default=str))
                agent_recs = self.agents.recent_records(180)
                if agent_recs:
                    f.write("\nThe last 3 minutes (the session agents):\n")
                    for r in agent_recs:
                        f.write("  %s\n" % json.dumps(r, default=str))
                for sid, ring in sorted(self.agents.front(180).items()):
                    f.write("\nThe app in front, session %d (last 3 minutes):\n" % sid)
                    last = None
                    for t, exe, *_ in ring:
                        if exe != last:
                            f.write("  %s  %s\n" % (dt.datetime.fromtimestamp(t).strftime("%H:%M:%S"), exe))
                            last = exe
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            self.jrnl.write("error", {"where": "incident report", "error": repr(e)[:300]})

    def prune_reports(self):
        """App reports older than the records (events.keep_days) go. Power-off reports are kept."""
        keep = ((self.cfg.get("events") or {}).get("keep_days")) or 183
        cutoff = (dt.date.today() - dt.timedelta(days=keep)).strftime("%Y%m%d")
        try:
            names = os.listdir(paths.P.incidents)
        except OSError:
            return 0
        gone = 0
        for f in names:
            m = APP_REPORT.match(f)
            if m and m.group(1) < cutoff:
                try:
                    os.remove(os.path.join(paths.P.incidents, f))
                    gone += 1
                except OSError:
                    pass
        return gone

    def logs_size(self):
        total = 0
        try:
            for f in os.scandir(paths.P.logs):
                total += f.stat().st_size
        except OSError:
            pass
        self.logs_mb = round(total / 2**20)
