r"""The service: the sensors, the watcher, the ports and the status, under one roof, from boot.

Threads: "sensors" (every 5 s), "rails" (4 a second) and "cpu" (the CPU's sensors, once a second) log the sensors;
"watcher" ticks every second (the watched apps' exits every second, the process list every 2 s, Windows' records and
the ports every 15 s, the session agents and the status every 30 s, the drives' free space, each program's use and
Home Assistant every minute); "gpu-counters" reads Windows' GPU counters once a minute; "supervisor" checks every 5 s that the sensors, the rails and the watcher are moving,
and only then pushes back the dead man's switch (deadman.py): a part that stops moving gets the process ended within
3 minutes, and the service manager starts it again.

From the service manager it also hears, as they happen: Windows shutting down (the "shutdown" record, phase
"services stopping": the last thing written before a clean shutdown, so its absence before a boot means the power
went), sessions starting, locking and ending, sleep and resume, and the clock being changed."""
import ctypes
import os
import sys
import threading
import time
import traceback

import psutil

from . import VERSION, config, paths, poweroff, status, winapi
from .agents import Agents
from .deadman import DeadMan
from .disks import DiskWatch
from .drives import DriveWatch
from .homeassistant import HaReporter
from .journal import Journal
from .ports import PortWatch
from .sensors import Sensors
from .util import is_link, now_iso, pack_logs
from .watcher import Watcher

# the day logs packed into .csv.gz once they're two days old (the records, events_*.jsonl, stay as they are: small, and
# read in many places)
PACKED = ("flight_", "rails_", "programs_", "cpu_", "disks_", "drives_")

WTS_EVENTS = {1: "console connect", 2: "console disconnect", 3: "remote connect", 4: "remote disconnect",
              5: "sign-in", 6: "sign-out", 7: "lock", 8: "unlock", 9: "remote control", 10: "session created",
              11: "session ended"}
POWER_EVENTS = {4: "going to sleep", 7: "woke up (by someone)", 0x12: "woke up", 0xA: "on battery or AC changed",
                0x9: "battery low"}
MUTEX = "Global\\HWBlackboxService"


def update_restart_pending():
    """Is Windows Update (or servicing) waiting for a restart?"""
    return status.restart_pending_since() is not None


class Service:
    STUCK = {"sensors": 60, "rails": 30, "watcher": 60}     # seconds without a pass before a part counts as stuck
    DEADMAN_S = 180

    def __init__(self, test=False, sensors=True):
        self.test = test
        self.want_sensors = sensors
        self.cfg = config.load()
        paths.P.make()
        self.jrnl = Journal(paths.P.logs, "events", self.cfg["events"]["keep_days"])
        self.me = psutil.Process()
        self.started = time.time()
        self.started_iso = now_iso()
        self.stop = threading.Event()
        self.beats = {}
        self.agent_down = {}
        self.cpu_mark = (time.time(), sum(self.me.cpu_times()[:2]))
        self.cpu_pct = None
        self.sensors = None
        self.poweroff_checked = False
        self.ha = HaReporter()
        self.ports = PortWatch(self.jrnl, paths.P.ports)
        self.agents = Agents(self.jrnl, restart=not test)
        self.watcher = Watcher(self.jrnl, self.cfg, self.ports, self.agents, test)
        self.disks = DiskWatch(self.jrnl, self.cfg["sensors"]["keep_days"])
        self.drives = DriveWatch(self.jrnl, self.cfg["sensors"]["keep_days"])
        self.lock = threading.Lock()         # the watcher's state: its thread, and the service manager's calls
        self.deadman = None
        self.host = None
        self.stuck_noted = set()
        self.last_status = None

    # the service's life ------------------------------------------------------------------------------------------

    def run(self, host):
        self.host = host
        prev = poweroff._last_record_before(time.time())
        clean = prev is None or prev.get("kind") in ("stop", "shutdown", "shutdown_snapshot")
        self.jrnl.write("startup", {
            "pid": os.getpid(), "version": VERSION, "python": sys.version.split()[0], "user": winapi.user_name(),
            "system": winapi.is_system(), "admin": winapi.is_admin(), "session": winapi.session_of(),
            "data_dir": paths.P.data, "test": self.test or None, "config_error": self.cfg.get("error"),
            "previous_run": None if prev is None else {"last_record": prev.get("ts"), "kind": prev.get("kind"),
                                                      "ended_cleanly": clean}})
        host.running()
        winapi.raise_process_priority()
        if not self.test:
            try:
                self.deadman = DeadMan(self.DEADMAN_S)
            except OSError as e:
                self.jrnl.write("error", {"where": "dead man's switch", "error": str(e)})
        threading.Thread(target=self._poweroff_check, name="poweroff-check", daemon=True).start()
        threading.Thread(target=self._sensors_start, name="sensors-open", daemon=True).start()
        self.watcher.programs.start_gpu(self.stop)        # (Windows' GPU counters, once a minute)
        if not self.test:
            self.drives.start(self.stop)                   # (the drives' health, once an hour)
        threading.Thread(target=self._pack_logs, name="logs-pack", daemon=True).start()
        threading.Thread(target=self._watch_loop, name="watcher", daemon=True).start()
        threading.Thread(target=self._supervise, name="supervisor", daemon=True).start()
        host.stop.wait()
        self.shutdown()

    def _sensors_start(self):
        try:
            if self.want_sensors:
                s = Sensors(self.cfg, self.jrnl, self.started_iso)
                s.open()
                self.sensors = s
                s.start(self.stop)
                self.jrnl.write("sensors", {"event": "open", "lhm": s.sampler.lhm.error or "ok",
                                            "nvml": s.sampler.nvml.error or "ok", "sensors": s.lhm_count,
                                            "devices": s.sampler.lhm.names, "gpu": s.sampler.nvml.name,
                                            "admin": s.sampler.admin})
        except Exception as e:
            self.error("sensors", e)

    def _pack_logs(self):
        """The day logs older than yesterday into .csv.gz (about a tenth of the size), 10 minutes after the start and
        then every 6 hours, at low priority: a few seconds' work a day."""
        winapi.lower_thread_priority()
        wait = 600
        while not self.stop.wait(wait):
            wait = 6 * 3600
            try:
                n = pack_logs(paths.P.logs, PACKED, done=self.stop)
                if n:
                    self.jrnl.write("logs", {"event": "packed", "files": n})
            except Exception as e:
                self.error("packing the logs", e)

    def _poweroff_check(self):
        """On a thread of its own from the start: a sensor library that's slow to open after a power loss mustn't
        hold up that power loss's report."""
        try:
            found = poweroff.check()
            if found:
                self.jrnl.write("power_off_report", {"summary": found})
            elif time.time() - psutil.boot_time() < 600:
                threading.Thread(target=poweroff.rechecks, args=(self.stop, self.jrnl), name="poweroff",
                                 daemon=True).start()
        except Exception as e:
            self.error("power-off check", e)
        self.poweroff_checked = True

    def _watch_loop(self):
        try:
            import pythoncom
            pythoncom.CoInitialize()              # (Task Scheduler, to start a session agent again)
        except Exception:
            pass
        w = self.watcher
        try:
            with self.lock:
                self.agents.refresh()
                w.users = {s["session"]: s["user"] for s in self.agents.view}
                w.scan(startup=True)
                w.load_notes()
                w.check_events()
                w.logs_size()
                w.sample_memory()
                w.prune_reports()
            self.disks.sample()
        except Exception as e:
            self.error("watcher start", e)
        tick = 0
        due = time.monotonic()
        while not self.stop.is_set():
            self.beats["watcher"] = time.monotonic()
            tick += 1
            try:
                with self.lock:
                    w.check_exits()
                    if tick % 2 == 0:
                        w.scan()
                    if tick % 60 == 0:
                        w.sample_memory()
                        w.sample_programs()
                    if tick % 15 == 0:
                        w.check_events()
                    if tick % 15 == 4:
                        self.ports.scan(self.cfg, w.label_for)
                    if tick % 30 == 5:            # (just before the status, so it has the agents' latest)
                        self.agents.refresh()
                        w.users = {s["session"]: s["user"] for s in self.agents.view}
                    if tick % 600 == 5:
                        w.logs_size()
                    if tick % 3600 == 1805:
                        w.prune_reports()
                if tick % 60 == 0:
                    self.disks.sample()           # (once a minute, just before a status)
                if tick % 30 == 7:
                    self.refresh_status(push=tick % 60 == 37 or tick == 7)
            except Exception as e:
                self.error("watcher", e)
            due += 1.0
            wait = due - time.monotonic()
            if wait < -1.0:
                due, wait = time.monotonic(), 0.0
            self.stop.wait(max(0.0, wait))

    def _supervise(self):
        while not self.stop.wait(5):
            stuck = [n for n, a in self.thread_ages().items() if a is not None and a > self.STUCK.get(n, 120)]
            for n in stuck:
                if n not in self.stuck_noted:
                    self.stuck_noted.add(n)
                    self.jrnl.write("error", {"where": "supervisor", "error": "the %s part hasn't moved for %d s; the "
                                              "service ends itself within %d s unless it does" %
                                              (n, self.thread_ages()[n], self.DEADMAN_S)})
            self.stuck_noted &= set(stuck)
            if not stuck and self.deadman:
                self.deadman.pet()

    def thread_ages(self):
        now = time.monotonic()
        beats = dict(self.beats)
        if self.sensors:
            beats.update(self.sensors.beats)
        out = {"watcher": None, "sensors": None, "rails": None}
        if not self.want_sensors or (self.sensors and not self.sensors.rails_on()):
            out.pop("rails")
        if not self.want_sensors:
            out.pop("sensors")
        for k in out:
            out[k] = now - beats[k] if k in beats else None
        return out

    def refresh_status(self, push):
        new = config.load()
        for k in config.LIVE:
            if k in new:
                self.cfg[k] = new[k]
        self.cfg["error"] = new.get("error")
        t, c = time.time(), sum(self.me.cpu_times()[:2])
        if t - self.cpu_mark[0] >= 20:
            self.cpu_pct = round(100 * (c - self.cpu_mark[1]) / (t - self.cpu_mark[0]), 2)
            self.cpu_mark = (t, c)
        state, problems, attrs = status.build(self)
        self.last_status = (state, problems, attrs)
        status.write(self, state, problems, attrs)
        if push and self.ha_on() and self.poweroff_checked:
            self.ha.submit(self.cfg["home_assistant"], status.ha_payload(self, state, problems, attrs))

    def ha_on(self):
        return not self.test and bool((self.cfg.get("home_assistant") or {}).get("enabled"))

    def ha_result(self):
        return self.ha.result if self.ha_on() else "off"

    def error(self, where, exc):
        self.jrnl.write("error", {"where": where, "error": ("%s: %s" % (type(exc).__name__, exc))[:300],
                                  "trace": traceback.format_exc(limit=4)[-800:]})

    # what the service manager says -------------------------------------------------------------------------------

    def control(self, kind, info):
        if kind == "preshutdown":
            self.watcher.ending = True
            if self.deadman:
                self.deadman.cancel()
            procs = []
            try:
                snap = winapi.process_snapshot()
                procs = sorted([pid, p.ppid, p.session, p.name] for pid, p in snap.items() if pid)
            except Exception:
                pass
            self.jrnl.write("shutdown", {"phase": "services stopping", "update_restart_pending": update_restart_pending(),
                                         "processes": len(procs)})
            self.jrnl.write("shutdown_snapshot", {"by": "service", "processes": procs})
            if self.ha_on() and self.last_status:
                try:
                    _state, problems, attrs = self.last_status
                    self.ha.submit(self.cfg["home_assistant"], status.ha_payload(self, "shutting down", problems, attrs))
                except Exception:
                    pass
        elif kind == "stop":
            if self.deadman:
                self.deadman.cancel()
        elif kind == "session":
            event, sid = info
            user = None
            try:
                user = next((s["user"] for s in winapi.sessions() if s["id"] == sid), None)
            except Exception:
                pass
            self.jrnl.write("session", {"event": WTS_EVENTS.get(event, "session change %d" % event), "session": sid,
                                        "user": user})
            if event in (5, 10):
                self.agents.first_seen[sid] = time.time()        # (its agent starts now: the restart grace begins)
            elif event == 6:
                self.watcher.signed_out[sid] = time.time()       # (its apps ending now are expected)
        elif kind == "power":
            what = POWER_EVENTS.get(info)
            if what:
                self.jrnl.write("power", {"event": what})
        elif kind == "timechange":
            self.jrnl.write("clock", {"event": "the clock was changed"})

    def shutdown(self):
        self.stop.set()
        if self.deadman:
            self.deadman.cancel()
        if self.host:
            self.host.pending(15000)
        time.sleep(0.5)                          # (the lanes finish the row they're on)
        self.jrnl.write("stop", {"pid": os.getpid(), "why": "Windows is shutting down" if self.watcher.ending
                                 else "the service was stopped",
                                 "ran": round(time.time() - self.started)})
        try:
            self.refresh_status(push=False)
        except Exception:
            pass
        self.jrnl.close()


def started_by_scm():
    """Was this process started by Windows' service manager (services.exe)?"""
    try:
        me = psutil.Process()
        parent = me.parent()
        return bool(parent) and parent.name().lower() == "services.exe" and parent.create_time() <= me.create_time()
    except Exception:
        return False


def service_running():
    """Is the installed service running (anything but stopped)?"""
    from . import SERVICE
    try:
        return psutil.win_service_get(SERVICE).status() != "stopped"
    except Exception:                    # (not installed)
        return False


def single_instance(test):
    """Hold the service's machine-wide lock for as long as this process lives; False if another holds it."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateMutexW.restype = ctypes.c_void_p
    k32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    h = k32.CreateMutexW(None, False, MUTEX + ("Test" if test else ""))
    err = ctypes.get_last_error()
    if not h or err == 183:                # ERROR_ALREADY_EXISTS (or access denied: another account's)
        return None
    return h


def crash_log():
    """A file for what has nowhere else to go (pythonw has no stderr): faults and the service glue's own errors."""
    import faulthandler
    try:
        os.makedirs(paths.P.data, exist_ok=True)
        fh = open(paths.P.crash_log, "a", encoding="utf-8")
        fh.write("\n--- %s: HW Blackbox %s, pid %d ---\n" % (now_iso(), VERSION, os.getpid()))
        fh.flush()
        faulthandler.enable(fh)
        sys.stderr = fh
        return fh
    except Exception:
        return None


def main(console=False, test=False, sensors=True, run_for=None):
    """The service's entry point (python -m hwblackbox service). Run by hand (not by the service manager) it runs in
    this console instead, until Ctrl+C (or for run_for seconds)."""
    from .winservice import ConsoleHost, ServiceHost
    from . import SERVICE
    if is_link(paths.P.data):
        print("%s is a link to somewhere else: HW Blackbox won't write through it." % paths.P.data)
        return 3                         # (not even the crash log: it's in there)
    log = crash_log()

    def note(text):
        if log:
            log.write(now_iso() + " " + text + "\n")
            log.flush()

    links = [p for p in (paths.P.logs, paths.P.state, paths.P.incidents, paths.P.secrets) if is_link(p)]
    if links:
        note("refusing to start: %s is a link to somewhere else (run Install.cmd again)" % ", ".join(links))
        print("%s is a link to somewhere else: HW Blackbox won't write through it." % ", ".join(links))
        return 3
    # Started by the service manager, which never runs a service twice, there's no lock: a lock's name is one any
    # account can take first, and that would keep the service from ever starting again.
    if console or test or not started_by_scm():
        lock = single_instance(test)                     # (held for as long as this process lives)
        if not lock:
            note("another HW Blackbox service is already running: this one exits")
            print("Another HW Blackbox service is already running.")
            return 2
        if not test and service_running():
            note("the HW Blackbox service is running: this one exits")
            print("The HW Blackbox service is running: stop it first, or add --test.")
            return 2
    svc = Service(test=test, sensors=sensors)
    if console:
        host = ConsoleHost(svc)
        if run_for:
            def later():
                svc.control("stop", None)
                host.stop.set()
            threading.Timer(run_for, later).start()
        host.dispatch()
        return host.exit_code
    host = ServiceHost(SERVICE, svc, note)
    if not host.dispatch():
        note("not started by the service manager: running in this console instead")
        host = ConsoleHost(svc)
        host.dispatch()
    return host.exit_code
