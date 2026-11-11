r"""The session agent: what only a signed-in session can see, and the dashboard.

It runs in each signed-in session (the scheduled task HWBlackboxAgent starts it at sign-in; the service starts it
again if it stops), as the user, not elevated, as a hidden top-level window. It writes in sessions\<the user's SID>\
(the service makes it at sign-in, for that user only):
  session_YYYYMMDD.jsonl  its records: "display" (the screens changed: resolution, position or scaling), "taskbar"
                          (the taskbar came back: Explorer restarted), "shutdown" (Windows asking this session to end:
                          shut down, restart or sign out, with the idle time, the lock and the app in front; then
                          "ending" or "cancelled") and "shutdown_snapshot" (the app in front over the last 3 minutes)
  agent.json              its heartbeat, every 30 s: the screens, the taskbar's process, locked or not
  front.json              the app in front every 2 s over the last 3 minutes (no history beyond that: it's for the
                          service's incident reports, and is rewritten as it changes)
  settings.json           this user's own settings: which notifications they get (the page's Settings tab)
  notified.json           what this user has been told about already (notify.py)
and serves the dashboard on 127.0.0.1 (see dashboard\server.py), and shows this user Windows notifications when the
service finds a power-off, a crash, a hardware error or a new problem (notify.py).
Like the service, it never blocks a shutdown, and the only settings it changes are this user's own."""
import collections
import ctypes
import datetime as dt
import faulthandler
import os
import sys
import threading
import time
from ctypes import wintypes

import psutil
import win32api
import win32con
import win32event
import win32gui
import win32process

from . import VERSION, config, paths, winapi
from .journal import Journal
from .util import now_iso, write_json

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32
user32.SetTimer.argtypes = [wintypes.HWND, ctypes.c_void_p, wintypes.UINT, ctypes.c_void_p]
user32.SetTimer.restype = ctypes.c_void_p
user32.GetForegroundWindow.restype = ctypes.c_void_p
user32.FindWindowW.restype = ctypes.c_void_p
user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]

WM_TIMER = 0x0113
WM_DISPLAYCHANGE = 0x007E
WM_WTSSESSION_CHANGE = 0x02B1
WM_QUERYENDSESSION = 0x0011
WM_ENDSESSION = 0x0016
ENDSESSION_CLOSEAPP = 0x00000001
ENDSESSION_CRITICAL = 0x40000000
ENDSESSION_LOGOFF = 0x80000000
SHUTDOWN_NORETRY = 0x1
SM_REMOTESESSION = 0x1000


def screens():
    """[(device, 'x,y wxh', percent)] for every monitor (per-monitor DPI aware)."""
    out = []
    try:
        for hmon, _hdc, _rect in win32api.EnumDisplayMonitors(None, None):
            info = win32api.GetMonitorInfo(hmon)
            l, t, r, b = info["Monitor"]
            dx, dy = ctypes.c_uint(), ctypes.c_uint()
            pct = None
            try:
                if ctypes.windll.shcore.GetDpiForMonitor(int(hmon), 0, ctypes.byref(dx), ctypes.byref(dy)) == 0:
                    pct = round(dx.value * 100 / 96)
            except Exception:
                pass
            out.append((info.get("Device", "?"), "%d,%d %dx%d" % (l, t, r - l, b - t), pct))
    except Exception:
        pass
    return sorted(out)


def describe_screens(s):
    return ["%s %s at %s%%" % (d, geo, p if p is not None else "?") for d, geo, p in s]


def foreground_exe():
    try:
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return None
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        return psutil.Process(pid).name()
    except Exception:
        return None


def taskbar_pid():
    try:
        hwnd = user32.FindWindowW("Shell_TrayWnd", None)
        if hwnd:
            return win32process.GetWindowThreadProcessId(hwnd)[1]
    except Exception:
        pass
    return None


class LASTINPUTINFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]


def idle_ms():
    """How long since the last mouse or keyboard input, in ms (-1 if Windows won't say)."""
    li = LASTINPUTINFO()
    li.cbSize = ctypes.sizeof(LASTINPUTINFO)
    if user32.GetLastInputInfo(ctypes.byref(li)):
        return (kernel32.GetTickCount() - li.dwTime) & 0xFFFFFFFF
    return -1


def endsession_type(lp):
    kinds = []
    if lp & ENDSESSION_LOGOFF:
        kinds.append("sign out")
    if lp & ENDSESSION_CRITICAL:
        kinds.append("forced")
    if lp & ENDSESSION_CLOSEAPP:
        kinds.append("an installer or update closing apps")
    return ", ".join(kinds) or "shut down or restart"


def own_folder(user, wait=120):
    """This user's folder, sessions\\<their SID>. The service makes it as they sign in (users can't make folders
    there): wait for it, up to `wait` seconds. In a data folder of the user's own (a test, a copy) it's made here.
    OSError if it doesn't come, or is a link to somewhere else."""
    from .util import is_link
    path = paths.P.session_dir(winapi.token_sid() or user)
    until = time.time() + wait
    while not os.path.isdir(path):
        try:
            os.makedirs(path)
        except OSError:
            if time.time() > until:
                raise OSError("%s wasn't made (the service makes it at sign-in)" % path)
            time.sleep(2)
    if is_link(path):
        raise OSError("%s is a link to somewhere else" % path)
    return path


class Agent:
    def __init__(self, test=False, serve=True):
        self.test = test
        self.serve = serve
        self.user = winapi.user_name()
        self.session = winapi.session_of()
        self.dir = own_folder(self.user)
        self.cfg = config.load()
        self.jrnl = Journal(self.dir, "session", self.cfg["events"]["keep_days"], ring=500)
        self.ring = collections.deque(maxlen=90)          # (time, exe in front, idle ms): 3 minutes, one every 2 s
        self.screens = screens()
        self.locked = None
        self.ending = False
        self.tick = 0
        self.front_at = 0
        self.front_exe = None
        self.dashboard = None
        self.dash_error = None
        self.dash_tried = 0
        self.started = time.time()
        self.run_for = None
        self.notifier = None
        self.notify_error = None

    def write_front(self):
        cutoff = time.time() - 180
        write_json(os.path.join(self.dir, "front.json"), {
            "ts": now_iso(), "session": self.session,
            "ring": [[round(t, 1), exe, round(i / 1000)] for t, exe, i in self.ring if t >= cutoff]})
        self.front_at = time.time()

    def heartbeat(self):
        try:
            write_json(os.path.join(self.dir, "agent.json"), {
                "ts": now_iso(), "pid": os.getpid(), "version": VERSION, "user": self.user, "session": self.session,
                "started": dt.datetime.fromtimestamp(self.started).isoformat(timespec="seconds"),
                "screens": describe_screens(self.screens), "taskbar_pid": taskbar_pid(), "locked": self.locked,
                "idle_s": round(idle_ms() / 1000), "in_front": self.front_exe, "test": self.test or None,
                "mem_mb": round(psutil.Process().memory_info().private / 2**20, 1),
                "dashboard": {"port": self.dashboard.server_address[1] if self.dashboard else None,
                              "error": self.dash_error}}, durable=True)
        except Exception:
            pass

    def check_display(self):
        now = screens()
        if now and now != self.screens:
            self.jrnl.write("display", {"before": describe_screens(self.screens), "after": describe_screens(now)})
            self.screens = now

    def start_dashboard(self):
        """The dashboard on 127.0.0.1 (dashboard.port), unless it's off in the settings. Tried again every minute
        while the port is taken."""
        self.dash_tried = time.time()
        d = self.cfg.get("dashboard") or {}
        if not self.serve or not d.get("enabled", True) or self.dashboard:
            return
        from .dashboard import server
        try:
            self.dashboard = server.start(int(d.get("port") or 9070))
            self.dash_error = None
        except OSError as e:
            who = server.who_serves(int(d.get("port") or 9070))
            self.dash_error = "port %s is taken%s" % (d.get("port"), " (%s)" % who if who else "")

    def on_timer(self):
        self.tick += 1
        if self.tick % 2 == 0:
            exe = foreground_exe()
            self.ring.append((time.time(), exe, idle_ms()))
            if exe != self.front_exe or time.time() - self.front_at > 30:
                self.front_exe = exe
                self.write_front()
            self.check_display()
        if self.tick % 30 == 0:
            self.heartbeat()
        if self.tick % 30 == 15:
            self.check_notify()
        if self.tick % 60 == 30 and not self.dashboard and time.time() - self.dash_tried > 55:
            self.cfg = config.load()
            self.start_dashboard()

    def check_notify(self):
        """What the service found that's new, as Windows notifications for this user (notify.py). Never in a test
        instance (it would announce a copy's history), and never while the session is ending."""
        if self.test or self.ending:
            return
        try:
            if self.notifier is None:
                from .notify import Notifier
                port = int((self.cfg.get("dashboard") or {}).get("port") or 9070)
                self.notifier = Notifier(self.dir, port)
            from .util import age, read_json
            st = read_json(paths.P.status)
            if isinstance(st, dict):
                self.notifier.check(st, age(paths.P.status))
        except Exception as e:
            if repr(e) != self.notify_error:
                self.notify_error = repr(e)
                self.jrnl.write("error", {"where": "notifications", "error": repr(e)[:300]})

    def on_queryendsession(self, lparam):
        """Windows asks every window whether the session may end. Write the essentials first (a few ms), then the
        snapshot. The answer is always yes: the agent never blocks a shutdown."""
        lp = lparam & 0xFFFFFFFF
        self.ending = True
        self.jrnl.write("shutdown", {"phase": "asked", "type": endsession_type(lp), "lparam": "0x%08X" % lp,
                                     "idle_s": round(idle_ms() / 1000, 1), "locked": self.locked,
                                     "remote": bool(user32.GetSystemMetrics(SM_REMOTESESSION)),
                                     "in_front": foreground_exe()})
        cutoff = time.time() - 180
        self.jrnl.write("shutdown_snapshot", {
            "by": "agent", "in_front_and_idle_s": [[dt.datetime.fromtimestamp(t).strftime("%H:%M:%S"), exe,
                                                    round(i / 1000)] for t, exe, i in self.ring if t >= cutoff]})
        return 1

    def on_endsession(self, wparam, lparam):
        ending = bool(wparam)
        self.jrnl.write("shutdown", {"phase": "ending" if ending else "cancelled",
                                     "lparam": "0x%08X" % (lparam & 0xFFFFFFFF)})
        if not ending:
            self.ending = False


def run(agent):
    try:
        user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))     # per-monitor v2: real sizes and scaling
    except Exception:
        pass
    # The screens again, now with their real sizes and scaling: read before (in Agent()), they came out scaled down to
    # 100 %, and the first check after the start wrote a "display" record for a change that never happened.
    agent.screens = screens()
    try:
        # among the first asked when Windows ends the session (0x3FF: the top of the apps' range), and if it ever has
        # to wait for us, end us without a "this app is preventing shutdown" screen
        kernel32.SetProcessShutdownParameters(0x3FF, SHUTDOWN_NORETRY)
    except Exception:
        pass
    taskbar_created = win32gui.RegisterWindowMessage("TaskbarCreated")

    def wndproc(hwnd, msg, wparam, lparam):
        try:
            if msg == WM_TIMER:
                if wparam == 2:
                    win32gui.PostQuitMessage(0)           # (--run-for: a test run's end)
                    return 0
                agent.on_timer()
                return 0
            if msg == WM_QUERYENDSESSION:
                return agent.on_queryendsession(lparam)
            if msg == WM_ENDSESSION:
                agent.on_endsession(wparam, lparam)
                return 0
            if msg == taskbar_created:
                agent.jrnl.write("taskbar", {"event": "TaskbarCreated: the taskbar came back (Explorer restarted)",
                                             "taskbar_pid": taskbar_pid()})
                agent.heartbeat()
                return 0
            if msg == WM_DISPLAYCHANGE:
                agent.check_display()
                return 0
            if msg == WM_WTSSESSION_CHANGE:
                if wparam == 7:
                    agent.locked = True
                elif wparam == 8:
                    agent.locked = False
                return 0
        except Exception as e:
            try:
                agent.jrnl.write("error", {"where": "wndproc %d" % msg, "error": repr(e)[:300]})
            except Exception:
                pass
            if msg == WM_QUERYENDSESSION:
                return 1          # whatever went wrong, never stand in the way of a shutdown
        return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

    wc = win32gui.WNDCLASS()
    wc.lpszClassName = "HWBlackboxAgent" + ("Test" if agent.test else "")
    wc.lpfnWndProc = wndproc
    atom = win32gui.RegisterClass(wc)
    # a TOP-LEVEL window, never shown (message-only windows don't get TaskbarCreated, WM_DISPLAYCHANGE or
    # WM_QUERYENDSESSION)
    hwnd = win32gui.CreateWindowEx(0x00000080, atom, "HW Blackbox agent", win32con.WS_OVERLAPPED, 0, 0, 0, 0, 0, 0, 0,
                                   None)
    try:
        ctypes.windll.wtsapi32.WTSRegisterSessionNotification(hwnd, 0)
    except Exception:
        pass
    agent.start_dashboard()
    agent.jrnl.write("startup", {"pid": os.getpid(), "version": VERSION, "user": agent.user, "session": agent.session,
                                 "screens": describe_screens(agent.screens), "test": agent.test or None,
                                 "dashboard": agent.dashboard.server_address[1] if agent.dashboard else agent.dash_error,
                                 "config_error": agent.cfg.get("error")})
    agent.heartbeat()
    agent.write_front()
    user32.SetTimer(hwnd, 1, 1000, None)
    if agent.run_for:
        user32.SetTimer(hwnd, 2, int(agent.run_for * 1000), None)
    win32gui.PumpMessages()


def main(test=False, serve=True, run_for=None):
    try:
        agent = Agent(test=test, serve=serve)
        agent.run_for = run_for
    except OSError as e:
        print("The agent can't write in %s: %s" % (paths.P.sessions, e))
        return 1
    crash = open(os.path.join(agent.dir, "agent_crash.log"), "a", encoding="utf-8")
    faulthandler.enable(crash)
    sys.stderr = crash
    mutex = win32event.CreateMutex(None, False, "Local\\HWBlackboxAgent" + ("Test" if test else ""))
    if win32api.GetLastError() == 183:      # one is already running in this session
        return 0
    winapi.raise_process_priority()
    try:
        run(agent)
    finally:
        if not agent.ending:
            agent.jrnl.write("stop", {"pid": os.getpid()})
        del mutex
    return 0
