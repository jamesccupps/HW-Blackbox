r"""Windows notifications, from the session agent (each signed-in user gets their own): a power-off, an app's crash
report, a hardware error or a drive's error, and a problem with HW Blackbox or the PC. Without them, someone who
doesn't run Home Assistant learns of these only when they open the page.

The agent reads the service's status (state\status.json) every 30 s and tells the user what's new since they were
last told (their sessions\<SID>\notified.json). On the first look after the install nothing is announced: what
happened before isn't news. Each kind can be turned off on the page's Settings tab (sessions\<SID>\settings.json,
the user's own), and they're rationed: one of a kind every 10 minutes, 6 an hour in all (a board that reports a
corrected error every few seconds doesn't make the PC unusable). A problem is announced once it has lasted a minute,
so a hiccup doesn't make a sound.

A notification is Windows' own (a toast, in the notification center too), shown by Windows PowerShell for the app
"HW Blackbox" (the installer registers that name, HKLM\SOFTWARE\Classes\AppUserModelId\HWBlackbox). Clicking it
opens the page where it's explained."""
import collections
import os
import subprocess
import threading
import time
from xml.sax.saxutils import escape, quoteattr

from .util import read_json, write_json

AUMID = "HWBlackbox"
POWERSHELL_AUMID = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe"
KINDS = collections.OrderedDict([
    ("power_off", "The PC went off without shutting down (a power cut, a crash, the power button held)"),
    ("crash", "An app you watch crashed or closed unexpectedly (Explorer, and those in config.json)"),
    ("hardware", "The hardware reported an error (the CPU, memory, PCIe) or a drive did"),
    ("problem", "Something stopped working: HW Blackbox's own parts, a server's port, the Windows drive filling up"),
])
EVERY_KIND = 600                 # seconds between two of the same kind
PER_HOUR = 6
PROBLEM_AFTER = 60               # seconds a problem must last before it's announced
CREATE_NO_WINDOW = 0x08000000
SCRIPT = r"""$ErrorActionPreference = 'Stop'
[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
$x = New-Object Windows.Data.Xml.Dom.XmlDocument
$x.LoadXml($env:HWB_TOAST)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($env:HWB_AUMID).Show(
  (New-Object Windows.UI.Notifications.ToastNotification $x))"""


def app_id():
    """HW Blackbox's own name for its notifications when the installer registered it; else Windows PowerShell's
    (a copy run from a build: the notification then says "Windows PowerShell")."""
    import winreg
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        try:
            with winreg.OpenKey(hive, r"SOFTWARE\Classes\AppUserModelId\%s" % AUMID):
                return AUMID
        except OSError:
            continue
    return POWERSHELL_AUMID


def toast_xml(title, body, link=None):
    """A toast's XML: two lines, and a click (and an "Open HW Blackbox" button) that opens the page at `link`."""
    open_ = (" activationType=\"protocol\" launch=%s" % quoteattr(link)) if link else ""
    button = ("<actions><action content=\"Open HW Blackbox\" activationType=\"protocol\" arguments=%s/></actions>"
              % quoteattr(link)) if link else ""
    return ("<toast%s><visual><binding template=\"ToastGeneric\"><text>%s</text><text>%s</text></binding></visual>%s"
            "</toast>" % (open_, escape(title[:120]), escape(body[:400]), button))


def send(title, body, link=None, wait=False):
    """Show a notification. In the background (the agent's window must keep answering Windows), unless wait: then
    the result, None when it was shown or the error."""
    result = {}

    def run():
        ps = os.path.join(os.environ.get("SystemRoot") or r"C:\Windows", "System32", "WindowsPowerShell", "v1.0",
                          "powershell.exe")
        env = dict(os.environ, HWB_TOAST=toast_xml(title, body, link), HWB_AUMID=app_id())
        try:
            r = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", SCRIPT],
                               env=env, capture_output=True, text=True, timeout=60, creationflags=CREATE_NO_WINDOW)
            result["error"] = None if r.returncode == 0 else (r.stderr or r.stdout or "exit %d" % r.returncode)[-300:]
        except Exception as e:
            result["error"] = ("%s: %s" % (type(e).__name__, e))[:300]
    if not wait:
        threading.Thread(target=run, name="notify", daemon=True).start()
        return None
    run()
    return result.get("error")


def user_settings(folder):
    """This user's notification settings: {kind: on}, all on unless they turned one off."""
    saved = (read_json(os.path.join(folder, "settings.json")) or {}) if folder else {}
    mine = saved.get("notify") if isinstance(saved, dict) and isinstance(saved.get("notify"), dict) else {}
    return {k: mine.get(k) is not False for k in KINDS}


def save_setting(folder, kind, on):
    """Turn one kind on or off for this user (only the known kinds, only true or false)."""
    if kind not in KINDS or not isinstance(on, bool):
        raise ValueError("not a notification setting")
    path = os.path.join(folder, "settings.json")
    saved = read_json(path)
    saved = saved if isinstance(saved, dict) else {}
    notify = saved.get("notify") if isinstance(saved.get("notify"), dict) else {}
    notify[kind] = on
    saved["notify"] = {k: v for k, v in notify.items() if k in KINDS and isinstance(v, bool)}
    write_json(path, saved, indent=2)
    return user_settings(folder)


def facts(status):
    """What the status says happened last, of each kind: {kind: value} (a value changes when there's something new)."""
    a = (status or {}).get("attributes") or {}
    lds = (status or {}).get("last_dirty_shutdown") or {}
    return {"power_off": lds.get("incident"), "crash": a.get("last_incident"),
            "hardware": a.get("last_hardware_error"), "drive": a.get("last_drive_error")}


class Notifier:
    def __init__(self, folder, port, send=send, clock=time.time):
        self.folder = folder
        self.port = port                       # (the page's port, for the click)
        self.send = send
        self.clock = clock
        self.path = os.path.join(folder, "notified.json")
        seen = read_json(self.path)
        self.seen = seen if isinstance(seen, dict) else None
        self.sent = collections.deque()        # when each one was shown, the last hour
        self.last_of = {}                      # kind -> when one was last shown
        self.problems_since = {}               # problem -> when it was first seen (this run)

    def link(self, where):
        return "http://127.0.0.1:%d/#%s" % (self.port, where) if self.port else None

    def check(self, status, status_age=None):
        """Announce what's new in the service's status (status_age: how old the status file is: a service that has
        stopped writing it is a problem of its own)."""
        now = self.clock()
        new = facts(status)
        problems = list((status or {}).get("problems") or [])
        if status_age is not None and status_age > 180:
            problems.append("HW Blackbox's service isn't running: nothing is being recorded")
        for p in list(self.problems_since):
            if p not in problems:
                del self.problems_since[p]
        for p in problems:
            self.problems_since.setdefault(p, now)
        lasting = sorted(p for p, since in self.problems_since.items() if now - since >= PROBLEM_AFTER)
        if self.seen is None:                 # (the first look: what's there already isn't news)
            self.seen = dict(new, problems=lasting)
            self.save()
            return []
        on = user_settings(self.folder)
        shown = []
        if new["power_off"] and new["power_off"] != self.seen.get("power_off"):
            shown += self.announce("power_off", on, "The PC went off without shutting down",
                                   "HW Blackbox wrote a report with the last readings before it.",
                                   "incidents:%s" % new["power_off"])
        if new["crash"] and new["crash"] != self.seen.get("crash"):
            when, _, what = new["crash"].partition(": ")
            shown += self.announce("crash", on, what or new["crash"], "At %s. Its report is on the Incidents tab." %
                                   when[11:16] if len(when) >= 16 else "Its report is on the Incidents tab.",
                                   "incidents")
        for key, title in (("hardware", "The hardware reported an error"), ("drive", "A drive reported an error")):
            if new[key] and new[key] != self.seen.get(key):
                when, _, what = new[key].partition(": ")
                if "fatal" in what:
                    title = "A fatal hardware error"
                shown += self.announce("hardware", on, title, what[:1].upper() + what[1:] if what else new[key],
                                       "diagnose")
        for p in lasting:
            if p not in (self.seen.get("problems") or []):
                shown += self.announce("problem", on, "HW Blackbox: a problem", p, "overview")
        self.seen = dict(new, problems=lasting)
        self.save()
        return shown

    def announce(self, kind, on, title, body, where):
        """Show it, if this kind is on and within the ration. Returns [title] when shown."""
        now = self.clock()
        while self.sent and now - self.sent[0] > 3600:
            self.sent.popleft()
        if not on.get(kind) or len(self.sent) >= PER_HOUR or now - self.last_of.get(kind, -1e9) < EVERY_KIND:
            return []
        self.sent.append(now)
        self.last_of[kind] = now
        self.send(title, body, self.link(where))
        return [title]

    def save(self):
        try:
            write_json(self.path, self.seen)
        except Exception:
            pass
