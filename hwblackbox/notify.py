r"""Windows notifications, from the session agent (each signed-in user gets their own): a power-off, an app's crash
report, a hardware error or a drive's error, and a problem with HW Blackbox or the PC. Without them, someone who
doesn't run Home Assistant learns of these only when they open the page.

The agent reads the service's status (state\status.json) every 30 s and tells the user what's new since they were
last told (their sessions\<SID>\notified.json). On the first look after the install nothing is announced: what
happened before isn't news. Each kind can be turned off on the page's Settings tab (sessions\<SID>\settings.json,
the user's own), and they're rationed: one of a kind every 10 minutes, 6 an hour in all (a board that reports a
corrected error every few seconds doesn't make the PC unusable). A problem is announced once it has lasted a minute,
so a hiccup doesn't make a sound. A problem is known by its words with its measurements taken out (problem_key):
"the sensors aren't logging (last sample 3 min ago)" is the same problem a minute later at 4 min. Until 1.2.0 it was
known by its whole text, so the problems whose numbers move (the drive filling up, the sensors or the agent down for
N minutes) changed before they'd lasted a minute, and were never announced.

From 1.2.0 the agent also tells the user once when a new version of HW Blackbox is out (the daily update check,
which the agent now runs whether or not the page is open; updates.check: false in config.json turns both off).

A notification is Windows' own (a toast, in the notification center too), shown by Windows PowerShell for the app
"HW Blackbox" (the installer registers that name, HKLM\SOFTWARE\Classes\AppUserModelId\HWBlackbox). Clicking it
opens the page where it's explained."""
import collections
import os
import re
import subprocess
import threading
import time
from xml.sax.saxutils import escape, quoteattr

from . import VERSION
from .util import read_json, write_json

AUMID = "HWBlackbox"
POWERSHELL_AUMID = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe"
KINDS = collections.OrderedDict([
    ("power_off", "The PC went off without shutting down (a power cut, a crash, the power button held)"),
    ("crash", "An app you watch crashed or closed unexpectedly (Explorer, and those in config.json)"),
    ("hardware", "The hardware reported an error (the CPU, memory, PCIe) or a drive did"),
    ("problem", "Something stopped working: HW Blackbox's own parts, a server's port, the Windows drive filling up"),
    ("update", "A new version of HW Blackbox is out (once for each version)"),
])
EVERY_KIND = 600                 # seconds between two of the same kind
PER_HOUR = 6
PROBLEM_AFTER = 60               # seconds a problem must last before it's announced
CREATE_NO_WINDOW = 0x08000000
# a measurement in a problem's words: a number with its unit ("3 min", "41.2 GB", "25 s", "2 programs"). A number
# without one is part of what the problem is about (a port, "disk 1", a chip's name) and stays.
MEASURE = re.compile(r"\d+(?:\.\d+)?(?=\s*(?:min|s|h|GB|MB|KB|TB|%|days?|hours?|minutes?|seconds?|programs?)"
                     r"(?![A-Za-z]))")


def problem_key(text):
    """A problem as the notifications know it: its words with the measurements taken out."""
    return MEASURE.sub("#", str(text))
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
        self.problems_since = {}               # problem's key -> when it was first seen (this run)

    def link(self, where):
        return "http://127.0.0.1:%d/#%s" % (self.port, where) if self.port else None

    def check(self, status, status_age=None, offer=None):
        """Announce what's new in the service's status (status_age: how old the status file is: a service that has
        stopped writing it is a problem of its own). offer: the update check's offer ({"version", "url", ...}: a newer
        release), announced once per version."""
        now = self.clock()
        new = facts(status)
        new["update"] = (offer or {}).get("version") if isinstance(offer, dict) else None
        problems = list((status or {}).get("problems") or [])
        if status_age is not None and status_age > 180:
            problems.append("HW Blackbox's service isn't running: nothing is being recorded")
        words = {}                             # key -> the newest words for it
        for p in problems:
            words[problem_key(p)] = p
        for k in list(self.problems_since):
            if k not in words:
                del self.problems_since[k]
        for k in words:
            self.problems_since.setdefault(k, now)
        lasting = sorted(k for k, since in self.problems_since.items() if now - since >= PROBLEM_AFTER)
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
        # (what was told before 1.2.0 was kept by the whole text: known by its key now, so a problem with fixed words
        # that was announced isn't announced again)
        told = {problem_key(p) for p in self.seen.get("problems") or []}
        for k in lasting:
            if k not in told:
                shown += self.announce("problem", on, "HW Blackbox: a problem", words[k], "overview")
        if new["update"] and new["update"] != self.seen.get("update"):
            shown += self.announce("update", on, "HW Blackbox %s is out" % new["update"],
                                   "You have %s. The page says what's new; Update installs it, keeping the settings and "
                                   "the history." % VERSION, "overview")
        # (what was told and is still there stays told: until 1.2.0 a restart of the agent forgot it, since this run
        # hadn't seen it last a minute yet, and the problem was told again a minute later)
        self.seen = dict(new, problems=sorted(set(lasting) | {k for k in told if k in words}))
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
