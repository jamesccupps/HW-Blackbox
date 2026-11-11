r"""The session agents, seen from the service: what each one last said (sessions\<SID>\agent.json and front.json),
and starting one again, through its scheduled task, when a signed-in session's agent has stopped.

Each user's folder is named by their account's SID and made by the service (since 1.1.0), for SYSTEM, the
administrators and that user only: users can't make folders in sessions\, so nobody can make another user's folder
first, write in it, or read it. Until 1.1.0 each agent made its own folder, named by the user's name, and any user
could make any name's (the 2026-11-05 review's M2): such a folder, made by its own user, is moved to the new name."""
import datetime as dt
import os
import re
import sys
import threading
import time

import psutil

from . import AGENT_TASK, paths, winapi
from .journal import read_tail
from .util import is_link, read_json

STALE = 150          # seconds without a heartbeat
GRACE = 180          # seconds a session gets after it first appears (its agent starts at sign-in)
RETRY = 300          # seconds between restarts of the same session's agent
TASK_RUN_USE_SESSION_ID = 4
SID_NAME = re.compile(r"^S-1-\d+(-\d+)+$")
SYSTEM, ADMINS = "S-1-5-18", "S-1-5-32-544"


def session_folder(name):
    """A session agent's folder (by the user's SID; a name for an older version's), or None when it's a link to
    somewhere else."""
    if not name:
        return None
    folder = paths.P.session_dir(name)
    return None if is_link(folder) else folder


_sids = {}


def sid_of(domain, user):
    """The account's SID as text ("S-1-5-21-...-1001"), or None."""
    key = (domain or "", user or "")
    if key not in _sids:
        try:
            import win32security
            account = "%s\\%s" % (domain, user) if domain else user
            _sids[key] = win32security.ConvertSidToStringSid(win32security.LookupAccountName(None, account)[0])
        except Exception:
            return None
    return _sids[key]


def owner_of(path):
    """A file's or folder's owner's SID as text, or None."""
    try:
        import win32security
        sd = win32security.GetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION)
        return win32security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner())
    except Exception:
        return None


def folder_security(sid, owner=True):
    """The security for a user's folder: SYSTEM and the administrators everything, the user modify (theirs to
    write, not to give away: the owner is the administrators), protected from what sessions\\ would pass down."""
    import win32security
    sddl = "%sD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;%s)" % ("O:BAG:SY" if owner else "", sid)
    return win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1)


def inherit_children(path, sid):
    """Every file and folder in a user's folder takes its permissions from that folder again (a DACL of its own that's
    empty, and inherits). Files moved in from an older version's folder keep the permissions of where they were, and
    on 2026-11-10 the first 1.1.0 install left them read-only for their own user: the agent couldn't open its own
    crash log, and exited at every start. Only what the user owns and has one name for (a hard link to someone
    else's file is never handed to them), never through a link."""
    import win32security
    empty = win32security.ACL()
    flags = win32security.DACL_SECURITY_INFORMATION | win32security.UNPROTECTED_DACL_SECURITY_INFORMATION
    done = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if not is_link(os.path.join(root, d))]
        for name in dirs + files:
            p = os.path.join(root, name)
            try:
                if is_link(p) or owner_of(p) != sid or (name in files and os.stat(p).st_nlink != 1):
                    continue
                win32security.SetNamedSecurityInfo(p, win32security.SE_FILE_OBJECT, flags, None, None, empty, None)
                done += 1
            except Exception:
                continue
    return done


_folder_lock = threading.Lock()


def make_user_folder(sid, user, jrnl=None):
    """sessions\\<sid>, made with the user's own permissions (the service, as SYSTEM, calls this for each signed-in
    user): the path, or None when it can't be. A folder of that name that someone else made first (before 1.1.0
    anyone could) is moved aside, never used; an older version's folder named by the user, made by that user's own
    agent, is moved here with its history. (One at a time: a sign-in and the 30-second look can come together.)"""
    with _folder_lock:
        return _make_user_folder(sid, user, jrnl)


def _make_user_folder(sid, user, jrnl):
    import win32file
    import win32security
    path = paths.P.session_dir(sid)
    if os.path.lexists(path):
        if not is_link(path) and os.path.isdir(path) and owner_of(path) in (SYSTEM, ADMINS):
            return path
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        try:
            os.rename(path, path + ".untrusted-" + stamp)
            if jrnl:
                jrnl.write("error", {"where": "session folders", "error": "%s wasn't made by HW Blackbox: moved aside "
                                     "to %s.untrusted-%s" % (path, sid, stamp)})
        except OSError:
            return None
    old = paths.P.session_dir(user) if user else None
    elevated = winapi.is_system() or winapi.is_admin()         # (only then can the owner be the administrators)
    try:
        moved = old and os.path.isdir(old) and not is_link(old) and owner_of(old) == sid
        if moved:
            os.rename(old, path)
    except OSError:
        moved = False
    if moved:
        try:
            sd = folder_security(sid, owner=elevated)
            flags = win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION
            win32security.SetNamedSecurityInfo(
                path, win32security.SE_FILE_OBJECT, flags | (win32security.OWNER_SECURITY_INFORMATION if elevated
                                                             else 0),
                sd.GetSecurityDescriptorOwner() if elevated else None, None, sd.GetSecurityDescriptorDacl(), None)
        except Exception as e:
            if jrnl:
                jrnl.write("error", {"where": "session folders", "error": "%s: its permissions: %s" % (path, e)})
        inherit_children(path, sid)                   # (and the files in it, which kept their old permissions)
        if jrnl:
            jrnl.write("agent", {"event": "folder moved", "user": user, "why": "sessions\\%s is now sessions\\%s "
                                 "(named by the account, for that user only)" % (os.path.basename(old), sid)})
        return path
    try:
        sa = win32security.SECURITY_ATTRIBUTES()
        sa.SECURITY_DESCRIPTOR = folder_security(sid, owner=elevated)
        win32file.CreateDirectory(path, sa)
        return path
    except Exception:
        return None


def agent_procs(session):
    """The agent processes in a session (pythonw.exe running "-m hwblackbox agent")."""
    out = []
    for p in psutil.process_iter(["pid", "name", "create_time"]):
        if (p.info["name"] or "").lower() not in ("python.exe", "pythonw.exe"):
            continue
        if winapi.session_of(p.info["pid"]) != session:
            continue
        try:
            cl = " ".join(p.cmdline()).lower()
        except Exception:
            continue
        if "hwblackbox" in cl and " agent" in cl:
            out.append(p)
    return out


def inside(path, folder):
    """Is path in folder (or folder itself)?"""
    try:
        path, folder = os.path.normcase(os.path.abspath(path)), os.path.normcase(os.path.abspath(folder))
        return os.path.commonpath([path, folder]) == folder
    except ValueError:                     # (different drives)
        return False


def com_cache_ok():
    """pywin32's COM cache must be the program's own (under Program Files, admins only): win32com.client unpickles a
    file from it as it's imported, and the fallback, the temp folder, is C:\\Windows\\Temp for SYSTEM, where any user
    can make the folder first. (Importing win32com itself reads nothing from it.)"""
    try:
        import win32com
        return inside(win32com.__gen_path__, sys.prefix)
    except Exception:
        return False


def get_task():
    """('present', task), ('missing', None), ('unknown', None) or ('unsafe', None). Only Task Scheduler's own "not
    found" counts as missing."""
    if not com_cache_ok():
        return "unsafe", None
    try:
        import pythoncom
        import pywintypes
        import win32com.client
        pythoncom.CoInitialize()
        svc = win32com.client.Dispatch("Schedule.Service")
        svc.Connect()
        try:
            return "present", svc.GetFolder("\\").GetTask(AGENT_TASK)
        except pywintypes.com_error as e:
            ei = e.excepinfo or ()
            scode = (ei[5] if len(ei) > 5 and ei[5] else e.hresult) & 0xFFFFFFFF
            return ("missing" if scode == 0x80070002 else "unknown"), None
    except Exception:
        return "unknown", None


class Agents:
    def __init__(self, jrnl, restart=True, folders=False):
        self.jrnl = jrnl
        self.restart = restart             # (off for a test instance: it never touches the real agents)
        self.folders = folders             # (the real service makes each signed-in user's folder)
        self.checked = set()               # SIDs whose folder's files this run has given back their permissions
        self.first_seen = {}               # session id -> when this service first saw it signed in
        self.last_restart = {}             # session id -> time
        self.view = []                     # [{session, user, state, agent, age, ...}], refreshed every 30 s
        self.heartbeats = {}               # session id -> the agent's last heartbeat
        self.last_beat = {}                # session id -> when that heartbeat was written (agent.json's time)
        self.task = None

    def refresh(self):
        now = time.time()
        view, beats = [], {}
        current = winapi.sessions()
        for s in current:
            sid, user = s["id"], s["user"]
            self.first_seen.setdefault(sid, now)
            account = sid_of(s.get("domain"), user)
            if self.folders and account:
                made = make_user_folder(account, user, self.jrnl)
                if made and account not in self.checked:
                    # once a run: the files in it take their permissions from it (see inherit_children)
                    self.checked.add(account)
                    inherit_children(made, account)
            folder = session_folder(account or user)
            path = os.path.join(folder, "agent.json") if folder else None
            hb = (read_json(path, limit=1 << 20) if path else None) or {}
            if not isinstance(hb, dict):
                hb = {}
            try:
                written = os.path.getmtime(path) if hb.get("session") == sid and isinstance(hb.get("ts"), str) else None
            except (OSError, TypeError):
                written = None
            if written is not None:
                beats[sid], self.last_beat[sid] = hb, written
            elif sid in self.heartbeats:
                # One failed read isn't a missing heartbeat: the file can't be opened while the agent swaps a new one
                # in, or while a virus scanner holds it. (On 2026-10-16 that restarted a healthy agent twice.) Judge
                # by the last heartbeat read.
                beats[sid] = self.heartbeats[sid]
            last = self.last_beat.get(sid)
            age = None if last is None else now - last
            state = "running" if age is not None and age <= STALE else "stale" if age is not None else "none"
            good = beats.get(sid) or {}
            view.append({"session": sid, "user": user, "state": s["state"], "agent": state,
                         "age": None if age is None else round(age), "pid": good.get("pid"),
                         "version": good.get("version"), "folder": account or user})
            if state != "running" and s["state"] == "active" and self.restart:
                self.maybe_restart(sid, user, state, age, now)
        for sid in list(self.first_seen):
            if sid not in {s["id"] for s in current}:
                del self.first_seen[sid]
                self.last_beat.pop(sid, None)
        self.view, self.heartbeats = view, beats

    def make_folder_now(self, session):
        """A session that has just signed in: its user's folder now, so its agent (starting this moment) has it."""
        if not self.folders:
            return
        for s in winapi.sessions():
            if s["id"] == session:
                account = sid_of(s.get("domain"), s["user"])
                if account:
                    make_user_folder(account, s["user"], self.jrnl)

    def maybe_restart(self, sid, user, state, age, now):
        if now - self.first_seen.get(sid, now) < GRACE or now - self.last_restart.get(sid, 0) < RETRY:
            return
        procs = agent_procs(sid)
        if any(now - (p.info.get("create_time") or 0) < 90 for p in procs):
            return                                          # (one has just started: give it time)
        self.last_restart[sid] = now
        st, task = get_task()
        self.task = st
        why = "no heartbeat" if state == "none" else "heartbeat stale (%d s)" % age
        if task is None:
            self.jrnl.write("agent", {"event": "can't restart", "session": sid, "user": user, "why": why,
                                      "task": st})
            return
        for p in procs:
            try:
                p.kill()
            except Exception:
                pass
        try:
            task.RunEx(None, TASK_RUN_USE_SESSION_ID, sid, "")
            self.jrnl.write("agent", {"event": "restarted", "session": sid, "user": user, "why": why,
                                      "ended": [p.pid for p in procs]})
        except Exception as e:
            self.jrnl.write("agent", {"event": "restart failed", "session": sid, "user": user, "why": why,
                                      "error": str(e)[:200]})

    # what the agents know, for the service's records and reports -----------------------------------------------

    def taskbar_pids(self):
        return {hb.get("taskbar_pid") for hb in self.heartbeats.values() if hb.get("taskbar_pid")}

    def taskbar_of(self, sid):
        """The taskbar's process in a session (its Explorer), from the session agent's heartbeat; None if unknown."""
        return (self.heartbeats.get(sid) or {}).get("taskbar_pid")

    def screens(self):
        return {sid: hb.get("screens") or [] for sid, hb in self.heartbeats.items()}

    def front(self, seconds=180):
        """{session: [[time, exe, idle s], ...]}: the app in front, from each agent's front.json."""
        out = {}
        cutoff = time.time() - seconds
        for s in self.view:
            folder = session_folder(s.get("folder") or s["user"])
            data = (read_json(os.path.join(folder, "front.json"), limit=1 << 20) if folder else None) or {}
            if isinstance(data, dict) and data.get("session") == s["session"]:
                ring = data.get("ring") if isinstance(data.get("ring"), list) else []
                out[s["session"]] = [x for x in ring if isinstance(x, list) and len(x) >= 2
                                     and isinstance(x[0], (int, float)) and x[0] >= cutoff]
        return out

    def recent_records(self, seconds=180):
        """The agents' own records from the last `seconds` (display changes, the taskbar, shutdown requests)."""
        out = []
        for s in self.view:
            folder = session_folder(s.get("folder") or s["user"])
            if not folder:
                continue
            path = os.path.join(folder, "session_%s.jsonl" % time.strftime("%Y%m%d"))
            out.extend(dict(r, session=s["session"]) for r in read_tail(path, seconds, 1 << 20) if isinstance(r, dict))
        return sorted(out, key=lambda r: r.get("ts", ""))
