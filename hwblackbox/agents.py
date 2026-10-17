r"""The session agents, seen from the service: what each one last said (sessions\<user>\agent.json and front.json),
and starting one again, through its scheduled task, when a signed-in session's agent has stopped."""
import os
import time

import psutil

from . import AGENT_TASK, paths, winapi
from .journal import read_tail
from .util import read_json

STALE = 150          # seconds without a heartbeat
GRACE = 180          # seconds a session gets after it first appears (its agent starts at sign-in)
RETRY = 300          # seconds between restarts of the same session's agent
TASK_RUN_USE_SESSION_ID = 4


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


def get_task():
    """('present', task), ('missing', None) or ('unknown', None). Only Task Scheduler's own "not found" counts."""
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
    def __init__(self, jrnl, restart=True):
        self.jrnl = jrnl
        self.restart = restart             # (off for a test instance: it never touches the real agents)
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
            path = os.path.join(paths.P.session_dir(user), "agent.json")
            hb = read_json(path, limit=1 << 20) or {}
            try:
                written = os.path.getmtime(path) if hb.get("session") == sid and isinstance(hb.get("ts"), str) else None
            except OSError:
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
                         "version": good.get("version")})
            if state != "running" and s["state"] == "active" and self.restart:
                self.maybe_restart(sid, user, state, age, now)
        for sid in list(self.first_seen):
            if sid not in {s["id"] for s in current}:
                del self.first_seen[sid]
                self.last_beat.pop(sid, None)
        self.view, self.heartbeats = view, beats

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

    def screens(self):
        return {sid: hb.get("screens") or [] for sid, hb in self.heartbeats.items()}

    def front(self, seconds=180):
        """{session: [[time, exe, idle s], ...]}: the app in front, from each agent's front.json."""
        out = {}
        cutoff = time.time() - seconds
        for s in self.view:
            data = read_json(os.path.join(paths.P.session_dir(s["user"]), "front.json"), limit=1 << 20) or {}
            if data.get("session") == s["session"]:
                out[s["session"]] = [x for x in data.get("ring") or [] if isinstance(x, list) and x and x[0] >= cutoff]
        return out

    def recent_records(self, seconds=180):
        """The agents' own records from the last `seconds` (display changes, the taskbar, shutdown requests)."""
        out = []
        for s in self.view:
            day = time.strftime("%Y%m%d")
            path = os.path.join(paths.P.session_dir(s["user"]), "session_%s.jsonl" % day)
            out.extend(dict(r, session=s["session"]) for r in read_tail(path, seconds, 1 << 20))
        return sorted(out, key=lambda r: r.get("ts", ""))
