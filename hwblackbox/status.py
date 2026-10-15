r"""One status for everything: "ok" or "problem", the problems in words, and the facts Home Assistant shows.
Written to state\status.json every 30 s (the dashboard reads it) and sent to Home Assistant every minute."""
import datetime as dt
import os
import shutil
import socket
import sys
import time

import psutil

from . import VERSION
from .poweroff import last_dirty_shutdown
from .util import now_iso, parse_iso

_disks = {"at": 0.0, "list": []}


def disks():
    """The fixed drives and their free space (looked at every 10 minutes: a network or removable drive makes the
    look slow)."""
    if time.time() - _disks["at"] > 600:
        out = []
        for p in psutil.disk_partitions(all=False):
            if "fixed" not in (p.opts or ""):
                continue
            try:
                u = shutil.disk_usage(p.mountpoint)
            except OSError:
                continue
            out.append({"mount": p.mountpoint, "total_gb": round(u.total / 2**30, 1),
                        "free_gb": round(u.free / 2**30, 1)})
        _disks.update(at=time.time(), list=out)
    return _disks["list"]


def host_facts():
    """This PC, as the status file records it (so a copied data folder still says which PC it came from)."""
    v = sys.getwindowsversion()
    return {"host": socket.gethostname(), "boot_epoch": psutil.boot_time(), "disks": disks(),
            "windows": "Windows %s, build %d" % ("11" if v.build >= 22000 else "10", v.build)}

# What Home Assistant gets: the facts that change rarely. HA keeps a history row for every change of state OR
# attributes, so per-minute numbers (CPU, memory, the last sample's time) stay in status.json; HA still sees every
# report through the sensor's last_reported, which an alert for "gone quiet" can use.
HA_KEYS = ("sensors", "rails", "cpu_temperature", "watcher", "session_agent", "boot", "last_incident",
           "last_shutdown", "last_power_loss", "last_power_loss_died_at")


def build(svc):
    """(state, problems, attributes) from the service's parts."""
    now = time.time()
    cfg = svc.cfg
    problems, a = [], {}
    sens = svc.sensors.status() if svc.sensors else None
    if svc.sensors:
        svc.sensors.status_cache = sens
    elif svc.want_sensors:
        a["sensors"] = "not logging"
        if now - svc.started > 120:
            problems.append("The sensors haven't started (see the service's error records)")
    if sens is not None:
        last = parse_iso(sens.get("last_sample") or "")
        age = now - last if last else None
        a["sensors"] = "logging" if age is not None and age < 60 else "not logging"
        if a["sensors"] != "logging":
            problems.append("The sensors aren't logging" + ("" if age is None else " (last sample %d min ago)"
                                                             % (age // 60)))
        if sens.get("admin"):
            a["rails"] = "ok" if sens.get("rails_ok") else "missing"
            a["cpu_temperature"] = "ok" if sens.get("cpu_temp_ok") else "missing"
            if not sens.get("rails_ok"):
                problems.append("No rail voltages (the sensor driver, PawnIO, may be gone)")
            if not sens.get("cpu_temp_ok"):
                problems.append("No CPU temperature (the sensor driver, PawnIO, may be gone)")
        else:
            a["rails"] = a["cpu_temperature"] = "not elevated"
        fast = cfg["sensors"]["rails_interval_s"]
        hz = sens.get("fast_hz")
        if svc.sensors.rails_on() and hz is not None and hz < 0.8 / fast:
            problems.append("The rails lane is slow: %.2f a second (should be %g)" % (hz, round(1 / fast, 2)))
    lds = last_dirty_shutdown() or {}
    a["last_power_loss_died_at"] = lds.get("time_of_death")
    a["watcher"] = "running" + (" (test)" if svc.test else "")
    if svc.watcher.events and not any(v is not None for v in svc.watcher.events.last.values()):
        problems.append("Windows' event logs can't be read")
    # the session agents
    view = svc.agents.view
    signed_in = [s for s in view if s["state"] in ("active", "connected", "disconnected")]
    if not signed_in:
        a["session_agent"] = "nobody signed in"
    else:
        down = [s for s in signed_in if s["state"] == "active" and s["agent"] != "running"]
        a["session_agent"] = "running" if not down else "not running"
        for s in down:
            since = svc.agent_down.setdefault(s["session"], now)
            if now - since > 600:
                problems.append("The session agent isn't running for %s (%d min)" % (s["user"], (now - since) // 60))
        for sid in list(svc.agent_down):
            if sid not in {s["session"] for s in down}:
                del svc.agent_down[sid]
    # the ports
    if svc.ports.listed:
        problems.extend(svc.ports.problems[k] for k in sorted(svc.ports.problems))
        a["ports_listening"] = svc.ports.listening_count()
    if svc.ports.error:
        problems.append("The port check failed: %s" % svc.ports.error)
    free = svc.watcher.disk_free_gb()
    if free is not None:
        a["disk_free_gb"] = round(free, 1)
        if free < (cfg.get("disk_warn_gb") or 10):
            problems.append("%s has only %.1f GB free" % (os.environ.get("SystemDrive", "C:"), free))
    stuck = [name for name, age in svc.thread_ages().items() if age is not None and age > svc.STUCK.get(name, 120)]
    if stuck:
        problems.append("Part of the service is stuck: %s" % ", ".join(stuck))
    if cfg.get("error"):
        problems.append(cfg["error"])
    a["logs_mb"] = svc.watcher.logs_mb
    a["boot"] = dt.datetime.fromtimestamp(psutil.boot_time()).isoformat(timespec="seconds")
    a["version"] = VERSION
    a.update(svc.watcher.notes)
    return ("problem" if problems else "ok"), problems, a


def write(svc, state, problems, attrs):
    """state\\status.json: everything the dashboard shows about the service."""
    from .util import write_json
    from . import paths
    me = svc.me
    try:
        mem = round(me.memory_info().private / 2**20, 1)
    except Exception:
        mem = None
    write_json(paths.P.status, {
        "ts": now_iso(), "version": VERSION, "pid": os.getpid(), "started": svc.started_iso, "test": svc.test,
        "state": state, "problems": problems, "attributes": attrs, "pc": host_facts(),
        "sensors": svc.sensors.status_cache if svc.sensors else None,
        "apps": sorted("%s/%d" % (t.exe, t.pid) for t in svc.watcher.tracked.values() if t.main),
        "agents": svc.agents.view, "ha": svc.ha_result(), "cpu_pct": svc.cpu_pct, "mem_mb": mem,
        "threads": {k: None if v is None else round(v, 1) for k, v in svc.thread_ages().items()},
        "event_logs": {log: pos is not None for log, pos in svc.watcher.events.last.items()},
        "config_error": svc.cfg.get("error"), "data_dir": paths.P.data,
        "last_dirty_shutdown": last_dirty_shutdown()}, durable=True)


def ha_payload(svc, state, problems, attrs):
    ha = svc.cfg.get("home_assistant") or {}
    out = {k: attrs[k] for k in HA_KEYS if k in attrs}
    if attrs.get("disk_free_gb") is not None:
        out["disk_free_gb"] = int(attrs["disk_free_gb"])
    if attrs.get("logs_mb") is not None:
        out["logs_gb"] = round(attrs["logs_mb"] / 1024, 1)
    out.update({"problems": problems, "friendly_name": ha.get("name") or "HW Blackbox", "icon": "mdi:monitor-eye",
                "version": VERSION})
    return {"state": state, "attributes": out}
