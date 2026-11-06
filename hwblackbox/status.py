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
from .sensors import SLOW_CPU_AGE
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


RESTART_KEYS = (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
                r"SOFTWARE\Microsoft\Windows\WindowsUpdate\Auto Update\RebootRequired")


def restart_pending_since():
    """When Windows Update (or servicing) started waiting for a restart, as epoch seconds (the oldest of its keys'
    last-written times); None if it isn't waiting."""
    import winreg
    times = []
    for key in RESTART_KEYS:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
                times.append(winreg.QueryInfoKey(k)[2] / 1e7 - 11644473600)    # (100 ns units since 1601)
        except OSError:
            continue
    return min(times) if times else None


def host_facts():
    """This PC, as the status file records it (so a copied data folder still says which PC it came from)."""
    v = sys.getwindowsversion()
    return {"host": socket.gethostname(), "boot_epoch": psutil.boot_time(), "disks": disks(),
            "threads": psutil.cpu_count(),               # (logical processors: what 100 % of the CPU is)
            "windows": "Windows %s, build %d" % ("11" if v.build >= 22000 else "10", v.build)}

# What Home Assistant gets: the facts that change rarely. HA keeps a history row for every change of state OR
# attributes, so per-minute numbers (CPU, memory, the last sample's time) stay in status.json; HA still sees every
# report through the sensor's last_reported, which an alert for "gone quiet" can use.
HA_KEYS = ("sensors", "rails", "cpu_temperature", "watcher", "session_agent", "boot", "last_incident",
           "last_shutdown", "last_power_loss", "last_power_loss_died_at", "windows_update")


PAWNIO_HOW = ("run Install.cmd again and answer yes to installing it (or, as admin: winget install namazso.PawnIO, "
              "then restart the PC)")


def sensor_problems(sens, a):
    """The problems with the CPU's and the board's sensors (read elevated), with what's true in a["rails"],
    a["cpu_temperature"] and a note for the page in a["board_note"].
    Until 1.0.9 a PC without rails always had the problem "No rail voltages (the sensor driver may be gone)": wrong on
    a laptop (there are no rails to read), and only a guess on a desktop. Now the driver's state says which it is."""
    out = []
    driver = sens.get("driver")                       # PawnIO: "running", "stopped", "missing"; None: can't be told
    chip, before, portable = sens.get("board_chip"), sens.get("board_chip_before"), sens.get("portable")
    no_driver = driver is not None and driver not in ("running", "starting")
    rails_ok, temp_ok = bool(sens.get("rails_ok")), bool(sens.get("cpu_temp_ok"))
    expected = bool(chip or before) or (driver is None and not portable)    # (unknown driver: as before 1.0.9)
    a["cpu_temperature"] = "ok" if temp_ok else "missing"
    a["rails"] = "ok" if rails_ok else "missing" if expected or (no_driver and not portable) else "none on this PC"
    if no_driver:
        what = "the CPU's temperature and power" + ("" if portable else ", the rail voltages")
        out.append("The PawnIO driver %s, so there's no reading of %s: %s" % (
            "isn't installed" if driver == "missing" else "isn't running (%s)" % driver, what, PAWNIO_HOW))
    elif not rails_ok and chip:
        out.append("No rail voltages from the board's sensor chip (%s)" % chip)
    elif not rails_ok and before:
        out.append("The board's sensor chip (%s) didn't answer when the service started: no rail voltages. Restart "
                   "the service, as admin: Restart-Service HWBlackbox" % before)
    elif not rails_ok and expected:
        out.append("No rail voltages (the sensor driver, PawnIO, may be gone)")
    if a["rails"] == "none on this PC":
        a["board_note"] = ("A laptop: no power supply rails to read" if portable else
                           "No board sensor chip that LibreHardwareMonitor can read, so no rail voltages")
    if not temp_ok and not no_driver:
        held = sens.get("cpu_age_s")
        if held is not None and held > SLOW_CPU_AGE:
            out.append("No CPU readings for %d s: reading the CPU's sensors is held up (a core kept busy by another "
                       "program, or the sensor driver)" % held)
        elif driver == "running":
            out.append("No CPU temperature: LibreHardwareMonitor reads none from this CPU")
        else:
            out.append("No CPU temperature (the sensor driver, PawnIO, may be gone)")
    return out


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
        age = sens.get("last_sample_age_s")
        if age is None and sens.get("last_sample"):           # (no row written yet by this run: the row's own time)
            last = parse_iso(sens["last_sample"])
            age = now - last if last else None
        a["sensors"] = "logging" if age is not None and age < 60 else "not logging"
        if a["sensors"] != "logging":
            problems.append("The sensors aren't logging" + ("" if age is None else " (last sample %d min ago)"
                                                             % (age // 60)))
        if sens.get("admin"):
            problems.extend(sensor_problems(sens, a))
        else:
            a["rails"] = a["cpu_temperature"] = "not elevated"
        fast = cfg["sensors"]["rails_interval_s"]
        hz = sens.get("fast_hz")
        # A note for the page, not a problem: the rails are still read, only less often, and what they read is what
        # matters. (The lane stopping is a problem: the supervisor's "stuck".) Until 1.0.7 this was a problem, and a
        # core kept busy all night by another program sent five phone alerts that read like a fault in the power.
        if svc.sensors.rails_on() and hz is not None and hz < 0.8 / fast:
            a["rails_note"] = "read %.1f times a second instead of %g: still read, only less often" % (
                hz, round(1 / fast, 2))
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
    free = svc.disks.free_gb()
    if free is not None:
        a["disk_free_gb"] = round(free, 1)
    problems.extend(svc.disks.problems(cfg))
    # (a note, not a problem: Windows decides when, and it isn't something wrong)
    try:
        since = restart_pending_since()
    except Exception:
        since = None
    a["windows_update"] = ("waiting for a restart since %s" % dt.datetime.fromtimestamp(since).strftime("%Y-%m-%d %H:%M")
                           if since else "no restart waiting")
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
