"""The settings: config.json in the data folder, over the defaults below.

The service reads it at start, and again every minute for "ports", "home_assistant", "dashboard" and "disk_warn_gb",
so those take effect without a restart. The watch list and the sensors' timing take a restart of the service."""
import copy
import os
import re
import socket

from . import paths
from .util import read_json, write_json

HOST = socket.gethostname()
LIVE = ("ports", "home_assistant", "dashboard", "disk_warn_gb")


def slug(text):
    return re.sub(r"[^a-z0-9]+", "_", (text or "pc").lower()).strip("_") or "pc"


def defaults():
    return {
        # every reading every interval_s; the voltage rails and the CPU every rails_interval_s (0: off). lhm_gpu:
        # LibreHardwareMonitor's GPU readings, for AMD and Intel GPUs ("auto": when there's no NVIDIA GPU, which is
        # read through NVML; true / false)
        "sensors": {"interval_s": 5.0, "rails_interval_s": 0.25, "keep_days": 183, "rails_keep_days": 7,
                    "lhm_gpu": "auto"},
        "events": {"keep_days": 183},
        # The apps to watch, by exe name. Optional: "match", a word the command line must have, and "exclude", one it
        # must not; "ports", the ports it listens on (a server: found by its port, and the process that started it is
        # watched too, as its supervisor); "incidents": "crash" writes an incident report only for a crash (an app
        # that's stopped and started all day), the default writes one for any exit but a clean one.
        "watch": [
            {"exe": "explorer.exe", "label": "Windows Explorer"},
            {"exe": "pythonw.exe", "label": "HW Blackbox agent", "match": "hwblackbox agent"},
        ],
        # The ports. "expected": port -> who should hold it ({"label", "exe", "always": a server that should always be
        # listening}); "ignore": ports two programs may share.
        "ports": {"expected": {}, "ignore": [], "down_after_min": 5},
        # A status for Home Assistant every minute (a sensor entity). env_file: HA_URL=... and HA_TOKEN=... lines.
        "home_assistant": {"enabled": False, "env_file": os.path.join(paths.P.secrets, "home_assistant.env"),
                           "entity": "sensor.%s_hw_blackbox" % slug(HOST), "name": "%s HW Blackbox" % HOST},
        # The page. "milestones": [{"at": "2026-10-08T19:03:00", "text": "..."}], marked on the charts.
        "dashboard": {"enabled": True, "port": 9070, "milestones": []},
        "disk_warn_gb": 10,
    }


def _merge(cfg, user):
    errors = []
    for key, val in user.items():
        if key not in cfg:
            continue
        if key == "watch":
            if isinstance(val, list) and val:
                rules = [dict(x) for x in val if isinstance(x, dict) and isinstance(x.get("exe"), str) and x["exe"]]
                for r in rules:
                    r.setdefault("label", r["exe"])
                    if r.get("ports"):
                        r["ports"] = [int(p) for p in r["ports"] if str(p).isdigit()]
                cfg["watch"] = rules
            else:
                errors.append("watch: not a list of rules")
        elif isinstance(cfg[key], dict):
            if isinstance(val, dict):
                cfg[key].update(val)
            else:
                errors.append("%s: not an object" % key)
        elif isinstance(cfg[key], (int, float)) and not isinstance(val, bool) and isinstance(val, (int, float)):
            cfg[key] = val
        else:
            errors.append("%s: wrong type" % key)
    return errors


def load(path=None):
    """The settings (defaults, overridden by config.json). An unreadable file leaves the defaults, with "error" set."""
    cfg = defaults()
    path = path or paths.P.config
    if not os.path.exists(path):
        return cfg
    user = read_json(path)
    if not isinstance(user, dict):
        cfg["error"] = "%s is unreadable: using the defaults" % path
        return cfg
    errors = _merge(cfg, user)
    s = cfg["sensors"]
    s["interval_s"] = min(60.0, max(1.0, float(s.get("interval_s") or 5)))
    s["rails_interval_s"] = min(5.0, max(0.0, float(s.get("rails_interval_s") or 0)))
    if errors:
        cfg["error"] = "config.json: " + "; ".join(errors)
    return cfg


def write_default(path=None, overrides=None):
    """A config.json with the defaults (and overrides), for a first install."""
    cfg = defaults()
    if overrides:
        _merge(cfg, overrides)
    write_json(path or paths.P.config, cfg, indent=2)
    return cfg


def public(cfg):
    """The settings without anything secret, for the dashboard."""
    out = copy.deepcopy({k: v for k, v in cfg.items() if k != "error"})
    out["home_assistant"].pop("env_file", None)
    return out
