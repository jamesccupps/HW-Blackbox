"""The settings: config.json in the data folder, over the defaults below.

The service reads it at start, and again every minute for "ports", "home_assistant", "dashboard", "disk_warn_gb" and
"disk_drop_gb", so those take effect without a restart. The watch list and the sensors' timing take a restart of the
service."""
import copy
import json
import math
import os
import re
import socket

from . import paths
from .util import read_json, write_json

HOST = socket.gethostname()
LIVE = ("ports", "home_assistant", "dashboard", "disk_warn_gb", "disk_drop_gb")


def slug(text):
    return re.sub(r"[^a-z0-9]+", "_", (text or "pc").lower()).strip("_") or "pc"


def defaults():
    return {
        # every reading every interval_s; the voltage rails every rails_interval_s (0: off). lhm_gpu:
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
        # The Windows drive: a problem below disk_warn_gb free, or when it loses disk_drop_gb within an hour and at that
        # rate would be under disk_warn_gb within two hours (filling up fast). Every fixed drive's free space is logged
        # every minute (logs\disks_*.csv).
        "disk_warn_gb": 10,
        "disk_drop_gb": 10,
    }


def _number(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _fits(default, val):
    """Is val the same kind of setting as its default?"""
    if isinstance(default, bool):
        return isinstance(val, bool)
    if _number(default):
        return _number(val)
    if isinstance(default, (str, list, dict)):
        return isinstance(val, type(default))
    return True


# settings whose default doesn't say all they may be, and the ranges of numbers
EITHER = {("sensors", "lhm_gpu"): (str, bool)}
RANGES = {("sensors", "keep_days"): (1, 3650), ("sensors", "rails_keep_days"): (1, 3650),
          ("events", "keep_days"): (1, 3650), ("ports", "down_after_min"): (0, 1440), ("dashboard", "port"): (1, 65535),
          ("disk_warn_gb",): (0, 1 << 20), ("disk_drop_gb",): (0, 1 << 20)}


def _rules(val, errors):
    rules = []
    for x in val:
        if not (isinstance(x, dict) and isinstance(x.get("exe"), str) and x["exe"]):
            errors.append("watch: a rule without an \"exe\"")
            continue
        r = dict(x)
        if not isinstance(r.get("label"), str):
            r["label"] = r["exe"]
        for k in ("match", "exclude", "incidents"):
            if k in r and not isinstance(r[k], str):
                errors.append("watch: %s's \"%s\" isn't text" % (r["exe"], k))
                del r[k]
        if "ports" in r:
            ports = r["ports"] if isinstance(r["ports"], list) else []
            if not isinstance(r["ports"], list):
                errors.append("watch: %s's \"ports\" isn't a list" % r["exe"])
            r["ports"] = [int(p) for p in ports if str(p).isdigit()]
        rules.append(r)
    return rules


def _merge(cfg, user):
    """The user's settings over the defaults. A setting of the wrong kind (a word where a number goes, ...) keeps its
    default and is named in the errors: a typo never stops the service."""
    errors = []
    for key, val in user.items():
        if key not in cfg:
            continue
        if key == "watch":
            if isinstance(val, list) and val:
                cfg["watch"] = _rules(val, errors)
            else:
                errors.append("watch: not a list of rules")
        elif isinstance(cfg[key], dict):
            if not isinstance(val, dict):
                errors.append("%s: not an object" % key)
                continue
            for k, v in val.items():
                ok = isinstance(v, EITHER[(key, k)]) if (key, k) in EITHER else \
                    k not in cfg[key] or _fits(cfg[key][k], v)
                lo, hi = RANGES.get((key, k), (None, None))
                if ok and lo is not None and not lo <= v <= hi:
                    ok = False
                if ok:
                    cfg[key][k] = v
                else:
                    errors.append("%s.%s: %s isn't a setting it can take" % (key, k, json.dumps(v)[:40]))
            if key == "ports":
                exp = cfg["ports"].get("expected") or {}
                cfg["ports"]["expected"] = {str(p): w for p, w in exp.items() if isinstance(w, dict)}
                if len(cfg["ports"]["expected"]) < len(exp):
                    errors.append("ports.expected: an entry that isn't an object")
            if key == "dashboard":
                cfg["dashboard"]["milestones"] = [m for m in cfg["dashboard"].get("milestones") or []
                                                  if isinstance(m, dict) and isinstance(m.get("at"), str)]
        elif _number(cfg[key]) and _number(val) and \
                RANGES.get((key,), (-math.inf, math.inf))[0] <= val <= RANGES.get((key,), (-math.inf, math.inf))[1]:
            cfg[key] = val
        else:
            errors.append("%s: %s isn't a setting it can take" % (key, json.dumps(val)[:40]))
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
    try:
        errors = _merge(cfg, user)
    except Exception as e:                # (never: but a settings file must not be able to stop the service)
        cfg, errors = defaults(), ["%s: %s (using the defaults)" % (type(e).__name__, e)]
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
