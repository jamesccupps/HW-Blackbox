r"""python -m hwblackbox <command>

  service    the Windows service (what the service manager runs). Started by hand, it runs in this console instead.
  console    the service's work in this console, until Ctrl+C (testing)
  agent      the session agent (what the HWBlackboxAgent task runs at sign-in)
  open       open the dashboard in its own window; serves it from this process when no agent does
  serve      serve the dashboard from this process, with no window (--port N; until Ctrl+C or --run-for)
  once       one look at everything, printed: a sensor sample, the watched apps, the ports, the status
  status     the service's status file, printed
  init       make the data folders, and config.json with the defaults unless there is one (--set K=V to change some)
  set K=V    change settings in config.json (K dotted: home_assistant.enabled=true dashboard.port=9070)
  update     install the newest release from GitHub, checked against its SHA-256 (as admin: the page's Update button
             starts it). --dry-run: everything but the install; --pretend-version X: be version X; --from-zip Z
             --sha256 H: a zip on this PC instead

  --data-dir DIR   another data folder (default %ProgramData%\HWBlackbox)
  --test           a second instance next to the real one: its own lock, never sends to Home Assistant, never
                   restarts agents (with --data-dir)
  --no-sensors     (console) without the sensors
"""
import argparse
import json
import os
import subprocess
import sys
import threading
import time
import webbrowser

from . import NAME, VERSION, paths

EDGE = (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe")


def open_window(url):
    """Its own window: Edge's app mode (no tabs or address bar); the default browser if Edge isn't there."""
    for edge in EDGE:
        if os.path.exists(edge):
            try:
                subprocess.Popen([edge, "--app=" + url, "--window-size=1440,920"], close_fds=True)
                return
            except OSError:
                pass
    webbrowser.open(url)


def message(text):
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, text, NAME, 0x30)
    except Exception:
        print(text)


def cmd_open(args):
    from . import config
    from .dashboard import server
    port = int((config.load().get("dashboard") or {}).get("port") or 9070)
    url = "http://127.0.0.1:%d/" % port
    if server.who_serves(port):
        open_window(url)
        return 0
    try:
        httpd = server.start(port)
    except OSError:
        message("Port %d is taken by another program, so %s can't show its page.\n\nThe Ports page of the "
                "dashboard (or %s) says which one; another port: \"dashboard\": {\"port\": ...} in %s." %
                (port, NAME, paths.P.ports, paths.P.config))
        return 1
    threading.Timer(0.3, open_window, args=(url,)).start()
    # serve until no page has asked for anything for 20 minutes
    while time.time() - server.Handler.last_request < 20 * 60:
        time.sleep(30)
    httpd.shutdown()
    return 0


def cmd_serve(args):
    """The dashboard from this process, with no window (until Ctrl+C, or --run-for seconds)."""
    from . import config
    from .dashboard import server
    port = args.port or int((config.load().get("dashboard") or {}).get("port") or 9070)
    try:
        httpd = server.start(port)
    except OSError as e:
        print("Port %d: %s" % (port, e))
        return 1
    print("serving %s on http://127.0.0.1:%d/" % (paths.P.data, port))
    end = time.time() + args.run_for if args.run_for else None
    try:
        while end is None or time.time() < end:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    httpd.shutdown()
    return 0


def cmd_once(args):
    from . import config
    from .agents import Agents
    from .ports import PortWatch
    from .sensors import Sampler, SensorStats
    from .util import now_iso
    from .watcher import Watcher

    class Printer:
        """A journal that prints instead of writing."""
        def write(self, kind, payload=None, hard=True):
            print(json.dumps(dict({"kind": kind}, **(payload or {})), default=str))

        def recent(self, seconds):
            return []

    cfg = config.load()
    if cfg.get("error"):
        print("config:", cfg["error"])
    if not args.no_sensors:
        s = Sampler(gpu_mode=cfg["sensors"].get("lhm_gpu", "auto"))
        row, lhm = s.sample()
        time.sleep(1)
        row, lhm = s.sample()
        st = SensorStats(now_iso()).build(s, lhm, row)
        print(json.dumps({"admin": s.admin, "lhm_error": s.lhm.error, "nvml_error": s.nvml.error,
                          "lhm_sensors": len(lhm), "row": row,
                          "sensors": ["%s | %s | %s %s = %s %s" % (x["group"], x["device"], x["type"], x["name"],
                                                                    x["value"], x["unit"]) for x in st["sensors"]]},
                         indent=1, default=str))
    j = Printer()
    agents = Agents(j, restart=False)
    agents.refresh()
    print(json.dumps({"sessions": agents.view}, default=str))
    ports = PortWatch(j)
    w = Watcher(j, cfg, ports, agents, test=True)
    w.events.save = lambda: None
    w.users = {s["session"]: s["user"] for s in agents.view}
    w.scan(startup=True)
    w.load_notes()
    for _ in range(PortWatch.OPEN_AFTER):
        ports.scan(cfg, w.label_for)
        time.sleep(1)
    print(json.dumps({"notes": w.notes, "events_from": w.events.last, "port_problems": ports.problems},
                     default=str, indent=1))
    return 0


def cmd_init(args):
    """The data folders, and config.json with the defaults (and --set) unless there is one."""
    from . import config
    from .util import write_json
    paths.P.make("logs", "state", "incidents", "sessions", "secrets")
    if os.path.exists(paths.P.config) and not args.force:
        print("kept the existing %s" % paths.P.config)
    else:
        cfg = config.defaults()
        for item in args.set or []:
            apply_setting(cfg, item)
        cfg.pop("error", None)
        write_json(paths.P.config, cfg, indent=2)
        print("wrote %s" % paths.P.config)
    return 0


def apply_setting(cfg, item):
    """KEY=VALUE, KEY dotted ("dashboard.port=9070"); VALUE as JSON when it is (true, 9070, [..]), else text."""
    key, _, raw = item.partition("=")
    try:
        val = json.loads(raw)
    except ValueError:
        val = raw
    node = cfg
    parts = key.strip().split(".")
    for p in parts[:-1]:
        node = node.setdefault(p, {})
    node[parts[-1]] = val


def cmd_set(args):
    from .util import read_json, write_json
    cfg = read_json(paths.P.config)
    if not isinstance(cfg, dict):
        print("No readable %s (run init first)" % paths.P.config)
        return 1
    for item in args.items:
        apply_setting(cfg, item)
    write_json(paths.P.config, cfg, indent=2)
    print("updated %s: %s" % (paths.P.config, ", ".join(args.items)))
    return 0


def cmd_status(args):
    from .util import read_json, age
    st = read_json(paths.P.status)
    if not st:
        print("No status at %s: the service hasn't run with this data folder." % paths.P.status)
        return 1
    st["age_s"] = round(age(paths.P.status) or 0)
    print(json.dumps(st, indent=1, default=str))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="hwblackbox", description="%s %s" % (NAME, VERSION),
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("command", choices=["service", "console", "agent", "open", "serve", "once", "status", "init",
                                        "set", "update"])
    ap.add_argument("--port", type=int, help="(serve) the port, instead of config.json's")
    ap.add_argument("items", nargs="*", help="(set) KEY=VALUE settings, KEY dotted: dashboard.port=9070")
    ap.add_argument("--data-dir")
    ap.add_argument("--force", action="store_true", help="(init) write config.json even if there is one")
    ap.add_argument("--set", action="append", help="(init) a KEY=VALUE setting for the new config.json")
    ap.add_argument("--test", action="store_true")
    ap.add_argument("--no-sensors", action="store_true")
    ap.add_argument("--no-dashboard", action="store_true")
    ap.add_argument("--run-for", type=float, help="(console, agent) stop after this many seconds")
    ap.add_argument("--dry-run", action="store_true", help="(update) everything but the install")
    ap.add_argument("--pretend-version", help="(update) be this version")
    ap.add_argument("--from-zip", help="(update) this zip instead of the download (with --sha256)")
    ap.add_argument("--sha256", help="(update) the --from-zip zip's SHA-256")
    ap.add_argument("--staging", help="(update) unpack here instead of the data folder's update\\")
    args = ap.parse_args(argv)
    if args.data_dir:
        paths.init(args.data_dir)
    if args.test and not args.data_dir and args.command in ("console", "agent"):
        ap.error("--test needs --data-dir (a test instance never writes into the real data folder)")
    if args.command == "service":
        from . import service
        return service.main(test=args.test, sensors=not args.no_sensors)
    if args.command == "console":
        from . import service
        return service.main(console=True, test=args.test, sensors=not args.no_sensors, run_for=args.run_for)
    if args.command == "agent":
        from . import agent
        return agent.main(test=args.test, serve=not args.no_dashboard, run_for=args.run_for)
    if args.command == "open":
        return cmd_open(args)
    if args.command == "serve":
        return cmd_serve(args)
    if args.command == "once":
        return cmd_once(args)
    if args.command == "status":
        return cmd_status(args)
    if args.command == "init":
        return cmd_init(args)
    if args.command == "set":
        return cmd_set(args)
    if args.command == "update":
        from . import update

        def wait():
            if sys.stdin and sys.stdin.isatty():
                try:
                    input("\nPress Enter to close this window.")
                except (EOFError, KeyboardInterrupt):
                    pass
        return update.run(dry_run=args.dry_run, pretend=args.pretend_version, from_zip=args.from_zip,
                          sha256=args.sha256, staging=args.staging, wait=None if args.dry_run else wait)
    return 2


if __name__ == "__main__":
    code = main()
    if sys.stdout:                    # (pythonw has none)
        sys.stdout.flush()
    # (pythonnet's runtime can hold up a normal interpreter exit; everything is on disk by now)
    os._exit(code or 0)
