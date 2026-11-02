"""Who listens on which TCP port, and trouble with it: two programs on one port, a known port held by the wrong
program, a server that should always be listening and isn't."""
import collections
import datetime as dt
import time

import psutil

from .util import now_iso, write_json
from .winapi import tcp_listeners


def addr_text(ip, port):
    return "[%s]:%d" % (ip, port) if ":" in ip else "%s:%d" % (ip, port)


def overlap(a, b):
    """Could listeners on these two addresses (the same port) get each other's connections? Only within one address
    family, and only on the same address or with one of them on all addresses (0.0.0.0 or ::). (2026-10-29: Tailscale
    on its own 100.x address and a program on 127.0.0.2 were taken for a clash; so was one browser on 127.0.0.1 and
    ::1.)"""
    if (":" in a) != (":" in b):
        return False
    return a == b or a in ("0.0.0.0", "::") or b in ("0.0.0.0", "::")


def same_program(exe, want):
    """exe names, ignoring case; python.exe and pythonw.exe count as one (the same program, with or without a console)."""
    norm = lambda x: (x or "").lower().replace("pythonw.exe", "python.exe")        # noqa: E731
    return norm(exe) == norm(want)


def describe_pid(pid):
    """(exe name, its command line without the program, or None where Windows won't show it)."""
    try:
        p = psutil.Process(pid)
        exe = p.name()
    except Exception:
        return "?", None
    try:
        cmd = " ".join(p.cmdline()[1:])[:200] or None
    except Exception:
        cmd = None
    return exe, cmd


class PortWatch:
    """Scanned every 15 s.
    - A listener counts once it's been seen at OPEN_AFTER scans in a row (so one that lives for a few seconds, like a
      language server's, makes no records), and is gone after CLOSE_AFTER scans without it.
    - Problems: two programs listening on the same port where their addresses overlap (say one on 0.0.0.0 and one on
      127.0.0.1: Windows allows it, and the more specific one quietly gets the connections); a port in
      ports.expected held by another program; an "always" server not listening for down_after_min.
    - Records: "ports" once (everything listening), then "port" for each change and each problem starting or ending.
    - state\\ports.json has the table and the problems after every scan, for the dashboard."""

    OPEN_AFTER = 2
    CLOSE_AFTER = 2

    def __init__(self, jrnl, save_path=None):
        self.jrnl = jrnl
        self.save_path = save_path
        self.table = {}                  # (ip, port) -> entry
        self.scans = 0
        self.listed = False              # the "ports" record written
        self.problems = {}               # key -> text, as last reported
        self.down = {}                   # port -> since when an "always" server's port has been free
        self.error = None

    def scan(self, cfg, label_for, current=None):
        now = time.time()
        self.scans += 1
        if current is None:
            try:
                current = tcp_listeners()
                self.error = None
            except Exception as e:
                self.error = ("%s: %s" % (type(e).__name__, e))[:200]
                return
        for key, pid in current.items():
            e = self.table.get(key)
            if e is not None and e["pid"] == pid:
                e["hits"] += 1
                e["misses"] = 0
            else:
                before = "%s/%d" % (e["exe"], e["pid"]) if e is not None and e["open"] else None
                exe, cmd = describe_pid(pid)
                e = self.table[key] = {"ip": key[0], "port": key[1], "pid": pid, "exe": exe, "cmd": cmd, "app": None,
                                       "since": now, "hits": 1, "misses": 0, "open": False, "before": before}
            if not e["open"] and e["hits"] >= self.OPEN_AFTER:
                e["open"] = True
                e["app"] = label_for(pid, e["port"], e["exe"])
                if self.listed:
                    self.jrnl.write("port", {"event": "new owner" if e["before"] else "open",
                                             "addr": addr_text(*key), "pid": pid, "exe": e["exe"], "app": e["app"],
                                             "cmd": e["cmd"], "before": e["before"]})
        for key, e in list(self.table.items()):
            if key in current:
                continue
            e["misses"] += 1
            if e["misses"] >= (self.CLOSE_AFTER if e["open"] else 1):
                del self.table[key]
                if e["open"] and self.listed:
                    gone = now - e["since"]
                    self.jrnl.write("port", {"event": "closed", "addr": addr_text(*key), "pid": e["pid"],
                                             "exe": e["exe"], "app": e["app"],
                                             "seen_for": "%dh %02dm" % (gone // 3600, gone % 3600 // 60)})
        if not self.listed and self.scans >= self.OPEN_AFTER:
            self.listed = True
            self.jrnl.write("ports", {"listening": ["%s %s/%d%s" % (addr_text(e["ip"], e["port"]), e["exe"], e["pid"],
                                                                     " (%s)" % e["app"] if e["app"] else "")
                                                    for e in self.sorted_open()]})
        self.check(cfg, now)
        if self.save_path:
            self.save()

    def sorted_open(self):
        return sorted((e for e in self.table.values() if e["open"]), key=lambda e: (e["port"], e["ip"]))

    def check(self, cfg, now):
        pc = cfg.get("ports") or {}
        expected = {int(k): v for k, v in (pc.get("expected") or {}).items() if str(k).isdigit() and isinstance(v, dict)}
        ignore = {int(x) for x in (pc.get("ignore") or []) if str(x).isdigit()}
        by_port = collections.defaultdict(dict)                   # port -> {pid: entry}
        every = collections.defaultdict(list)                     # port -> every entry (a program on several addresses)
        for e in self.sorted_open():
            by_port[e["port"]].setdefault(e["pid"], e)
            every[e["port"]].append(e)
        found = {}
        for port, owners in by_port.items():
            if port in ignore:
                continue
            clash = {a["pid"]: a for a in every[port] for b in every[port]
                     if a["pid"] != b["pid"] and overlap(a["ip"], b["ip"])}
            if len(clash) > 1:
                found["shared:%d" % port] = "Port %d is held by %d programs: %s" % (
                    port, len(clash), ", ".join("%s (pid %d, on %s)" % (e["exe"], e["pid"], e["ip"])
                                                for e in clash.values()))
            want = expected.get(port) or {}
            if want.get("exe"):
                wrong = [e for e in owners.values() if not same_program(e["exe"], want["exe"])]
                if wrong:
                    found["owner:%d" % port] = "Port %d (%s) is held by %s" % (
                        port, want.get("label") or want["exe"], ", ".join("%s (pid %d)" % (e["exe"], e["pid"])
                                                                         for e in wrong))
        down_after = pc.get("down_after_min")
        down_after = 5 if not isinstance(down_after, (int, float)) else down_after
        if self.listed:                                           # (not before the table has settled)
            for port, want in expected.items():
                if not want.get("always") or port in by_port:
                    self.down.pop(port, None)
                    continue
                since = self.down.setdefault(port, now)
                if now - since >= 60 * down_after:
                    found["down:%d" % port] = "Nothing has listened on port %d (%s) since %s" % (
                        port, want.get("label") or "?", dt.datetime.fromtimestamp(since).strftime("%H:%M"))
        for k in sorted(set(found) - set(self.problems)):
            self.jrnl.write("port", {"event": "problem", "problem": found[k]})
        for k in sorted(set(self.problems) - set(found)):
            self.jrnl.write("port", {"event": "problem over", "problem": self.problems[k]})
        self.problems = found

    def holders(self, ports, but=None):
        """Who holds these ports now (not `but`): {port: "exe (pid N)"}."""
        return {str(e["port"]): "%s (pid %d)" % (e["exe"], e["pid"]) for e in self.sorted_open()
                if e["port"] in (ports or ()) and e["pid"] != but}

    def listening_count(self):
        return sum(1 for e in self.table.values() if e["open"])

    def save(self):
        write_json(self.save_path, {
            "ts": now_iso(), "scans": self.scans, "error": self.error,
            "listening": [{"addr": addr_text(e["ip"], e["port"]), "ip": e["ip"], "port": e["port"], "pid": e["pid"],
                           "exe": e["exe"], "app": e["app"], "cmd": e["cmd"],
                           "seen_since": dt.datetime.fromtimestamp(e["since"]).isoformat(timespec="seconds")}
                          for e in self.sorted_open()],
            "problems": [self.problems[k] for k in sorted(self.problems)]})
