"""HW Blackbox's logic, without Windows' state: run with  python -m unittest discover -s tests  (from the project)."""
import datetime as dt
import json
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hwblackbox import config, paths  # noqa: E402


class TempData(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="hwb-test-")
        paths.init(self.dir)
        paths.P.make("logs", "state", "incidents", "sessions")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)


class Recorder:
    """A journal that keeps records in a list."""
    def __init__(self):
        self.recs = []

    def write(self, kind, payload=None, hard=True):
        self.recs.append(dict({"kind": kind}, **(payload or {})))

    def recent(self, seconds):
        return []


class ConfigTest(TempData):
    def write(self, text, bom=False):
        with open(paths.P.config, "wb") as f:
            f.write((b"\xef\xbb\xbf" if bom else b"") + text.encode("utf-8"))

    def test_defaults_without_a_file(self):
        cfg = config.load()
        self.assertEqual(cfg["dashboard"]["port"], 9070)
        self.assertNotIn("error", cfg)

    def test_byte_order_mark(self):
        self.write('{"dashboard": {"port": 9071}}', bom=True)
        cfg = config.load()
        self.assertEqual(cfg["dashboard"]["port"], 9071)
        self.assertNotIn("error", cfg)

    def test_unreadable_keeps_defaults(self):
        self.write("{not json")
        cfg = config.load()
        self.assertIn("error", cfg)
        self.assertEqual(cfg["dashboard"]["port"], 9070)

    def test_watch_rules_checked(self):
        self.write(json.dumps({"watch": [{"exe": "a.exe"}, {"label": "no exe"}, "junk",
                                         {"exe": "b.exe", "ports": [8080, "x", "9090"]}],
                               "sensors": {"interval_s": 0.01}, "disk_warn_gb": "lots"}))
        cfg = config.load()
        self.assertEqual([w["exe"] for w in cfg["watch"]], ["a.exe", "b.exe"])
        self.assertEqual(cfg["watch"][0]["label"], "a.exe")
        self.assertEqual(cfg["watch"][1]["ports"], [8080, 9090])
        self.assertEqual(cfg["sensors"]["interval_s"], 1.0)          # (clamped)
        self.assertIn("disk_warn_gb", cfg.get("error", ""))

    def test_disk_settings_are_live(self):
        self.assertEqual((config.defaults()["disk_warn_gb"], config.defaults()["disk_drop_gb"]), (10, 10))
        self.assertIn("disk_drop_gb", config.LIVE)
        self.write('{"disk_drop_gb": 5}')
        self.assertEqual(config.load()["disk_drop_gb"], 5)

    def test_public_hides_the_env_file(self):
        self.assertNotIn("env_file", config.public(config.load())["home_assistant"])


class PortsTest(unittest.TestCase):
    def setUp(self):
        from hwblackbox.ports import PortWatch
        self.j = Recorder()
        self.pw = PortWatch(self.j)
        import hwblackbox.ports as ports
        ports.describe_pid = lambda pid: ({1: "node.exe", 2: "python.exe", 3: "evil.exe"}.get(pid, "?"), None)
        self.cfg = {"ports": {"expected": {"8765": {"label": "Server", "exe": "node.exe", "always": True},
                                           "8788": {"label": "Cast", "exe": "pythonw.exe"}},
                              "ignore": [], "down_after_min": 0}}

    def scan(self, table):
        self.pw.scan(self.cfg, lambda pid, port, exe: None, current=table)

    def events(self):
        return [r for r in self.j.recs if r["kind"] == "port"]

    def test_open_close_needs_two_scans(self):
        self.scan({("127.0.0.1", 8765): 1})
        self.scan({("127.0.0.1", 8765): 1})
        self.assertTrue(self.pw.listed)
        self.scan({("127.0.0.1", 8765): 1, ("127.0.0.1", 5000): 2})
        self.assertEqual(self.events(), [])                          # (one scan: not yet)
        self.scan({("127.0.0.1", 8765): 1, ("127.0.0.1", 5000): 2})
        self.assertEqual([e["event"] for e in self.events()], ["open"])
        self.scan({("127.0.0.1", 8765): 1})
        self.scan({("127.0.0.1", 8765): 1})
        self.assertEqual([e["event"] for e in self.events()], ["open", "closed"])

    def test_problems(self):
        # python.exe counts as pythonw.exe; another program on 8788 and a second one on 8765 are problems
        t = {("127.0.0.1", 8765): 1, ("0.0.0.0", 8765): 3, ("127.0.0.1", 8788): 2}
        self.scan(t)
        self.scan(t)
        found = sorted(self.pw.problems)
        self.assertEqual(found, ["owner:8765", "shared:8765"])
        self.scan({("127.0.0.1", 8788): 2})
        self.scan({("127.0.0.1", 8788): 2})
        self.scan({("127.0.0.1", 8788): 2})
        self.assertIn("down:8765", self.pw.problems)                 # (down_after_min 0: at once)
        self.assertIn("problem over", [e["event"] for e in self.events()])

    def test_shared_only_where_addresses_overlap(self):
        t = {("100.64.0.7", 443): 1, ("127.0.0.2", 443): 2,             # two addresses of one family: no clash
             ("127.0.0.1", 8809): 1, ("::1", 8809): 2,                    # IPv4 and IPv6: no clash
             ("0.0.0.0", 8787): 2, ("127.0.0.1", 8787): 3,                # all addresses and one of them: a clash
             ("::", 9000): 1, ("::1", 9000): 3}
        self.scan(t)
        self.scan(t)
        self.assertEqual(sorted(k for k in self.pw.problems if k.startswith("shared")), ["shared:8787", "shared:9000"])

    def test_holders(self):
        self.scan({("127.0.0.1", 8765): 1})
        self.scan({("127.0.0.1", 8765): 1})
        self.assertEqual(self.pw.holders([8765], but=99), {"8765": "node.exe (pid 1)"})
        self.assertEqual(self.pw.holders([8765], but=1), {})


class EventsTest(unittest.TestCase):
    def test_event_app(self):
        from hwblackbox.events import event_app, wanted
        self.assertEqual(event_app({"source": "Application Error", "id": 1000, "inserts": ["claude.exe", "1.0"]}),
                         ("claude.exe", True))
        self.assertEqual(event_app({"source": "Application Hang", "id": 1002, "inserts": ["x.exe"]}), ("x.exe", False))
        wer = {"source": "Windows Error Reporting", "id": 1001,
               "inserts": ["b", "4", "APPCRASH", "Not available", "0", "game.exe", "1", "2", "ntdll.dll"]}
        self.assertEqual(event_app(wer), ("game.exe", True))
        self.assertTrue(wanted(wer))
        store = dict(wer, inserts=["b", "4", "StoreAgentScanForUpdatesFailure0", "", "", "x"])
        self.assertFalse(wanted(store))
        self.assertEqual(event_app({"source": "Winlogon", "id": 1002, "inserts": []}), ("explorer.exe", True))
        self.assertEqual(event_app({"source": "Service Control Manager", "id": 7031, "inserts": ["HW Blackbox"]}),
                         ("HW Blackbox", False))

    def test_describe_1074(self):
        from hwblackbox.events import describe_1074
        self.assertEqual(describe_1074("2026-10-08 19:01:22", r"C:\Windows\system32\winlogon.exe (MY-PC)",
                                       "restart", "No title"),
                         "2026-10-08 19:01:22: restart by winlogon.exe (No title)")


class ExitCodesTest(unittest.TestCase):
    def test_meaning(self):
        from hwblackbox.watcher import crashed, meaning
        self.assertTrue(crashed(0xC0000005))
        self.assertFalse(crashed(0xFFFFFFFF))            # (killed, not crashed)
        self.assertFalse(crashed(1))
        self.assertFalse(crashed(None))
        self.assertTrue(crashed(0x80000003))
        self.assertFalse(crashed(0xC000013A))            # (Ctrl+C or its console closing)
        self.assertIn("NTSTATUS 0xC0001234", meaning(0xC0001234))
        self.assertEqual(meaning(0), "clean exit")
        self.assertIn("couldn't be read", meaning(None))


class JournalTest(TempData):
    def test_write_and_read_tail(self):
        from hwblackbox.journal import Journal, read_tail
        j = Journal(paths.P.logs, "events", 30)
        j.write("a", {"x": 1})
        j.write("b", {"y": 2}, hard=False)
        j.close()
        recs = read_tail(j.path_for(dt.date.today()), 60)
        self.assertEqual([r["kind"] for r in recs], ["a", "b"])
        self.assertEqual(len(j.recent(60)), 2)

    def test_prune(self):
        from hwblackbox.util import prune
        old = os.path.join(paths.P.logs, "events_20000101.jsonl")
        new = os.path.join(paths.P.logs, "events_%s.jsonl" % dt.date.today().strftime("%Y%m%d"))
        for p in (old, new):
            open(p, "w").close()
        self.assertEqual(prune(paths.P.logs, "events_", ".jsonl", 30), 1)
        self.assertFalse(os.path.exists(old))
        self.assertTrue(os.path.exists(new))


class DashboardTest(TempData):
    def test_describe(self):
        from hwblackbox.dashboard.server import describe
        t = time.time()
        d = describe({"kind": "exit", "app": "Claude", "meaning": "crash: access violation", "ran": "1h"}, t)
        self.assertEqual(d["level"], "bad")
        d = describe({"kind": "startup", "pid": 1, "version": 5, "session_lock": True}, t)           # AppWatch's
        self.assertEqual(d["text"], "AppWatch started (v5)")
        d = describe({"kind": "startup", "version": "1.0.0", "data_dir": "x",
                      "previous_run": {"ended_cleanly": False}}, t)
        self.assertIn("ended without stopping", d["text"])
        self.assertEqual(d["level"], "warn")
        d = describe({"kind": "startup", "version": "1.0.0", "user": "alice"}, t, src="alice")
        self.assertEqual(d["text"], "The session agent (alice) started (1.0.0)")
        d = describe({"kind": "winevent", "source": "Microsoft-Windows-Kernel-Power", "id": 41, "at": "x"}, t)
        self.assertEqual((d["text"], d["level"], d["group"]), ("Power lost", "bad", "power"))
        d = describe({"kind": "shutdown", "phase": "services stopping"}, t)
        self.assertIn("shutting down", d["text"])
        d = describe({"kind": "exit", "app": "Windows Explorer", "code": "0x40010004", "while_session_ends": True,
                      "meaning": "ended by Windows (sign-out, or a debugger)", "ran": "1h"}, t)
        self.assertEqual(d["level"], "info")
        self.assertIn("session was ending", d["text"])

    def test_event_wording(self):
        from hwblackbox.dashboard.server import describe, human_ran
        # how long an app ran, the way a person says it (rounded to the smaller unit first: never "1 h 60 min")
        self.assertEqual([human_ran(x) for x in ("0h 00m 03s", "0h 01m 01s", "0h 05m 00s", "26h 12m 45s",
                                                  "1h 59m 50s", "47h 40m 00s", "?")],
                         ["3 s", "1 min 1 s", "5 min", "1 d 2 h", "2 h", "2 d", "?"])
        t = time.time()
        d = describe({"kind": "exit", "app": "Slate", "meaning": "clean exit", "code": "0x00000000",
                      "ran": "0h 01m 01s"}, t)
        self.assertEqual(d["text"], "Slate ended: clean exit (ran 1 min 1 s)")
        # a port whose program restarted, and one another program took over
        d = describe({"kind": "port", "event": "new owner", "addr": "127.0.0.1:8737", "exe": "tool.exe", "pid": 31,
                      "before": "tool.exe/29652"}, t)
        self.assertEqual(d["text"], "Port 127.0.0.1:8737: tool.exe restarted (pid 29652, now 31)")
        d = describe({"kind": "port", "event": "new owner", "addr": "0.0.0.0:80", "exe": "b.exe", "app": "Web",
                      "pid": 7, "before": "a.exe/5"}, t)
        self.assertEqual(d["text"], "Port 0.0.0.0:80: now b.exe (Web) (before: a.exe, pid 5)")
        d = describe({"kind": "port", "event": "open", "addr": "[::]:443", "exe": "srv.exe", "pid": 9}, t)
        self.assertEqual(d["text"], "Port [::]:443 open: srv.exe")
        # Windows Error Reporting's names, in words
        d = describe({"kind": "winevent", "source": "Windows Error Reporting", "id": 1001, "app": "app.exe",
                      "inserts": ["", "", "RADAR_PRE_LEAK_64"]}, t)
        self.assertEqual(d["text"], "Windows Error Reporting, app.exe: Windows' memory-leak check flagged it "
                                    "(RADAR_PRE_LEAK_64)")

    def test_bucketed(self):
        from hwblackbox.dashboard.server import bucketed
        nan = float("nan")
        out = bucketed([0, 5, 10, 100], {"a": [1.0, 3.0, nan, 7.0]}, 0, 100, 10)
        self.assertEqual(out["series"]["a"]["avg"][0], 2.0)
        self.assertIsNone(out["series"]["a"]["avg"][5])                 # (a gap)
        self.assertEqual(out["series"]["a"]["max"][-1], 7.0)

    def test_incident_names_only(self):
        from hwblackbox.dashboard.server import api_incident
        for bad in ("..\\config.json", "incident_20261013_220452_x.txt\\..\\..\\config.json", "x.txt", ""):
            with self.assertRaises(KeyError):
                api_incident({"name": bad})
        name = "incident_20261013_220452_explorer.exe.txt"
        with open(os.path.join(paths.P.incidents, name), "w") as f:
            f.write("Windows Explorer ended\n")
        self.assertIn("Explorer", api_incident({"name": name})["text"])

    def test_power_offs(self):
        from hwblackbox.dashboard.server import power_offs
        with open(os.path.join(paths.P.incidents, "incident_20261007_021512.txt"), "w") as f:
            f.write("HW Blackbox: power-off report\n\nBooted at:    2026-10-07 02:15:12, after a shutdown that wasn't clean\n"
                    "Went down:    2026-10-07 02:14:58.697  (...)\n\n"
                    "rails_20261007.csv: 2026-10-07T02:14:58.697,12.168,5.04,3.346,0.9,1.1,11.2,40.5,,,\n")
        po = power_offs()
        self.assertEqual(len(po), 1)
        self.assertEqual(po[0]["went_down"], "2026-10-07T02:14:58.697")
        self.assertAlmostEqual(po[0]["gap_s"], 13.3, places=1)
        self.assertEqual(po[0]["last_rails"]["v12_v"], 12.168)


class SensorsTest(unittest.TestCase):
    def test_pick_and_vcore(self):
        from hwblackbox.sensors import _pick, _temp, _vcore
        lhm = {("Cpu", "Voltage", "Core (SVI2 TFN)"): 1.55, ("SuperIO", "Voltage", "Vcore"): 1.2,
               ("SuperIO", "Voltage", "+5V"): 5.04, ("SuperIO", "Voltage", "5VSB"): 5.1}
        self.assertEqual(_vcore(lhm), 1.2)                              # (the board's, not the CPU's flat 1.55)
        self.assertEqual(_pick(lhm, "SuperIO", "Voltage", ("+5",), ("5vsb",)), 5.04)
        self.assertEqual(_temp(0), "")
        self.assertEqual(_temp(150), "")
        self.assertEqual(_temp(45.06), 45.1)

    def test_flat_cpu_voltage_noted(self):
        from hwblackbox.sensors import FLAT_AFTER, SensorStats
        st = SensorStats("now")
        for _ in range(FLAT_AFTER):
            st.entry("Cpu/Voltage/Core (SVI2 TFN)", "CPU", "x", "Voltage", "Core (SVI2 TFN)", "V", 1.55, 3)
            st.entry("SuperIO/Voltage/+3V Standby", "Motherboard", "x", "Voltage", "+3V Standby", "V", 3.312, 3)
        self.assertIsNotNone(st.note("Cpu/Voltage/Core (SVI2 TFN)", "Cpu", "Voltage"))
        self.assertIsNone(st.note("SuperIO/Voltage/+3V Standby", "SuperIO", "Voltage"))   # (a flat rail can be real)

    def test_gpu_from_lhm(self):
        from hwblackbox.sensors import gpu_from_lhm
        lhm = {("GpuIntel", "Load", "D3D 3D"): 3.0, ("GpuIntel", "Temperature", "GPU Core"): 40.0,
               ("GpuAmd", "Temperature", "GPU Core"): 61.24, ("GpuAmd", "Temperature", "GPU Hot Spot"): 75.0,
               ("GpuAmd", "Power", "GPU Package"): 182.36, ("GpuAmd", "Load", "GPU Core"): 97.0,
               ("GpuAmd", "Clock", "GPU Core"): 2412.4, ("GpuAmd", "SmallData", "GPU Memory Used"): 6120.6,
               ("GpuAmd#2", "Temperature", "GPU Core"): 30.0, ("Cpu", "Temperature", "Core (Tctl/Tdie)"): 55.0}
        self.assertEqual(gpu_from_lhm(lhm), {"gpu_temp_c": 61.2, "gpu_power_w": 182.4, "gpu_util_pct": 97.0,
                                             "gpu_clock_mhz": 2412, "gpu_vram_mb": 6121})     # (the discrete one)
        self.assertEqual(gpu_from_lhm({("Cpu", "Load", "CPU Total"): 5.0}), {})
        self.assertEqual(gpu_from_lhm({("GpuIntel", "Load", "D3D 3D"): 3.0}), {"gpu_util_pct": 3.0})

    def test_gpu_sensors_grouped(self):
        from hwblackbox.sensors import SensorStats

        class Fake:
            admin = False                               # (unelevated: GPU readings still count, the CPU's don't)
            lhm = type("L", (), {"names": {"GpuAmd": "AMD Radeon RX 7800 XT", "GpuAmd#2": "AMD Radeon(TM)"}})()
            nvml = type("N", (), {"name": None})()
            last_nv = {}
            ram_total_gb = None
        lhm = {("GpuAmd", "Temperature", "GPU Core"): 61.0, ("GpuAmd#2", "Temperature", "GPU Core"): 30.0,
               ("Cpu", "Temperature", "Core (Tctl/Tdie)"): 55.0}
        out = SensorStats("now").build(Fake(), lhm, {"timestamp": "x"})["sensors"]
        self.assertEqual([(x["group"], x["device"]) for x in out],
                         [("GPU", "AMD Radeon RX 7800 XT"), ("GPU", "AMD Radeon(TM)")])


class SensorsAgeTest(unittest.TestCase):
    def test_last_sample_age_from_a_steady_clock(self):
        from hwblackbox.sensors import Sensors
        s = Sensors({"sensors": {"interval_s": 5, "rails_interval_s": 0.25, "keep_days": 1, "rails_keep_days": 1}},
                    Recorder(), "now")
        self.assertIsNone(s.status()["last_sample_age_s"])
        # a row stamped in the hour that repeats when daylight saving ends, written 4 s ago: 4 s old, not an hour
        s.latest, s.written = {"timestamp": "2026-11-01T01:00:05"}, time.monotonic() - 4
        self.assertAlmostEqual(s.status()["last_sample_age_s"], 4, delta=1)


class PowerOffTest(TempData):
    def test_rows_before_skips_damage(self):
        from hwblackbox.poweroff import _event_date, _rows_before
        p = os.path.join(paths.P.logs, "flight_20261007.csv")
        with open(p, "wb") as f:
            f.write(b"timestamp,a\n2026-10-07T02:14:50,1\n2026-10-07T02:14:55,2\n\x00\x00\x00\n"
                    b"garbage line\n2026-10-07T02:16:00,3\n")
        rows = _rows_before(p, dt.datetime(2026, 10, 7, 2, 15, 12), 5)
        self.assertEqual([r[1].split(": ")[1] for r in rows], ["2026-10-07T02:14:50,1", "2026-10-07T02:14:55,2"])
        self.assertEqual(_event_date("Event[0]:\n  Date: 2026-10-07T02:15:15.5000000Z\n"),
                         dt.datetime(2026, 10, 7, 2, 15, 15, 500000))


class AgentsTest(TempData):
    def test_a_failed_read_is_not_a_missing_heartbeat(self):
        from unittest import mock
        from hwblackbox import agents
        folder = paths.P.session_dir("u")
        os.makedirs(folder)
        hb = os.path.join(folder, "agent.json")
        with open(hb, "w", encoding="utf-8") as f:
            json.dump({"ts": "2026-10-16T20:10:00", "session": 1, "pid": 42, "version": "x"}, f)
        a = agents.Agents(Recorder())
        calls = []
        a.maybe_restart = lambda sid, user, state, age, now: calls.append(state)
        with mock.patch.object(agents.winapi, "sessions", return_value=[{"id": 1, "user": "u", "state": "active"}]):
            a.refresh()
            self.assertEqual((a.view[0]["agent"], a.view[0]["pid"], calls), ("running", 42, []))
            with mock.patch.object(agents, "read_json", return_value=None):     # (the file mid-swap)
                a.refresh()
            self.assertEqual((a.view[0]["agent"], a.view[0]["pid"], calls), ("running", 42, []))
            os.utime(hb, (time.time() - 200, time.time() - 200))              # really stuck: no new heartbeat
            a.refresh()
            self.assertEqual((a.view[0]["agent"], calls), ("stale", ["stale"]))

    def test_never_heard_from(self):
        from unittest import mock
        from hwblackbox import agents
        a = agents.Agents(Recorder())
        calls = []
        a.maybe_restart = lambda sid, user, state, age, now: calls.append(state)
        with mock.patch.object(agents.winapi, "sessions", return_value=[{"id": 1, "user": "u", "state": "active"}]):
            a.refresh()
        self.assertEqual((a.view[0]["agent"], calls), ("none", ["none"]))


class DisksTest(TempData):
    """Free space: the log, the Windows drive's problems, and the dashboard's chart of it."""

    def test_problems(self):
        from hwblackbox import disks
        w = disks.DiskWatch(Recorder(), 183)
        sysd, now = disks.system_drive(), time.time()
        cfg = {"disk_warn_gb": 10, "disk_drop_gb": 10}
        def look(free, history, at=now):
            w.now = {sysd: (free, 465.0)}
            w.history.clear()
            w.history.extend(history)
            return w.problems(cfg, at)

        fast = "%s is filling up fast: 14.2 GB gone in 50 min; at that rate it's under 10 GB free in about 1 h 16 min"
        self.assertEqual(look(31.8, [(now - 3000, 46.0), (now - 1800, 40.0), (now, 31.8)]), [fast % sysd])
        # held on for a quarter of an hour after it was last true, so a swing doesn't make it flicker; then off
        self.assertEqual(look(33.0, [(now - 3000, 38.0), (now + 600, 33.0)], now + 600), [fast % sysd])
        self.assertEqual(look(33.0, [(now - 3000, 38.0), (now + 1000, 33.0)], now + 1000), [])
        # 15 GB in 50 min with 85 GB left: under 10 GB only in four hours, so not urgent (2026-10-23's swings)
        self.assertEqual(look(85.0, [(now - 3000, 100.0), (now, 85.0)]), [])
        self.assertEqual(look(31.8, [(now - 3000, 38.0), (now, 31.8)]), [])            # 6.2 GB: not fast
        self.assertEqual(look(8.5, [(now - 3000, 30.0), (now, 8.5)]), ["%s has only 8.5 GB free" % sysd])
        self.assertEqual(w.problems(dict(cfg, disk_drop_gb=0), now), ["%s has only 8.5 GB free" % sysd])

    def test_log_and_seed(self):
        from hwblackbox import disks
        w = disks.DiskWatch(Recorder(), 183)
        w.sample()
        sysd = disks.system_drive()
        self.assertIn(sysd, w.now)
        rows = disks.read_rows(disks.path_for(dt.date.today()))
        self.assertTrue(any(r[1] == sysd for r in rows))
        self.assertEqual(len(disks.DiskWatch(Recorder(), 183).history), 1)     # a restart remembers the last hour

    def test_chart(self):
        from hwblackbox.dashboard import server
        now = time.time()
        with open(os.path.join(paths.P.logs, "disks_%s.csv" % dt.date.today().strftime("%Y%m%d")), "w") as f:
            f.write("timestamp,drive,free_gb,total_gb\n")
            for k in range(30, 0, -1):                      # a reading a minute over the last half hour
                t = dt.datetime.fromtimestamp(now - k * 60).isoformat(timespec="seconds")
                f.write("%s,C:,%.1f,465.0\n%s,G:,800.0,1863.0\n" % (t, 40 - k / 10, t))
        server._cache.clear()
        server._disk_files.clear()
        ids = [c["id"] for c in server.api_flight_columns({})["cols"]]
        self.assertEqual(ids[-2:], ["disk:C:", "disk:G:"])
        h = server.api_history({"cols": "disk:C:", "hours": "1", "points": "720"})          # 5 s buckets
        avg = h["series"]["disk:C:"]["avg"]
        self.assertEqual(h["cols"]["disk:C:"]["unit"], "GB free")
        seen = [i for i, v in enumerate(avg) if v is not None]
        self.assertEqual(sum(1 for i in range(seen[0], seen[-1]) if avg[i] is None), 0)  # held, not dots
        self.assertLess(seen[0], len(avg) // 2 + 5)                                   # from half an hour ago
        self.assertEqual(h["rows"], 30)


class WatcherTest(TempData):
    """An app Windows ends as its session ends is recorded, not an incident (2026-10-16: a restart wrote two)."""
    SIGN_OUT = 0x40010004

    def ended(self, code, agent_recs=(), signed_out=False, session=1):
        from hwblackbox import watcher

        class FakeAgents:
            def taskbar_pids(self):
                return set()

            def recent_records(self, seconds):
                return list(agent_recs)

            def screens(self):
                return {}

            def front(self, seconds):
                return {}

        jr = Recorder()
        w = watcher.Watcher(jr, {"watch": []}, None, FakeAgents())
        if signed_out:
            w.signed_out[1] = time.time()
        t = watcher.Tracked()
        t.pid, t.exe, t.label, t.started, t.main, t.handle, t.mem = 4242, "explorer.exe", "Explorer", time.time(), True, \
            None, None
        t.by_port, t.policy, t.ports, t.session = False, "nonzero", None, session
        w.ended(t, code)
        exit_rec = next(r for r in jr.recs if r["kind"] == "exit")
        return w.notes["last_incident"] is not None, bool(exit_rec.get("while_session_ends"))

    def test_session_ending(self):
        asked = {"kind": "shutdown", "phase": "asked", "session": 1}
        self.assertEqual(self.ended(self.SIGN_OUT), (True, False))                       # a debugger, say
        self.assertEqual(self.ended(self.SIGN_OUT, [asked]), (False, True))              # Windows asked the agent
        self.assertEqual(self.ended(self.SIGN_OUT, signed_out=True), (False, True))      # the service saw the sign-out
        self.assertEqual(self.ended(self.SIGN_OUT, [asked, {"kind": "shutdown", "phase": "cancelled", "session": 1}]),
                         (True, False))                                                  # ... and it was cancelled
        self.assertEqual(self.ended(self.SIGN_OUT, [asked], session=2), (True, False))   # another session
        self.assertEqual(self.ended(0xC0000005, [asked]), (True, False))                 # a crash still counts
        self.assertEqual(self.ended(0xC000013A, [asked]), (False, True))                 # a console closing with it


if __name__ == "__main__":
    unittest.main()
