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

    def test_page_carries_its_version(self):
        # an open page compares its own version with the API's, to offer a reload after an update
        from hwblackbox import VERSION
        from hwblackbox.dashboard import server
        body = server.page().decode("utf-8")
        self.assertIn('<meta name="hwb-version" content="%s">' % VERSION, body)
        self.assertNotIn("__HWB_VERSION__", body)
        self.assertEqual(server.api_overview({})["version"], VERSION)

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
        from hwblackbox.poweroff import _rows_before
        p = os.path.join(paths.P.logs, "flight_20261007.csv")
        with open(p, "wb") as f:
            f.write(b"timestamp,a\n2026-10-07T02:14:50,1\n2026-10-07T02:14:55,2\n\x00\x00\x00\n"
                    b"garbage line\n2026-10-07T02:16:00,3\n")
        rows = _rows_before(p, dt.datetime(2026, 10, 7, 2, 15, 12), 5)
        self.assertEqual([r[1].split(": ")[1] for r in rows], ["2026-10-07T02:14:50,1", "2026-10-07T02:14:55,2"])

    def test_check_reads_the_times_through_the_event_api(self):
        # (wevtutil's text names its fields in Windows' display language: the check doesn't read it, the report does)
        from unittest import mock
        from hwblackbox import events, poweroff
        boot = dt.datetime(2026, 10, 23, 22, 24, 31)
        times = {poweroff.Q41: "2026-10-23 22:24:35", poweroff.Q6008: "2026-10-23 22:24:40"}
        with mock.patch.object(events, "newest_event", lambda log, q: (times[q], {})), \
                mock.patch.object(poweroff, "_wevtutil", lambda q, n: "Ereignis[0]:\n  Datum: ...\n"):
            found = poweroff.check(boot=boot, now=boot + dt.timedelta(minutes=1))
            self.assertIn("incident_20261023_222431.txt", found)
            self.assertTrue(os.path.exists(os.path.join(paths.P.incidents, "incident_20261023_222431.txt")))
            # a clean boot later: the newest 41 / 6008 are the old ones
            later = boot + dt.timedelta(hours=3)
            self.assertEqual(poweroff.check(boot=later, now=later + dt.timedelta(minutes=1)), "")


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


def free_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class HardeningTest(TempData):
    """The 2026-11-05 review's findings: what another account on the PC, a web page or a typo could do."""

    def test_com_cache_must_be_the_programs_own(self):
        from unittest import mock
        from hwblackbox import agents
        prog = r"C:\Program Files\HWBlackbox\python"
        self.assertTrue(agents.inside(prog + r"\Lib\site-packages\win32com\gen_py", prog))
        self.assertFalse(agents.inside(r"C:\Windows\TEMP\gen_py\3.12", prog))
        self.assertFalse(agents.inside(r"D:\HWBlackbox\python", prog))
        self.assertFalse(agents.inside(r"C:\Program Files\HWBlackbox\python2", prog))
        # outside it, the service doesn't touch COM at all (importing win32com.client unpickles the cache)
        with mock.patch.object(agents, "com_cache_ok", return_value=False):
            self.assertEqual(agents.get_task(), ("unsafe", None))

    def test_a_typo_in_the_settings_never_stops_the_service(self):
        with open(paths.P.config, "w", encoding="utf-8") as f:
            json.dump({"sensors": {"interval_s": "fast", "keep_days": "30", "rails_keep_days": -1, "lhm_gpu": True},
                       "events": {"keep_days": None}, "dashboard": {"port": 99999, "enabled": "yes",
                                                                    "milestones": [{"at": "2026-10-08", "text": "x"}, 5]},
                       "ports": {"expected": {"80": "web", "443": {"label": "Web"}}, "ignore": "all"},
                       "watch": [{"exe": "a.exe", "ports": 8080, "match": 5}], "disk_warn_gb": -3}, f)
        cfg = config.load()
        self.assertEqual((cfg["sensors"]["interval_s"], cfg["sensors"]["keep_days"], cfg["sensors"]["rails_keep_days"]),
                         (5.0, 183, 7))
        self.assertIs(cfg["sensors"]["lhm_gpu"], True)                   # (it may be "auto", true or false)
        self.assertEqual((cfg["events"]["keep_days"], cfg["dashboard"]["port"], cfg["dashboard"]["enabled"]),
                         (183, 9070, True))
        self.assertEqual(cfg["dashboard"]["milestones"], [{"at": "2026-10-08", "text": "x"}])
        self.assertEqual((cfg["ports"]["expected"], cfg["ports"]["ignore"]), ({"443": {"label": "Web"}}, []))
        self.assertEqual(cfg["watch"], [{"exe": "a.exe", "ports": [], "label": "a.exe"}])
        self.assertEqual(cfg["disk_warn_gb"], 10)
        for name in ("sensors.interval_s", "dashboard.port", "ports.ignore", "disk_warn_gb", "ports.expected"):
            self.assertIn(name, cfg["error"])

    def test_secrets_in_command_lines_are_hidden(self):
        from hwblackbox.ports import redact
        cases = {
            "--port 8080 --password hunter2 --verbose": "--port 8080 --password *** --verbose",
            "-api-key=abc123 serve": "-api-key=*** serve",
            "/token:xyz run": "/token:*** run",
            'db --auth-token "a b c" x': 'db --auth-token *** x',
            "connect https://bob:s3cret@db.local:5432/x": "connect https://bob:***@db.local:5432/x",
            "PASSWORD=pw1 node app.js": "PASSWORD=*** node app.js",
            "-m hwblackbox agent": "-m hwblackbox agent",
            "server.js --port 8765 --data G:\\Beam\\data": "server.js --port 8765 --data G:\\Beam\\data",
        }
        for cmd, want in cases.items():
            self.assertEqual(redact(cmd), want, cmd)

    def test_history_reads_each_column_once(self):
        from unittest import mock
        from hwblackbox.dashboard import server
        seen = []
        with mock.patch.object(server.FLIGHT_CACHE, "rows_between",
                               side_effect=lambda s, e, cols: seen.append(list(cols)) or ([], {})):
            server.api_history({"cols": ",".join(["cpu_temp_c"] * 5000 + ["v12_v"]), "hours": "1"})
        self.assertEqual(seen, [["cpu_temp_c", "v12_v"]])

    def test_events_survive_bad_and_forged_session_records(self):
        from hwblackbox.dashboard import server
        now = dt.datetime.now().replace(microsecond=0)
        day = now.strftime("%Y%m%d")

        def line(**r):
            return json.dumps(dict({"ts": now.isoformat()}, **r)) + "\n"
        with open(os.path.join(paths.P.logs, "events_%s.jsonl" % day), "w", encoding="utf-8") as f:
            f.write(line(kind="startup", version="1.0.6", data_dir="x"))
        folder = os.path.join(paths.P.sessions, "service")         # (a user named "service", or posing as it)
        os.makedirs(folder)
        with open(os.path.join(folder, "session_%s.jsonl" % day), "w", encoding="utf-8") as f:
            f.write("[]\n")                                                       # not a record
            f.write(line(kind="winevent", source="Microsoft-Windows-Kernel-Power", id=41, at=now.isoformat()))
            f.write(line(kind="display", before=5, after=6))                      # wrong types
            f.write(json.dumps({"ts": "2099-01-01T00:00:00", "kind": "startup", "version": "x"}) + "\n")
            f.write(line(kind="startup", version="1.0.6", data_dir="x"))
        texts = [e["text"] for e in server.api_events({})["events"]]
        self.assertEqual(texts, ["HW Blackbox's service started (1.0.6)", "The session agent (service) started (1.0.6)"])

    def test_app_reports_are_capped_and_pruned(self):
        from hwblackbox import watcher

        class FakeAgents:
            def screens(self):
                return {}

            def recent_records(self, seconds):
                return []

            def front(self, seconds):
                return {}
        jr = Recorder()
        w = watcher.Watcher(jr, {"watch": [], "events": {"keep_days": 30}}, None, FakeAgents())
        for i in range(watcher.REPORTS_PER_HOUR + 5):
            w.incident("app%d.exe" % i, "app%d crashed" % i, {})
        reports = [f for f in os.listdir(paths.P.incidents) if f.endswith(".txt")]
        self.assertEqual(len(reports), watcher.REPORTS_PER_HOUR)
        self.assertEqual(len([r for r in jr.recs if r["kind"] == "error"]), 1)
        # old app reports go; power-off reports stay
        for name in ("incident_20200101_120000_old.exe.txt", "incident_20200101_120000.txt"):
            open(os.path.join(paths.P.incidents, name), "w").close()
        self.assertEqual(w.prune_reports(), 1)
        self.assertTrue(os.path.exists(os.path.join(paths.P.incidents, "incident_20200101_120000.txt")))
        self.assertEqual(len(os.listdir(paths.P.incidents)), watcher.REPORTS_PER_HOUR + 1)

    def test_no_network_paths_from_other_programs(self):
        from unittest import mock
        from hwblackbox import watcher
        proc = mock.Mock()
        proc.exe.return_value = r"\\host\share\venv\Scripts\pythonw.exe"
        with mock.patch.object(watcher.psutil, "Process", return_value=proc), \
                mock.patch.object(watcher.os.path, "isfile", side_effect=AssertionError("looked on the share")):
            self.assertFalse(watcher.is_venv_launcher(1234))

    def test_links_are_not_followed(self):
        import _winapi
        from hwblackbox.dashboard import server
        from hwblackbox.util import is_link
        target = os.path.join(self.dir, "elsewhere")
        os.makedirs(target)
        os.makedirs(os.path.join(paths.P.sessions, "alice"))
        _winapi.CreateJunction(target, os.path.join(paths.P.sessions, "bob"))
        self.assertTrue(is_link(os.path.join(paths.P.sessions, "bob")))
        self.assertFalse(is_link(os.path.join(paths.P.sessions, "alice")))
        self.assertEqual([n for n, _ in server.session_dirs()], ["alice"])

    def test_the_data_only_for_the_page_itself(self):
        import urllib.error
        import urllib.request
        from hwblackbox.dashboard import server
        port = free_port()
        httpd = server.start(port)
        try:
            def get(path, site=None):
                req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path),
                                             headers={"Sec-Fetch-Site": site} if site else {})
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                try:
                    with opener.open(req, timeout=5) as r:
                        return r.status
                except urllib.error.HTTPError as e:
                    return e.code
            self.assertEqual(get("/api/ping", "cross-site"), 403)
            self.assertEqual(get("/api/ping", "same-site"), 403)                 # (another local port's page)
            self.assertEqual(get("/api/ping", "same-origin"), 200)
            self.assertEqual(get("/api/ping"), 200)                              # (a program: the installer's check)
            self.assertEqual(get("/", "cross-site"), 200)                        # (a link to the page from elsewhere)
            self.assertEqual(server.who_serves(port)[:11], "HW Blackbox")
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_a_slow_port_holder_cant_hold_the_agent(self):
        import socket
        import threading
        from hwblackbox.dashboard import server
        lst = socket.socket()
        lst.bind(("127.0.0.1", 0))
        lst.listen(1)
        port, stop = lst.getsockname()[1], threading.Event()

        def trickle():                  # answers, then a byte a second for ever
            conn, _ = lst.accept()
            conn.recv(4096)
            conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 100000\r\n\r\n")
            while not stop.is_set():
                try:
                    conn.sendall(b" ")
                except OSError:
                    break
                time.sleep(1)
            conn.close()
        threading.Thread(target=trickle, daemon=True).start()
        t0 = time.monotonic()
        try:
            self.assertIsNone(server.who_serves(port, wait=2))
            self.assertLess(time.monotonic() - t0, 3)
        finally:
            stop.set()
            lst.close()

    def test_home_assistant_redirects_are_not_followed(self):
        import http.server
        import threading
        from hwblackbox.homeassistant import HaReporter
        got = []

        class Elsewhere(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                got.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()
            do_POST = do_GET

            def log_message(self, *a):
                pass
        other = http.server.HTTPServer(("127.0.0.1", 0), Elsewhere)

        class Moved(Elsewhere):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:%d/steal" % other.server_port)
                self.end_headers()
        ha = http.server.HTTPServer(("127.0.0.1", 0), Moved)
        for s in (other, ha):
            threading.Thread(target=s.serve_forever, daemon=True).start()
        env = os.path.join(self.dir, "ha.env")
        with open(env, "w", encoding="utf-8") as f:
            f.write("HA_URL=http://127.0.0.1:%d\nHA_TOKEN=secret-token\n" % ha.server_port)
        try:
            r = HaReporter._post({"env_file": env, "entity": "sensor.x"}, {"state": "ok"})
            self.assertFalse(r["ok"])
            self.assertTrue(r["error"].startswith("HTTP 302"))
            self.assertEqual(got, [])
        finally:
            for s in (other, ha):
                s.shutdown()
                s.server_close()


class FakeHw:
    """A LibreHardwareMonitor device: its type, name, sensors, and an Update() that can be made to hang."""
    def __init__(self, kind, sensors, gate=None):
        self.HardwareType, self.Name, self.SubHardware, self.gate = kind, kind + " chip", [], gate
        self.Sensors = [type("S", (), {"SensorType": t, "Name": n, "Value": v})() for t, n, v in sensors]

    def Update(self):
        if self.gate is not None:
            self.gate.wait(10)


class RailsLaneTest(TempData):
    """2026-11-05: a core kept busy all night by another program held up every CPU read, and the rails, read on the same
    thread, slowed to 2 a second. The CPU now has a lane (and a lock) of its own."""

    def backend(self, gate=None):
        import threading
        from hwblackbox.sensors import LhmBackend
        b = LhmBackend.__new__(LhmBackend)
        b.error, b.gpu, b.names = None, False, {}
        b.lock, b.cpu_lock = threading.Lock(), threading.Lock()
        b.computer = type("C", (), {"Hardware": [
            FakeHw("Cpu", [("Temperature", "Core (Tctl/Tdie)", 52.0), ("Power", "Package", 14.2)], gate),
            FakeHw("SuperIO", [("Voltage", "+12V", 12.168), ("Voltage", "+5V", 5.04), ("Voltage", "Vcore", 1.2)])]})()
        return b

    def test_a_held_up_cpu_read_doesnt_hold_up_the_rails(self):
        import threading
        gate = threading.Event()
        b = self.backend(gate)
        t = threading.Thread(target=b.read_cpu, daemon=True)
        t.start()                                    # (the CPU read now waits on its "busy core", holding its lock)
        time.sleep(0.1)
        t0 = time.monotonic()
        fast = b.read_fast()
        self.assertLess(time.monotonic() - t0, 1)
        self.assertEqual(fast[("SuperIO", "Voltage", "+12V")], 12.168)
        self.assertNotIn(("Cpu", "Temperature", "Core (Tctl/Tdie)"), fast)
        gate.set()
        t.join(5)

    def test_rows_take_the_cpu_lanes_newest_reading(self):
        from hwblackbox import sensors
        s = sensors.Sampler.__new__(sensors.Sampler)
        s.lhm, s.admin, s.cpu_mark, s.ram_total_gb, s.lhm_gpu, s.last_nv = self.backend(), True, None, None, False, {}
        s.nvml = type("N", (), {"read": lambda self: {}})()
        import psutil
        s.psutil = psutil
        s.cpu_lane, s.cpu_last = False, None
        s.read_cpu()                                                # (the lane's read)
        s.cpu_lane = True
        calls = []
        real = s.lhm.read_cpu
        s.lhm.read_cpu = lambda: calls.append(1) or real()
        row = s.sample_fast()
        self.assertEqual((row["v12_v"], row["cpu_temp_c"], row["cpu_power_w"]), (12.168, 52.0, 14.2))
        self.assertEqual(calls, [])                                 # the rails lane never reads the CPU itself
        s.cpu_last = (time.monotonic() - 5, s.cpu_last[1])          # the CPU lane held up for 5 s
        row = s.sample_fast()
        self.assertEqual((row["v12_v"], row["cpu_temp_c"], row["cpu_power_w"]), (12.168, "", ""))
        row, _ = s.sample()                                         # (the 5-second row still takes a 5 s old one)
        self.assertEqual((row["v12_v"], row["cpu_temp_c"]), (12.168, 52.0))
        self.assertEqual(calls, [])
        s.cpu_last = (time.monotonic() - 60, s.cpu_last[1])
        row, _ = s.sample()
        self.assertEqual(row["cpu_temp_c"], "")

    def status(self, fast_hz, cpu_age=0.5, cpu_temp_ok=True):
        from hwblackbox import status

        class Sens:
            def status(self):
                return {"last_sample_age_s": 2, "admin": True, "rails_ok": True, "cpu_temp_ok": cpu_temp_ok,
                        "fast_hz": fast_hz, "cpu_age_s": cpu_age}

            def rails_on(self):
                return True

        none = lambda *a: None                                                     # noqa: E731
        svc = type("Svc", (), {})()
        svc.cfg, svc.sensors, svc.want_sensors, svc.started, svc.test = config.defaults(), Sens(), True, 0, False
        svc.watcher = type("W", (), {"events": None, "notes": {}, "logs_mb": 1})()
        svc.agents = type("A", (), {"view": []})()
        svc.agent_down = {}
        svc.ports = type("P", (), {"listed": False, "error": None})()
        svc.disks = type("D", (), {"free_gb": none, "problems": lambda self, cfg: []})()
        svc.thread_ages, svc.STUCK = lambda: {}, {}
        return status.build(svc)

    def test_a_slow_rails_lane_is_a_note_not_a_problem(self):
        state, problems, attrs = self.status(2.0)
        self.assertEqual((state, problems), ("ok", []))
        self.assertEqual(attrs["rails_note"], "read 2.0 times a second instead of 4: still read, only less often")
        self.assertNotIn("rails_note", self.status(4.0)[2])
        from hwblackbox import status
        self.assertNotIn("rails_note", status.HA_KEYS)              # (the page shows it; Home Assistant doesn't get it)

    def test_a_held_up_cpu_lane_says_so(self):
        _s, problems, _a = self.status(4.0, cpu_age=42, cpu_temp_ok=False)
        self.assertTrue(problems[0].startswith("No CPU readings for 42 s"))
        _s, problems, _a = self.status(4.0, cpu_age=0.5, cpu_temp_ok=False)
        self.assertEqual(problems, ["No CPU temperature (the sensor driver, PawnIO, may be gone)"])


MB = 2 ** 20


class ProgramLogTest(TempData):
    """Each program's CPU, memory and GPU use, minute by minute: Windows keeps no such history."""

    def snap(self, procs):
        from hwblackbox.winapi import Proc
        return {pid: Proc(name, 1, 1, created, int(cpu_s * 1e7), int(mem_mb * MB))
                for pid, (name, created, cpu_s, mem_mb) in procs.items()}

    def test_a_minute_by_program(self):
        from unittest import mock
        from hwblackbox import programs
        log = programs.ProgramLog(183)
        t0 = time.time()
        old = t0 - 3600
        eng = "luid_0x00000000_0x000124D4_phys_0_eng_0"
        with mock.patch.object(programs, "interrupt_seconds", side_effect=[100.0, 100.9]):
            log.look(self.snap({1752: ("dwm.exe", old, 500.0, 300), 10: ("chrome.exe", old, 30.0, 400),
                                11: ("chrome.exe", old, 20.0, 300), 77: ("python.exe", old, 9.0, 50),
                                88: ("idle.exe", old, 1.0, 20), 99: ("big.exe", old, 0.0, 900)}), now=0, wall=t0)
            log.look(self.snap({1752: ("dwm.exe", old, 559.0, 310),                 # a core flat out
                                10: ("chrome.exe", old, 33.0, 500), 11: ("chrome.exe", old, 21.5, 300),
                                77: ("python.exe", t0 + 30, 2.0, 40),               # pid 77 again: a new process
                                90: ("build.exe", t0 + 40, 4.0, 60),                # started since the last look
                                91: ("old.exe", old, 50.0, 10),                     # (missing from the last look)
                                88: ("idle.exe", old, 1.1, 20), 99: ("big.exe", old, 0.0, 700)}),
                     now=60, wall=t0 + 60)
            # Windows' GPU counters: dwm 1.3 GB and 12 % of the 3D engine, chrome 4 % + 3 % on the same engine
            log.gpu.latest = (time.monotonic(), {1752: 1300 * MB, 10: 200 * MB, 4242: 50 * MB},
                              {1752: {eng: 12.0}, 10: {eng: 4.0}, 11: {eng: 3.0}})
            rows = log.minute()
        got = {r[0]: (round(r[1], 2), r[2], r[3], r[4], r[5], r[6]) for r in rows}
        self.assertEqual(got["dwm.exe"], (59.0, 310.0, 1300.0, 12.0, 1, 1752))
        self.assertEqual(got["chrome.exe"], (4.5, 800.0, 200.0, 7.0, 2, 10))        # (its processes summed)
        self.assertEqual(got["big.exe"][:2], (0.0, 900.0))                         # memory alone: the most it held
        self.assertEqual(got["build.exe"][0], 4.0)
        self.assertEqual(got["python.exe"][0], 2.0)
        self.assertNotIn("idle.exe", got)                                        # small in everything
        self.assertNotIn("old.exe", got)
        self.assertEqual(got[programs.INTERRUPTS][0], 0.9)
        self.assertEqual(got[programs.ALL][0], round(59 + 4.5 + 4 + 2 + 0.1 + 0.9, 2))
        self.assertEqual(got[programs.ALL][2:4], (1550.0, 19.0))                  # all VRAM; the engine's total
        on_disk = programs.read_rows(programs.path_for(dt.date.today()))
        self.assertEqual(on_disk[0][2:7], ("dwm.exe", 59.0, 310.0, 1300.0, 12.0))
        self.assertTrue(log.busiest()[0].startswith("dwm.exe: 98 % of one core (1 process, the busiest pid 1752)"))

    def test_without_the_gpu_counters(self):
        from hwblackbox import programs
        log = programs.ProgramLog(183)
        log.look(self.snap({5: ("a.exe", time.time() - 99, 1.0, 300)}), now=0)
        log.look(self.snap({5: ("a.exe", time.time() - 99, 31.0, 300)}), now=60)
        rows = log.minute()
        self.assertEqual(rows[0][:5], ("a.exe", 30.0, 300.0, None, None))       # (blank, not 0)

    def test_the_counters_names(self):
        from hwblackbox.programs import gpu_by_pid
        vram, eng = gpu_by_pid({"pid_1752_luid_0x00000000_0x000124D4_phys_0": 100,
                                "pid_1752_luid_0x00000000_0x0000AAAA_phys_0": 20, "junk": 5},
                               {"pid_1752_luid_0x00000000_0x000124D4_phys_0_eng_0_engtype_3D": 10.5,
                                "pid_1752_luid_0x00000000_0x000124D4_phys_0_eng_3_engtype_VideoDecode": 0.0,
                                "pid_9_luid_0x00000000_0x000124D4_phys_0_eng_0_engtype_3D": 2.0})
        self.assertEqual(vram, {1752: 120})
        self.assertEqual(eng, {1752: {"luid_0x00000000_0x000124D4_phys_0_eng_0": 10.5},
                               9: {"luid_0x00000000_0x000124D4_phys_0_eng_0": 2.0}})

    def write_minutes(self, prefix, rows, now):
        """rows(k, t) -> CSV lines for the minute k minutes ago."""
        from hwblackbox import programs
        cols = programs.COLUMNS if prefix == programs.PREFIX else programs.OLD_COLUMNS
        with open(programs.path_for(dt.date.today(), prefix), "w", encoding="utf-8") as f:
            f.write(",".join(cols) + "\n")
            for k in range(30, 0, -1):
                f.write(rows(k, dt.datetime.fromtimestamp(now - k * 60).isoformat(timespec="seconds")))

    def test_the_page_reads_1_0_7s_cpu_log(self):
        from hwblackbox import programs
        from hwblackbox.dashboard import server
        now = time.time()
        # the last half hour in 1.0.7's log: dwm.exe a core flat out
        self.write_minutes(programs.OLD_PREFIX, lambda k, t: (
            "%s,60.0,dwm.exe,60.0,1,1752\n%s,60.0,chrome.exe,%.1f,9,10\n%s,60.0,System interrupts,0.6,0,\n"
            "%s,60.0,(all),%.1f,250,\n" % (t, t, 3 + (k == 10) * 30, t, t, 63.6 + (k == 10) * 30)), now)
        with open(paths.P.status, "w", encoding="utf-8") as f:
            json.dump({"pc": {"threads": 12}}, f)
        server._prog_files.clear()
        d = server.api_programs({"metric": "cpu", "hours": "1", "points": "60"})
        self.assertEqual([p["name"] for p in d["programs"]], ["dwm.exe", "chrome.exe", "System interrupts"])
        dwm, chrome = d["programs"][0], d["programs"][1]
        self.assertEqual((dwm["avg_cores"], dwm["peak_cores"], dwm["avg"]), (1.0, 1.0, 8.33))
        self.assertEqual(chrome["peak_cores"], 0.55)
        self.assertAlmostEqual(chrome["peak_at"], now - 600, delta=1.5)
        self.assertEqual(d["logged_s"], 1800)
        dw = d["series"]["dwm.exe"]
        self.assertTrue(all(v is None for v in dw[:25]))                   # before the log: a gap, not 0
        self.assertEqual([v for v in dw if v is not None], [8.33] * 30)
        self.assertEqual([v for v in d["total"] if v is not None][-1], 8.83)
        self.assertEqual(server.api_programs({"metric": "mem", "hours": "1"})["logged_s"], 0)   # (1.0.7: no memory)

    def test_memory_and_the_gpu_on_the_page(self):
        from hwblackbox import programs
        from hwblackbox.dashboard import server
        now = time.time()
        # explorer.exe grows from 350 MB to 2.9 GB; chrome.exe holds 1.5 GB and the GPU's 3D engine at 20 %
        self.write_minutes(programs.PREFIX, lambda k, t: (
            "%s,60.0,explorer.exe,0.5,%d,180,0,1,7060\n%s,60.0,chrome.exe,3.0,1536,300,20,9,10\n"
            "%s,60.0,(all),3.5,%d,480,20,250,\n" % (t, 350 if k > 20 else 1976 if k > 5 else 2900, t, t,
                                                   (350 if k > 20 else 1976 if k > 5 else 2900) + 1536)), now)
        server._prog_files.clear()
        d = server.api_programs({"metric": "mem", "hours": "1", "points": "60"})
        ex = next(p for p in d["programs"] if p["name"] == "explorer.exe")
        self.assertEqual([p["name"] for p in d["programs"]], ["explorer.exe", "chrome.exe"])   # by the most held
        self.assertEqual((ex["now"], ex["peak"], ex["change"]), (2900, 2900, 2550))
        self.assertEqual(d["unit"], "MB")
        g = server.api_programs({"metric": "gpu", "hours": "1", "points": "60"})
        self.assertEqual((g["programs"][0]["name"], g["programs"][0]["avg"]), ("chrome.exe", 20.0))
        self.assertEqual([v for v in g["total"] if v is not None][-1], 20.0)
        v = server.api_programs({"metric": "vram", "hours": "1", "points": "60"})
        self.assertEqual(v["programs"][0]["now"], 300)


class DiagnoseTest(unittest.TestCase):
    """The Diagnose tab's rules, on made-up records."""

    def inputs(self, **kw):
        now = time.time()
        d = {"now": now, "status": {"problems": [], "pc": {"boot_epoch": now - 3 * 86400, "disks": [
            {"mount": "C:\\", "total_gb": 465, "free_gb": 120}]}, "attributes": {"windows_update": "no restart waiting"}},
             "status_age": 10, "cfg": {"disk_warn_gb": 10}, "sensors": [], "flight_t": [], "flight": {},
             "programs": [], "power_offs": [], "records": [], "displays": []}
        d.update(kw)
        return d

    def run_(self, **kw):
        from hwblackbox import diagnose
        out = diagnose.run(self.inputs(**kw))
        return {c["id"]: c for c in out["checks"]}

    def test_a_busy_windows_program_and_a_leak(self):
        now = time.time()
        rows, shown = [], now - 6 * 3600
        for k in range(600, 0, -1):                          # the last 10 hours, a row a minute
            t = now - k * 60
            rows.append((t, 60.0, "dwm.exe", 59.0 if k > 120 else 1.0, 300.0, 1300.0, 2.0, 1, 1752))
            rows.append((t, 60.0, "Game.exe", 60.0 if k < 60 else 0.0, 4000.0, 2000.0, 90.0, 1, 4444))
            mem = 350.0 if t < shown + 60 else 1976.0
            rows.append((t, 60.0, "explorer.exe", 0.4, mem, 180.0, 0.0, 1, 7060))
            rows.append((t, 60.0, "(all)", 70.0, 8000.0, 3500.0, 90.0, 250, None))
        c = self.run_(programs=rows, displays=[shown])
        dwm = c["busy:dwm.exe"]
        self.assertEqual(dwm["level"], "warn")
        self.assertIn("Desktop Window Manager", dwm["seen"][0])
        self.assertTrue(any("graphics driver" in a for a in dwm["advice"]))
        self.assertNotIn("busy:Game.exe", c)                  # an hour of a game: what games do
        ex = c["memory:explorer.exe"]
        self.assertEqual(ex["level"], "warn")
        self.assertTrue(any("right after the screens changed" in s for s in ex["seen"]))
        self.assertTrue(ex["advice"][0].startswith("Restart it: Task Manager"))
        for ok in ("problems", "power", "crashes", "display", "disk", "update", "uptime"):
            self.assertEqual(c[ok]["level"], "ok", ok)

    def test_a_leak_from_before_the_programs_log(self):
        # (just after an update to 1.0.8 there's no programs log yet: the watched apps' own minute records show it)
        now = time.time()
        jump = now - 5 * 3600
        w = [(now - k * 60, 350.0 if now - k * 60 < jump else 1976.0) for k in range(900, 0, -1)]
        c = self.run_(watched_mem={"explorer.exe": w}, displays=[jump - 40])
        self.assertIn("memory:explorer.exe", c)
        self.assertTrue(any("right after the screens changed" in s for s in c["memory:explorer.exe"]["seen"]))
        self.assertNotIn("memory:explorer.exe", self.run_(watched_mem={"explorer.exe": [(t, 350.0) for t, _v in w]}))
        # (2026-11-06: just after the update, the watch list's record of claude.exe's main process (500 MB) ran into
        # the programs log's all-of-its-processes (7 GB), and read as a leak of 6.5 GB)
        rows = [(now - k * 60, 60.0, "claude.exe", 10.0, 7000.0, 200.0, 1.0, 26, 1) for k in range(40, 0, -1)]
        rows += [(now - k * 60, 60.0, "(all)", 50.0, 30000.0, 3000.0, 10.0, 400, None) for k in range(40, 0, -1)]
        early = [(now - k * 60, 500.0) for k in range(900, 41, -1)]
        self.assertNotIn("memory:claude.exe", self.run_(programs=rows, watched_mem={"claude.exe": early}))
        joined = [(now - k * 60, 350.0) for k in range(900, 300, -1)] + [(now - k * 60, 2000.0) for k in range(300, 41, -1)]
        ex = [(t, 60.0, "explorer.exe", 0.2, 2000.0, 180.0, 0.0, 1, 7060) for t, *_ in rows[:40]]
        self.assertIn("memory:explorer.exe", self.run_(programs=rows + ex, watched_mem={"explorer.exe": joined}))

    def test_crashes_in_several_programs_point_at_the_memory(self):
        now = time.time()
        recs = [{"kind": "winevent", "source": "Application Error", "id": 1000, "t": now - k * 3600,
                 "inserts": [app, "1.0", "x", "ntdll.dll", "1.0", "y", "0xc0000005"]}
                for k, app in enumerate(("a.exe", "b.exe", "c.exe"), start=1)]
        recs.append({"kind": "exit", "t": now - 100, "app": "Blender", "exe": "blender.exe", "code": "0xC0000005",
                     "meaning": "crash: access violation"})
        recs.append({"kind": "winevent", "source": "Application Error", "id": 1000, "t": now - 95,  # (the same crash)
                     "inserts": ["blender.exe", "4.2", "x", "y", "1", "z", "0xc0000005"]})
        c = self.run_(records=recs)["crashes"]
        self.assertEqual((c["level"], c["summary"]), ("warn", "4 crashes in the last 7 days, 4 programs"))
        self.assertIn("test the memory", c["advice"][0])

    def test_heat_and_a_rail_out_of_bounds(self):
        now = time.time()
        ts = [now - 3600 + 5 * k for k in range(600)]
        c = self.run_(flight_t=ts, flight={"cpu_temp_c": [60.0] * 599 + [96.0], "v12_v": [12.1] * 599 + [11.2],
                                           "v5_v": [5.04] * 600, "v33_v": [3.34] * 600})
        self.assertEqual(c["cpu_temp_c"]["level"], "bad")
        self.assertEqual(c["rails"]["level"], "bad")
        self.assertTrue(any("+12 V" in s and "outside the ATX limit" in s for s in c["rails"]["seen"]))

    def test_the_service_not_reporting_and_a_check_that_breaks(self):
        c = self.run_(status_age=None, power_offs=[None])
        self.assertEqual(c["problems"]["level"], "bad")
        self.assertEqual(c["error"]["title"], "A check couldn't run")          # (the rest still ran)
        self.assertIn("disk", c)


if __name__ == "__main__":
    unittest.main()
