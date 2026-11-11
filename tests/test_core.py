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
            nvml = type("N", (), {"name": None, "handle": None})()
            last_nv = {}
            ram_total_gb = None
        lhm = {("GpuAmd", "Temperature", "GPU Core"): 61.0, ("GpuAmd#2", "Temperature", "GPU Core"): 30.0,
               ("Cpu", "Temperature", "Core (Tctl/Tdie)"): 55.0}
        built = SensorStats("now").build(Fake(), lhm, {"timestamp": "x"})
        out = built["sensors"]
        self.assertNotIn("Nvml", built["devices"])                   # (no NVIDIA GPU: the page names the AMD one)
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
        rows = _rows_before(p, dt.datetime(2026, 10, 7, 2, 15, 12).timestamp(), 5)
        self.assertEqual([r[1].split(": ")[1] for r in rows], ["2026-10-07T02:14:50,1", "2026-10-07T02:14:55,2"])

    def test_the_last_rows_across_versions_and_packed_days(self):
        # 1.1.0 writes times with their offset; the day before, without; the day before that is packed (.csv.gz)
        import gzip
        from hwblackbox.poweroff import _tail_rows
        from hwblackbox.util import iso_at
        t0 = dt.datetime(2026, 11, 8, 23, 59, 55).timestamp()
        with gzip.open(os.path.join(paths.P.logs, "flight_20261107.csv.gz"), "wb") as f:
            f.write(b"timestamp,a\n2026-11-07T23:59:59,0\n")
        with open(os.path.join(paths.P.logs, "flight_20261108.csv"), "w") as f:
            f.write("timestamp,a\n%s,1\n" % dt.datetime.fromtimestamp(t0).isoformat())
        with open(os.path.join(paths.P.logs, "flight_20261109.csv"), "w") as f:
            f.write("timestamp,a\n%s,2\n%s,3\n" % (iso_at(t0 + 10), iso_at(t0 + 20)))
        rows = _tail_rows("flight_", t0 + 15, 3)
        self.assertEqual([r[1].rsplit(",", 1)[1] for r in rows], ["0", "1", "2"])
        self.assertEqual([round(r[0] - t0) for r in rows][1:], [0, 10])
        self.assertTrue(rows[0][1].startswith("flight_20261107.csv: "))       # (named as the day's log, packed or not)

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

    def ended(self, code, agent_recs=(), signed_out=False, session=1, taskbar=None, shell=None, exe="explorer.exe",
              rec=False):
        from hwblackbox import watcher

        class FakeAgents:
            def taskbar_pids(self):
                return {taskbar} if taskbar else set()

            def taskbar_of(self, sid):
                return taskbar if sid == 1 else None

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
        if shell:                                       # (pid, exe, session) of a running process the watcher tracks
            s = watcher.Tracked()
            s.pid, s.exe, s.label, s.started, s.main, s.handle, s.mem = shell[0], shell[1], "Explorer", time.time(), \
                True, None, None
            s.by_port, s.policy, s.ports, s.session = False, "nonzero", None, shell[2]
            w.tracked[s.pid] = s
        t = watcher.Tracked()
        t.pid, t.exe, t.label, t.started, t.main, t.handle, t.mem = 4242, exe, "Explorer", time.time(), True, \
            None, None
        t.by_port, t.policy, t.ports, t.session = False, "nonzero", None, session
        w.tracked[t.pid] = t
        w.ended(t, code)
        exit_rec = next(r for r in jr.recs if r["kind"] == "exit")
        if rec:
            return w.notes["last_incident"] is not None, exit_rec
        return w.notes["last_incident"] is not None, bool(exit_rec.get("while_session_ends"))

    def test_explorer_hand_off(self):
        """2026-11-09: an updater ran explorer.exe to start a program; it handed that to the running shell and ended
        with exit code 1 (ran 1 s), which wrote "Windows Explorer ended" though the taskbar never went away."""
        from hwblackbox.dashboard.server import describe
        shell = (8568, "explorer.exe", 1)
        incident, rec = self.ended(1, taskbar=8568, shell=shell, rec=True)
        self.assertFalse(incident)
        self.assertEqual(rec["shell_running"], 8568)
        d = describe(rec, time.time())
        self.assertEqual(d["level"], "info")
        self.assertIn("the taskbar's kept running", d["text"])
        # still incidents: a crash; the taskbar's own Explorer; no taskbar known (no agent); the taskbar's pid no
        # longer a running Explorer (restarted, or another program got the pid); its taskbar in another session;
        # another program
        self.assertTrue(self.ended(0xC0000005, taskbar=8568, shell=shell)[0])
        self.assertTrue(self.ended(1, taskbar=4242, shell=shell)[0])
        self.assertTrue(self.ended(1, taskbar=None, shell=shell)[0])
        self.assertTrue(self.ended(1, taskbar=8568)[0])
        self.assertTrue(self.ended(1, taskbar=8568, shell=(8568, "notepad.exe", 1))[0])
        self.assertTrue(self.ended(1, taskbar=8568, shell=(8568, "explorer.exe", 2))[0])
        self.assertTrue(self.ended(1, taskbar=8568, shell=shell, exe="claude.exe")[0])
        self.assertTrue(self.ended(1, session=2, taskbar=8568, shell=shell)[0])

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
        from hwblackbox import winapi
        with open(os.path.join(paths.P.logs, "events_%s.jsonl" % day), "w", encoding="utf-8") as f:
            f.write(line(kind="startup", version="1.0.6", data_dir="x"))
        # (a folder named "service", posing as the service: an older version's kind of folder, not read since 1.1.0)
        for name in ("service", winapi.token_sid()):
            folder = os.path.join(paths.P.sessions, name)
            os.makedirs(folder)
            with open(os.path.join(folder, "session_%s.jsonl" % day), "w", encoding="utf-8") as f:
                f.write("[]\n")                                                       # not a record
                f.write(line(kind="winevent", source="Microsoft-Windows-Kernel-Power", id=41, at=now.isoformat()))
                f.write(line(kind="display", before=5, after=6))                      # wrong types
                f.write(json.dumps({"ts": "2099-01-01T00:00:00", "kind": "startup", "version": "x"}) + "\n")
                f.write(line(kind="startup", version="1.0.6", data_dir="x"))
        texts = [e["text"] for e in server.api_events({})["events"]]
        self.assertEqual(texts, ["HW Blackbox's service started (1.0.6)",
                                 "The session agent (%s) started (1.0.6)" % winapi.user_name()])

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
        from hwblackbox import winapi
        target = os.path.join(self.dir, "elsewhere")
        os.makedirs(target)
        me = winapi.token_sid()
        os.makedirs(os.path.join(paths.P.sessions, me))
        os.makedirs(os.path.join(paths.P.sessions, "alice"))           # (an older version's folder: not read)
        _winapi.CreateJunction(target, os.path.join(paths.P.sessions, "S-1-5-21-1-2-3-1009"))
        self.assertTrue(is_link(os.path.join(paths.P.sessions, "S-1-5-21-1-2-3-1009")))
        self.assertEqual([p for _, p in server.session_dirs()], [os.path.join(paths.P.sessions, me)])
        self.assertEqual(server.session_dirs()[0][0], winapi.user_name())        # (named by the account)

    def test_each_users_folder_is_theirs(self):
        # the service's side: a folder another user made first (anyone could, before 1.1.0) is moved aside; an older
        # version's folder, named by the user and made by them, moves to the SID with its history
        from hwblackbox import agents, winapi
        me, name = winapi.token_sid(), winapi.user_name()
        old = paths.P.session_dir(name)
        os.makedirs(old)
        with open(os.path.join(old, "session_20261101.jsonl"), "w") as f:
            f.write("{}\n")
        jr = Recorder()
        path = agents.make_user_folder(me, name, jr)
        self.assertEqual(path, paths.P.session_dir(me))
        self.assertTrue(os.path.exists(os.path.join(path, "session_20261101.jsonl")))
        self.assertFalse(os.path.exists(old))
        self.assertEqual(jr.recs[0]["event"], "folder moved")
        # 2026-11-10: the moved files kept the permissions of where they were, read-only for their own user (the
        # installer had taken the old folder's grants off), and the agent couldn't open its own crash log
        import win32security
        ro = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor("D:P(A;;0x1200a9;;;%s)" % me, 1)

        def read_only(p):
            win32security.SetNamedSecurityInfo(p, win32security.SE_FILE_OBJECT,
                                               win32security.DACL_SECURITY_INFORMATION |
                                               win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                                               None, None, ro.GetSecurityDescriptorDacl(), None)
        old_file = os.path.join(path, "agent_crash.log")
        open(old_file, "w").close()
        read_only(old_file)
        linked = os.path.join(path, "linked.txt")
        open(linked, "w").close()
        os.link(linked, os.path.join(self.dir, "elsewhere.txt"))           # (two names: never handed over)
        read_only(linked)
        with self.assertRaises(PermissionError):
            open(old_file, "a").close()
        self.assertGreaterEqual(agents.inherit_children(path, me), 1)
        with open(old_file, "a") as f:                                       # its own again
            f.write("x")
        with self.assertRaises(PermissionError):
            open(linked, "a").close()
        for p in (linked, os.path.join(self.dir, "elsewhere.txt")):          # (so the clean-up can remove them)
            win32security.SetNamedSecurityInfo(p, win32security.SE_FILE_OBJECT,
                                               win32security.DACL_SECURITY_INFORMATION |
                                               win32security.UNPROTECTED_DACL_SECURITY_INFORMATION,
                                               None, None, win32security.ACL(), None)
        # (made unelevated here, so owned by this user; the real service's are the administrators')
        if agents.owner_of(path) not in (agents.SYSTEM, agents.ADMINS):
            self.assertIsNone(agents.make_user_folder("S-1-5-21-1-2-3-1009", None) and None)
            os.makedirs(paths.P.session_dir("S-1-5-21-1-2-3-1010"))      # someone else's, made first
            agents.make_user_folder("S-1-5-21-1-2-3-1010", None, jr)
            self.assertTrue([f for f in os.listdir(paths.P.sessions) if f.startswith("S-1-5-21-1-2-3-1010.untrusted-")])

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
        svc.drives = type("Dr", (), {"latest": None, "problems": lambda self: []})()
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


class LaptopTest(TempData):
    """1.0.9: a laptop (2026-11-06, a Framework with an i7-1260P) had two false problems: "No rail voltages" (a laptop
    has none to read) and "No CPU temperature (the driver may be gone)" when the driver had never been installed."""

    def problems(self, **sens):
        from hwblackbox import status
        s = {"rails_ok": False, "cpu_temp_ok": False, "cpu_age_s": 0.5, "driver": "running", "board_chip": None,
             "board_chip_before": None, "portable": False}
        s.update(sens)
        a = {}
        return status.sensor_problems(s, a), a

    def test_a_laptop_without_the_driver(self):
        probs, a = self.problems(driver="missing", portable=True)
        self.assertEqual(len(probs), 1)
        self.assertTrue(probs[0].startswith("The PawnIO driver isn't installed, so there's no reading of the CPU's "
                                            "temperature and power: run Install.cmd again"), probs)
        self.assertEqual((a["rails"], a["cpu_temperature"]), ("none on this PC", "missing"))
        self.assertEqual(a["board_note"], "A laptop: no power supply rails to read")

    def test_a_laptop_with_the_driver_has_no_problems(self):
        probs, a = self.problems(portable=True, cpu_temp_ok=True)
        self.assertEqual(probs, [])
        self.assertEqual(a["rails"], "none on this PC")

    def test_a_desktop(self):
        probs, a = self.problems(driver="missing")                  # no driver: one problem, rails included
        self.assertEqual(len(probs), 1)
        self.assertIn("the rail voltages", probs[0])
        self.assertEqual(a["rails"], "missing")
        probs, a = self.problems(driver="stopped", cpu_temp_ok=True)
        self.assertTrue(probs[0].startswith("The PawnIO driver isn't running (stopped)"))
        probs, a = self.problems(cpu_temp_ok=True)                  # a board chip it can't read: a note
        self.assertEqual(probs, [])
        self.assertIn("No board sensor chip", a["board_note"])
        probs, a = self.problems(cpu_temp_ok=True, board_chip_before="Nuvoton NCT6798D")
        self.assertIn("The board's sensor chip (Nuvoton NCT6798D) didn't answer", probs[0])
        self.assertEqual(a["rails"], "missing")
        probs, a = self.problems(cpu_temp_ok=True, rails_ok=True, board_chip="Nuvoton NCT6798D")
        self.assertEqual((probs, a["rails"]), ([], "ok"))
        self.assertNotIn("board_note", a)
        probs, a = self.problems(driver=None, cpu_temp_ok=True)    # the driver's state unknown: as before 1.0.9
        self.assertEqual(probs, ["No rail voltages (the sensor driver, PawnIO, may be gone)"])

    def test_the_board_chip_is_remembered(self):
        from hwblackbox import sensors
        s = sensors.Sensors.__new__(sensors.Sensors)
        s.sampler = type("S", (), {})()
        s.sampler.lhm = type("L", (), {"names": {"Motherboard": "MSI B550", "SuperIO": "Nuvoton NCT6798D"}})()
        self.assertEqual(s.find_board_chip()["now"], "Nuvoton NCT6798D")
        s.sampler.lhm.names = {"Motherboard": "MSI B550"}           # (the chip didn't answer this time)
        self.assertEqual(s.find_board_chip()["before"], "Nuvoton NCT6798D")
        s.sampler.lhm.names = {"Motherboard": "Another board"}      # (a new board: what the old one had doesn't count)
        self.assertIsNone(s.find_board_chip()["before"])

    def test_an_intel_cpus_temperature(self):
        from hwblackbox.sensors import _cpu_temp
        intel = {("Cpu", "Temperature", "P-Core #1"): 47.0, ("Cpu", "Temperature", "P-Core #1 Distance to TjMax"): 53.0,
                 ("Cpu", "Temperature", "Core Max"): 49.0, ("Cpu", "Temperature", "CPU Package"): 50.0}
        self.assertEqual(_cpu_temp(intel), 50.0)
        del intel[("Cpu", "Temperature", "CPU Package")]
        self.assertEqual(_cpu_temp(intel), 49.0)
        del intel[("Cpu", "Temperature", "Core Max")]
        self.assertEqual(_cpu_temp(intel), 47.0)                     # (never the 53 "Distance to TjMax")
        self.assertEqual(_cpu_temp({("Cpu", "Temperature", "Core (Tctl/Tdie)"): 61.0,
                                    ("Cpu", "Temperature", "CCD1 (Tdie)"): 55.0}), 61.0)

    def test_why_it_went_off(self):
        from hwblackbox.poweroff import why_41
        self.assertEqual(why_41({"BugcheckCode": "159", "PowerButtonTimestamp": "0"}),
                         "Windows crashed: a blue screen, stop code 0x0000009F (DRIVER_POWER_STATE_FAILURE: a driver "
                         "failed going to sleep, waking, or a power change)")
        self.assertEqual(why_41({"BugcheckCode": "0x1C9"}), "Windows crashed: a blue screen, stop code 0x000001C9")
        self.assertIn("WHEA_UNCORRECTABLE_ERROR", why_41({"BugcheckCode": "292"}))     # (0x124)
        self.assertEqual(why_41({"BugcheckCode": "0", "PowerButtonTimestamp": "133000000000000000"}),
                         "the power button was held down (a forced power-off)")
        self.assertEqual(why_41({"BugcheckCode": "0", "LongPowerButtonPressDetected": "true"}),
                         "the power button was held down (a forced power-off)")
        self.assertEqual(why_41({"BugcheckCode": "0", "SleepInProgress": "4"}),
                         "it went off going into or coming out of sleep")
        self.assertEqual(why_41({"BugcheckCode": "0", "PowerButtonTimestamp": "0", "SleepInProgress": "0"}), "")
        self.assertEqual(why_41({}), "")

    def test_the_battery_before_it_went_off(self):
        from hwblackbox.poweroff import battery_before
        from hwblackbox.sensors import COLUMNS
        old = ",".join(["2026-11-05T09:00:00"] + ["1"] * 19)              # (a row from before 1.0.9: no battery)
        new = dict.fromkeys(COLUMNS, "")
        new.update(timestamp="2026-11-05T09:01:00", battery_pct="3", on_ac="0", note="a, quoted note")
        import csv
        import io
        buf = io.StringIO()
        csv.writer(buf).writerow([new[c] for c in COLUMNS])
        rows = [(0, "flight_20261105.csv: " + old), (1, "flight_20261105.csv: " + buf.getvalue().strip())]
        self.assertEqual(battery_before(rows), "3 %, on battery")
        self.assertEqual(battery_before(rows[:1]), "")

    def test_a_logs_column_names_are_written_again_after_an_update(self):
        from hwblackbox.sensors import CsvLogger
        log = CsvLogger("flight_", ["timestamp", "a"])
        log.write({"timestamp": "2026-11-06T10:00:00", "a": 1})
        log.close()
        log = CsvLogger("flight_", ["timestamp", "a", "b"])                # (the new version: one more column)
        log.write({"timestamp": "2026-11-06T10:00:05", "a": 2, "b": 3})
        log.close()
        log = CsvLogger("flight_", ["timestamp", "a", "b"])                # (a restart: no new header)
        log.write({"timestamp": "2026-11-06T10:00:10", "a": 4, "b": 5})
        log.close()
        with open(os.path.join(paths.P.logs, "flight_20261106.csv"), encoding="utf-8") as f:
            self.assertEqual(f.read().split(), ["timestamp,a", "2026-11-06T10:00:00,1", "timestamp,a,b",
                                                "2026-11-06T10:00:05,2,3", "2026-11-06T10:00:10,4,5"])
        from hwblackbox.dashboard.server import FlightCache
        c = FlightCache().get("flight_20261106.csv")
        self.assertEqual(len(c["t"]), 3)
        self.assertEqual(list(c["a"]), [1.0, 2.0, 4.0])
        self.assertEqual(len(c["b"]), 3)                                    # (a value for every row: blank first)
        self.assertEqual(list(c["b"])[1:], [3.0, 5.0])


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


class UpdateTest(TempData):
    """1.0.10: updates from GitHub, offered on the page, installed only on a click and Windows' admin prompt."""

    def zip_of(self, version, extra=None):
        import io
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("HWBlackbox/MANIFEST.json", json.dumps({"version": version, "files": 2}))
            z.writestr("HWBlackbox/install.ps1", "# the installer")
            for name, data in (extra or {}).items():
                z.writestr(name, data)
        return buf.getvalue()

    def release(self, tag="v1.0.10", data=b"zip", body_sha=True, digest=True, **kw):
        import hashlib
        sha = hashlib.sha256(data).hexdigest()
        rel = {"tag_name": tag, "draft": False, "prerelease": False,
               "html_url": "https://github.com/jamesccupps/HW-Blackbox/releases/tag/" + tag,
               "body": "notes\n\nSHA-256: `%s`\n" % sha if body_sha else "notes",
               "assets": [{"name": "HWBlackbox-win64.zip", "size": len(data),
                           "browser_download_url": "https://github.com/jamesccupps/HW-Blackbox/releases/download/%s/"
                                                   "HWBlackbox-win64.zip" % tag,
                           "digest": "sha256:" + sha if digest else None}]}
        rel.update(kw)
        return rel

    def test_versions(self):
        from hwblackbox.update import parse_version
        self.assertEqual(parse_version("v1.0.10"), (1, 0, 10))
        self.assertGreater(parse_version("1.0.10"), parse_version("v1.0.9"))
        self.assertEqual(parse_version("1.1"), (1, 1, 0))
        self.assertIsNone(parse_version("1.1.0-beta"))                  # (pre-releases are never offered)
        self.assertIsNone(parse_version("latest"))

    def test_what_a_release_offers(self):
        from hwblackbox.update import offer
        off = offer(self.release(), (1, 0, 9))
        self.assertEqual((off["version"], off["size"]), ("1.0.10", 3))
        self.assertIsNone(offer(self.release(), (1, 0, 10)))            # (no newer)
        self.assertIsNone(offer(self.release(tag="v1.0.8"), (1, 0, 9)))
        self.assertIsNone(offer(self.release(draft=True), (1, 0, 9)))
        self.assertIsNone(offer(self.release(prerelease=True), (1, 0, 9)))
        self.assertEqual(offer(self.release(digest=False), (1, 0, 9))["sha256"], off["sha256"])   # (the notes')
        self.assertEqual(offer(self.release(body_sha=False), (1, 0, 9))["sha256"], off["sha256"])  # (GitHub's)
        bad = [self.release(digest=False, body_sha=False),                                  # no SHA-256 at all
               self.release(assets=[]),                                                     # no zip
               self.release(body="SHA-256: `%s`" % ("0" * 64))]                             # two that disagree
        elsewhere = self.release()
        elsewhere["assets"][0]["browser_download_url"] = "https://example.com/HWBlackbox-win64.zip"
        bad.append(elsewhere)
        for rel in bad:
            with self.assertRaises(ValueError):
                offer(rel, (1, 0, 9))
        odd = self.release()
        odd["html_url"] = "javascript:alert(1)"
        self.assertIsNone(offer(odd, (1, 0, 9))["page"])                 # (the page links only to GitHub)

    def test_a_zip_that_points_outside_is_refused(self):
        from hwblackbox.update import unpack
        z = os.path.join(self.dir, "evil.zip")
        for name in ("HWBlackbox/../../evil.txt", "C:/evil.txt", "elsewhere/x.txt"):
            with open(z, "wb") as f:
                f.write(self.zip_of("1.0.10", {name: "x"}))
            with self.assertRaises(ValueError):
                unpack(z, os.path.join(self.dir, "out"))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "evil.txt")))

    def test_the_download_is_checked(self):
        import io
        from unittest import mock
        from hwblackbox import update
        data = self.zip_of("1.0.10")
        rel = self.release(data=data)
        staging = os.path.join(self.dir, "update")
        lines = []

        def fake_open(served):
            def _open(url, timeout):
                return io.BytesIO(json.dumps(rel).encode() if url == update.LATEST else served)
            return _open
        with mock.patch.object(update, "_open", fake_open(data)), mock.patch.object(update, "VERSION", "1.0.9"):
            self.assertEqual(update.run(dry_run=True, staging=staging, out=lines.append), 0)
        self.assertTrue(os.path.isfile(os.path.join(staging, "1.0.10", "HWBlackbox", "install.ps1")))
        with open(os.path.join(staging, "run-install.cmd")) as f:
            self.assertIn(os.path.join(staging, "1.0.10", "HWBlackbox", "install.ps1"), f.read())
        self.assertIn("dry run", lines[-1])
        lines.clear()
        tampered = data[:-1] + bytes([data[-1] ^ 1])                    # (one bit changed on the way)
        with mock.patch.object(update, "_open", fake_open(tampered)), mock.patch.object(update, "VERSION", "1.0.9"):
            self.assertEqual(update.run(dry_run=True, staging=staging, out=lines.append), 1)
        self.assertTrue(any("SHA-256 isn't the release's" in x for x in lines), lines)
        self.assertEqual(os.listdir(staging), [])                       # (nothing left to install from)
        other = self.zip_of("1.0.11")                                   # (the zip of another version)
        rel = self.release(data=other)
        with mock.patch.object(update, "_open", fake_open(other)), mock.patch.object(update, "VERSION", "1.0.9"):
            self.assertEqual(update.run(dry_run=True, staging=staging, out=lines.append), 1)
        self.assertIn("holds HW Blackbox 1.0.11, not 1.0.10", lines[-2])
        with mock.patch.object(update, "_open", fake_open(data)), mock.patch.object(update, "VERSION", "1.0.10"):
            self.assertEqual(update.run(dry_run=True, staging=staging, out=lines.append), 0)
        self.assertEqual(lines[-1], "This is the newest version.")

    def test_the_pages_check(self):
        from unittest import mock
        from hwblackbox import update
        path = os.path.join(self.dir, "update.json")
        c = update.Checker(path)
        with mock.patch.object(update, "latest_release", return_value=self.release()), \
                mock.patch.object(update, "VERSION", "1.0.9"):
            self.assertTrue(c.view()["checking"])
            for _ in range(50):
                if not c.busy:
                    break
                time.sleep(0.05)
            v = c.view()
            self.assertEqual((v["offer"]["version"], v["latest"], v["error"]), ("1.0.10", "1.0.10", None))
            self.assertFalse(v["checking"])                             # (asked a moment ago: not again for a day)
        with mock.patch.object(update, "VERSION", "1.0.10"):
            self.assertIsNone(update.Checker(path).view()["offer"])     # (kept on disk; this version has it now)
        c = update.Checker(None)
        with mock.patch.object(update, "latest_release", side_effect=OSError("offline")):
            self.assertFalse(c.view(enabled=False)["checking"])          # (the daily look off: never asks)
            c.view(enabled=False, now=True)                             # ("check now" asks anyway)
            for _ in range(50):
                if not c.busy:
                    break
                time.sleep(0.05)
            self.assertEqual(c.view(enabled=False)["error"], "OSError: offline")

    def test_update_only_from_the_page(self):
        import urllib.error
        import urllib.request
        from unittest import mock
        from hwblackbox.dashboard import server
        port = free_port()
        httpd = server.start(port)
        try:
            def post(path, headers):
                req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), data=b"", headers=headers,
                                             method="POST")
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                try:
                    with opener.open(req, timeout=5) as r:
                        return r.status, json.loads(r.read())
                except urllib.error.HTTPError as e:
                    return e.code, None
            page = {"Sec-Fetch-Site": "same-origin", "X-HWB": "1"}
            with mock.patch.object(server.update, "launch", return_value={"started": True}) as launch:
                self.assertEqual(post("/api/update/install", {})[0], 403)                      # (a program)
                self.assertEqual(post("/api/update/install", {"Sec-Fetch-Site": "cross-site", "X-HWB": "1"})[0], 403)
                self.assertEqual(post("/api/update/install", {"Sec-Fetch-Site": "same-origin"})[0], 403)
                self.assertEqual(post("/api/other", page)[0], 404)
                launch.assert_not_called()
                self.assertEqual(post("/api/update/install", page), (200, {"started": True}))
                launch.assert_called_once_with()
        finally:
            httpd.shutdown()
            httpd.server_close()


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

    def test_a_laptops_battery(self):
        self.assertNotIn("battery", self.run_())                                   # (a desktop: no battery at all)
        now = time.time()

        def bat(name, value, kind="Energy"):
            return {"id": "Battery/%s/%s" % (kind, name), "name": name, "value": value}
        worn = [bat("Designed Capacity", 55000.0), bat("Fully-Charged Capacity", 30250.0),
                bat("Degradation Level", 45.0, "Level")]
        # the last 2 hours: an hour plugged in, then 50 min on battery from 60 % to 4 % (a gap, a sleep, in between
        # doesn't count as time on battery), then plugged in again
        ts, pct, ac = [], [], []
        for k in range(1440):
            t = now - 7200 + 5 * k
            if 3600 <= 5 * k < 6600:
                ts.append(t), pct.append(60.0 - (5 * k - 3600) / 3000 * 56), ac.append(0.0)
            elif 5 * k >= 6600:
                ts.append(t), pct.append(5.0 + (5 * k - 6600) / 600), ac.append(1.0)
            else:
                ts.append(t), pct.append(90.0), ac.append(1.0)
        c = self.run_(sensors=worn, flight_t=ts, flight={"battery_pct": pct, "on_ac": ac})["battery"]
        self.assertEqual((c["level"], c["summary"]), ("warn", "Holds 55 % of the charge it held new"))
        self.assertEqual(c["seen"][0], "Holds 30 Wh of the 55 Wh it was made for: 45 % worn")
        self.assertTrue(c["seen"][1].startswith("On battery for 50 min in the last 24 hours, draining about 67 % an "
                                                "hour: a full charge would last about 1 h 30 min"), c["seen"][1])
        self.assertTrue(c["seen"][2].startswith("Ran down to 4 % on battery"), c["seen"])
        self.assertEqual(c["seen"][-1], "Now 6 %, plugged in")
        self.assertIn("plan to replace it", c["advice"][0])
        self.assertTrue(any("Critical battery action" in a for a in c["advice"]))
        self.assertIn("powercfg /batteryreport", c["advice"][-1])
        good = [bat("Designed Capacity", 55000.0), bat("Fully-Charged Capacity", 52800.0)]
        c = self.run_(sensors=good)["battery"]
        self.assertEqual((c["level"], c["summary"], c["advice"]), ("ok", "Holds 96 % of the charge it held new", []))
        c = self.run_(sensors=[bat("Degradation Level", 27.0, "Level")])["battery"]          # (only the wear)
        self.assertEqual((c["level"], c["seen"][0]), ("info", "27 % worn"))
        self.assertIn("charge limit", c["advice"][0])

    def test_a_laptops_power_offs(self):
        now = time.time()
        boot = dt.datetime.fromtimestamp(now - 3600).isoformat(timespec="seconds")
        st = self.inputs()["status"]
        st["sensors"] = {"portable": True}
        po = [{"boot": boot, "went_down": None, "why": None, "battery": "3 %, on battery"}]
        c = self.run_(power_offs=po, status=st)["power"]
        self.assertIn("battery 3 %, on battery", c["seen"][0])
        self.assertTrue(c["advice"][0].startswith("The battery ran out"))
        self.assertFalse(any("power supply" in a for a in c["advice"]))           # (no desktop advice on a laptop)
        po = [{"boot": boot, "went_down": None, "why": "Windows crashed: a blue screen, stop code 0x0000009F"}]
        c = self.run_(power_offs=po, status=st)["power"]
        self.assertTrue(c["seen"][0].endswith("Windows crashed: a blue screen, stop code 0x0000009F"))
        self.assertTrue(c["advice"][0].startswith("A blue screen"))
        po = [{"boot": boot, "went_down": None, "why": None}]
        c = self.run_(power_offs=po, status=st)["power"]
        self.assertIn("on a laptop", c["advice"][0])
        c = self.run_(power_offs=po)["power"]                                       # (a desktop)
        self.assertIn("A power supply that trips", c["advice"][1])

    def test_the_service_not_reporting_and_a_check_that_breaks(self):
        c = self.run_(status_age=None, power_offs=[None])
        self.assertEqual(c["problems"]["level"], "bad")
        self.assertEqual(c["error"]["title"], "A check couldn't run")          # (the rest still ran)
        self.assertIn("disk", c)

    def test_hardware_errors(self):
        now = time.time()
        whea = lambda eid, level, ago, **kw: dict({"kind": "winevent", "source": "Microsoft-Windows-WHEA-Logger",   # noqa
                                                  "id": eid, "level": level, "t": now - ago}, **kw)
        c = self.run_()["hardware"]
        self.assertEqual((c["level"], c["summary"]), ("ok", "None in the last 7 days"))
        c = self.run_(records=[whea(19, "warning", 3600), whea(19, "warning", 600, skipped_before=4),
                               whea(17, "warning", 300), whea(47, "warning", 8 * 86400)])["hardware"]
        self.assertEqual(c["level"], "warn")
        self.assertEqual(c["summary"], "7 hardware errors in the last 7 days")      # (2 + 4 left out, and the PCIe one)
        self.assertTrue(c["seen"][0].startswith("The CPU: 6 corrected"))
        self.assertTrue(any("PBO" in a for a in c["advice"]) and any("PCIe generation" in a for a in c["advice"]))
        self.assertFalse(any("MemTest86" in a for a in c["advice"]))               # (the memory's was 8 days ago)
        c = self.run_(records=[whea(18, "error", 120)])["hardware"]
        self.assertEqual((c["level"], c["summary"]), ("bad", "1 hardware error in the last 7 days, 1 fatal"))

    def test_drives(self):
        now = time.time()
        ok = [{"disk": 0, "model": "ST1000DM010", "media": "HDD", "health": "healthy", "temp_c": 38, "wear_pct": None,
               "read_err_unc": 0, "write_err_unc": 0, "power_on_h": 20000},
              {"disk": 1, "model": "Samsung SSD 990 PRO 1TB", "media": "SSD", "health": "healthy", "temp_c": 41,
               "wear_pct": 2, "read_err_unc": 0, "write_err_unc": 0, "power_on_h": 3000}]
        c = self.run_(drives={"drives": ok})["drives"]
        self.assertEqual((c["level"], c["summary"]), ("ok", "2 drives, all healthy"))
        self.assertIn("Disk 1 (Samsung SSD 990 PRO 1TB): healthy, 41 °C, 2 % worn", c["seen"][1])
        self.assertNotIn("drives", self.run_())                                     # (nothing known: no finding)
        # a drive that's run hot and worn out, and whose uncorrectable errors grew this month
        bad = [dict(ok[0]), dict(ok[1], temp_c=74, wear_pct=100, read_err_unc=3)]
        rows = [(now - 20 * 86400, 1, {"read_err_unc": 1, "write_err_unc": 0})]
        c = self.run_(drives={"drives": bad}, drive_rows=rows)["drives"]
        self.assertEqual(c["level"], "bad")
        self.assertIn("3 errors it couldn't correct (+2 this month)", c["seen"][1])
        self.assertTrue(any("heatsink" in a for a in c["advice"]) and c["advice"][0].startswith("Back up"))
        # the drives' error records: a controller reset names its drive; a bad block is serious
        reset = {"kind": "winevent", "source": "stornvme", "id": 129, "level": "warning", "t": now - 600,
                 "inserts": ["\\Device\\RaidPort1"]}
        block = {"kind": "winevent", "source": "disk", "id": 7, "level": "error", "t": now - 300,
                 "inserts": ["\\Device\\Harddisk1\\DR1"]}
        c = self.run_(drives={"drives": ok}, records=[reset])["drives"]
        self.assertEqual(c["level"], "info")
        self.assertIn("Windows reset the drive", c["seen"][-1])
        c = self.run_(drives={"drives": ok}, records=[reset, block])["drives"]
        self.assertEqual(c["level"], "bad")
        self.assertTrue(any(s.startswith("Disk 1 (Samsung SSD 990 PRO 1TB): 1 error record") for s in c["seen"]))
        self.assertTrue(any("chkdsk" in a for a in c["advice"]))

    def test_crashes_name_the_program(self):
        now = time.time()
        ins = ["python.exe", "3.12.10", "0", "gdal313.dll", "3.11", "0", "0xc0000005", "0x1", "0x2a0", "0",
               "C:\\PROGRA~1\\QGIS34~1.15\\bin\\python.exe"]
        rec = {"kind": "winevent", "source": "Application Error", "id": 1000, "t": now - 600, "inserts": ins,
               "app": "python.exe", "program": "QGIS 3.44.15"}
        c = self.run_(records=[rec, dict(rec, t=now - 300)])["crashes"]
        self.assertEqual(c["seen"][0].split(": ")[0], "python.exe (QGIS 3.44.15)")
        self.assertIn("Windows recorded a crash in gdal313.dll (0xc0000005)", c["seen"][0])


class NewIn110Test(TempData):
    """1.1.0: times with their offset, packed day logs, the hardware's and the drives' records, crashes named by their
    program."""

    def test_times_carry_their_offset_and_the_repeated_hour_is_told_apart(self):
        from hwblackbox.util import iso_at, now_iso, parse_iso
        s = now_iso(ms=True)
        self.assertRegex(s, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}[+-]\d\d:\d\d$")
        self.assertAlmostEqual(parse_iso(s), time.time(), delta=2)
        self.assertEqual(parse_iso(iso_at(1794000000.0)), 1794000000.0)
        first = dt.datetime(2026, 11, 1, 1, 30)
        if first.timestamp() == first.replace(fold=1).timestamp():
            self.skipTest("this PC's time zone has no daylight saving")
        t = parse_iso("2026-11-01T01:30:00")                        # (the first 01:30, before 1.1.0: no offset)
        self.assertEqual(parse_iso("2026-11-01T01:20:00", after=t), t + 3600 - 600)    # (the second, after it)
        self.assertEqual(parse_iso("2026-11-01T01:40:00", after=t), t + 600)          # (still the first)

    def test_old_days_are_packed_and_read_as_before(self):
        import gzip
        from hwblackbox import disks, util
        from hwblackbox.dashboard import server
        logs = paths.P.logs
        today = dt.date(2026, 11, 10)
        for day in ("20261107", "20261108", "20261109", "20261110"):
            with open(os.path.join(logs, "flight_%s.csv" % day), "w") as f:
                f.write("timestamp,cpu_temp_c\n%s-%s-%sT12:00:00,50\n\x00\x00" % (day[:4], day[4:6], day[6:]))
        with open(os.path.join(logs, "disks_20261107.csv"), "w") as f:
            f.write("timestamp,drive,free_gb,total_gb\n2026-11-07T12:00:00,C:,40.5,465\n")
        open(os.path.join(logs, "events_20261107.jsonl"), "w").close()
        self.assertEqual(util.pack_logs(logs, ("flight_", "disks_"), today=today), 3)
        # (yesterday's and today's stay plain; the records, events_*.jsonl, aren't a packed kind)
        self.assertEqual(sorted(os.listdir(logs)), ["disks_20261107.csv.gz", "events_20261107.jsonl",
                                                    "flight_20261107.csv.gz", "flight_20261108.csv.gz",
                                                    "flight_20261109.csv", "flight_20261110.csv"])
        with gzip.open(os.path.join(logs, "flight_20261108.csv.gz"), "rb") as f:
            self.assertNotIn(b"\x00", f.read())
        self.assertEqual(disks.read_rows(disks.path_for("2026-11-07"))[0][1:], ("C:", 40.5, 465.0))
        c = server.FlightCache().get("flight_20261108.csv")
        self.assertEqual((list(c["cpu_temp_c"]), c["packed"]), ([50.0], True))
        util.prune(logs, "flight_", ".csv", 1)                         # (packed or not, an old day goes)
        self.assertFalse([f for f in os.listdir(logs) if f.startswith("flight_2026110") and f < "flight_20261109"])

    def test_a_cut_off_row_is_ended_before_the_next(self):
        from hwblackbox.util import ensure_line_end
        p = os.path.join(paths.P.logs, "x.csv")
        with open(p, "wb") as f:
            f.write(b"timestamp,a\n2026-11-10T12:00:00,1\n2026-11-10T12:00:05,\x00\x00\x00")
        ensure_line_end(p)
        with open(p, "ab") as f:
            f.write(b"2026-11-10T12:01:00,3\n")
        with open(p, "rb") as f:
            self.assertTrue(f.read().endswith(b"\x00\n2026-11-10T12:01:00,3\n"))

    def test_hardware_and_drive_records_in_words(self):
        from hwblackbox.dashboard.server import describe
        from hwblackbox.events import drive_note, hardware_note
        whea = {"kind": "winevent", "source": "Microsoft-Windows-WHEA-Logger", "id": 19, "level": "warning",
                "inserts": [], "skipped_before": 12}
        d = describe(whea, time.time())
        self.assertEqual((d["level"], d["group"]), ("warn", "hardware"))
        self.assertTrue(d["text"].startswith("A corrected hardware error in the CPU (a machine check) (WHEA 19)"))
        self.assertIn("12 more like it", d["text"])
        self.assertEqual(describe(dict(whea, id=18, level="error"), 0)["level"], "bad")
        self.assertEqual(hardware_note("x", 17, "warning"), "a corrected hardware error in a PCI Express link (WHEA 17)")
        reset = {"kind": "winevent", "source": "stornvme", "id": 129, "level": "warning",
                 "inserts": ["\\Device\\RaidPort0"]}
        self.assertEqual(describe(reset, 0)["text"], "A drive: Windows reset the drive (it had stopped answering) "
                                                     "(stornvme 129)")
        block = {"kind": "winevent", "source": "disk", "id": 7, "level": "error", "inserts": ["\\Device\\Harddisk2\\DR2"]}
        self.assertEqual(describe(block, 0)["level"], "bad")
        self.assertEqual(drive_note(block), "disk 2: a bad block on the drive (part of it can't be read) (disk 7)")
        self.assertIsNone(drive_note({"source": "disk", "id": 999}))

    def test_a_flood_of_records_is_capped(self):
        from hwblackbox import watcher

        class Ev:
            def __init__(self, recs):
                self.recs, self.last = recs, {}

            def new_records(self):
                out, self.recs = self.recs, []
                return out

            def save(self):
                pass
        jr = Recorder()
        w = watcher.Watcher(jr, {"watch": []}, None, None)
        rec = lambda: {"log": "System", "source": "Microsoft-Windows-WHEA-Logger", "id": 17, "level": "warning",   # noqa
                       "at": "2026-11-10T12:00:00-05:00", "inserts": []}
        w.events = Ev([rec() for _ in range(watcher.FLOOD + 5)])
        w.check_events()
        self.assertEqual(sum(1 for r in jr.recs if r["kind"] == "winevent"), watcher.FLOOD)
        self.assertEqual(w.flood_skipped[("Microsoft-Windows-WHEA-Logger", 17)], 5)
        self.assertEqual(w.notes["last_hardware_error"], "2026-11-10 12:00:00: a corrected hardware error in a PCI "
                                                         "Express link (WHEA 17)")

    def test_notifications(self):
        from hwblackbox import notify
        folder = os.path.join(paths.P.sessions, "S-1-5-21-1-2-3-1001")
        os.makedirs(folder)
        sent, now = [], [1000.0]
        n = notify.Notifier(folder, 9070, send=lambda t, b, link: sent.append((t, b, link)), clock=lambda: now[0])
        st = {"problems": [], "attributes": {"last_incident": "2026-11-09 18:54:10: Windows Explorer ended: exit code 1",
                                             "last_hardware_error": None}, "last_dirty_shutdown": {"incident": "a.txt"}}
        self.assertEqual(n.check(st), [])                       # the first look: what's there isn't news
        self.assertEqual(n.check(st), [])
        st["last_dirty_shutdown"] = {"incident": "incident_20261111_080000.txt"}
        st["attributes"]["last_incident"] = "2026-11-11 08:05:00: Discord.exe ended: crash: access violation"
        self.assertEqual(n.check(st), ["The PC went off without shutting down", "Discord.exe ended: crash: access violation"])
        self.assertEqual(sent[0][2], "http://127.0.0.1:9070/#incidents:incident_20261111_080000.txt")
        self.assertEqual(sent[1][1], "At 08:05. Its report is on the Incidents tab.")
        # one of a kind every 10 minutes: a second crash 5 minutes later is passed over (and not told later either)
        now[0] += 300
        st["attributes"]["last_incident"] = "2026-11-11 08:10:00: Discord.exe ended: crash: access violation"
        self.assertEqual(n.check(st), [])
        # a problem is told once it has lasted a minute; this user turned hardware errors off
        notify.save_setting(folder, "hardware", False)
        st["problems"] = ["The sensors aren't logging"]
        st["attributes"]["last_hardware_error"] = "2026-11-11 08:11:00: a corrected hardware error in the CPU (WHEA 19)"
        self.assertEqual(n.check(st), [])
        now[0] += 61
        self.assertEqual(n.check(st), ["HW Blackbox: a problem"])
        self.assertEqual(n.check(st), [])                        # (told once)
        now[0] += 700
        self.assertEqual(n.check(st, status_age=400), [])                            # (no status for minutes...)
        now[0] += 61
        self.assertEqual(n.check(st, status_age=460), ["HW Blackbox: a problem"])     # (... for a minute more)
        self.assertIn("service isn't running", sent[-1][1])
        # what was told survives a restart of the agent
        n2 = notify.Notifier(folder, 9070, send=lambda *a: sent.append(a), clock=lambda: now[0])
        self.assertEqual(n2.check(st), [])
        self.assertEqual(notify.user_settings(folder), {"power_off": True, "crash": True, "hardware": False,
                                                         "problem": True})
        with self.assertRaises(ValueError):
            notify.save_setting(folder, "anything", True)
        with self.assertRaises(ValueError):
            notify.save_setting(folder, "crash", "yes")
        import xml.etree.ElementTree as ET
        x = ET.fromstring(notify.toast_xml("A <b>title</b>", "x & y", "http://127.0.0.1:9070/#a\"b'c"))
        self.assertEqual([t.text for t in x.iter("text")], ["A <b>title</b>", "x & y"])
        self.assertEqual(x.get("launch"), "http://127.0.0.1:9070/#a\"b'c")
        self.assertEqual(x.find("actions/action").get("arguments"), "http://127.0.0.1:9070/#a\"b'c")

    def test_the_page_actions(self):
        import urllib.error
        import urllib.request
        from unittest import mock
        from hwblackbox import notify, winapi
        from hwblackbox.dashboard import server
        os.makedirs(paths.P.session_dir(winapi.token_sid()))
        port = free_port()
        httpd = server.start(port)
        try:
            def post(path, body, site="same-origin", hwb="1"):
                req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), method="POST",
                                             data=json.dumps(body).encode(),
                                             headers={"Sec-Fetch-Site": site, "X-HWB": hwb})
                try:
                    with urllib.request.urlopen(req, timeout=10) as r:
                        return r.status, json.loads(r.read())
                except urllib.error.HTTPError as e:
                    return e.code, None
            self.assertEqual(post("/api/settings/notify", {"kind": "crash", "on": False}, site="cross-site")[0], 403)
            self.assertEqual(post("/api/settings/notify", {"kind": "crash", "on": False}, hwb="0")[0], 403)
            code, r = post("/api/settings/notify", {"kind": "crash", "on": False})
            self.assertEqual((code, r["notify"]["crash"]), (200, False))
            self.assertIn("error", post("/api/settings/notify", {"kind": "crash", "on": "no"})[1])
            self.assertEqual(post("/api/nothing", {})[0], 404)
            with mock.patch.object(notify, "send", return_value=None) as s:
                self.assertEqual(post("/api/notify/test", {})[1], {"ok": True, "error": None})
                self.assertTrue(s.call_args.kwargs.get("wait"))
            # (a copy run from a checkout: the elevated commands aren't offered)
            self.assertIn("isn't the installed", post("/api/homeassistant/setup", {})[1]["error"])
            with urllib.request.urlopen("http://127.0.0.1:%d/api/settings" % port, timeout=10) as r:
                d = json.loads(r.read())
            self.assertEqual((d["notify"]["crash"], d["ha"]["enabled"], d["installed"]), (False, False, False))
            self.assertEqual([k for k, _ in d["kinds"]], list(notify.KINDS))
        finally:
            httpd.shutdown()

    def test_home_assistant_setup(self):
        from unittest import mock
        from hwblackbox import config, homeassistant
        config.write_default()
        answers = iter(["", "http://ha.local:8123", "sensor.my_pc"])
        tokens = iter(["bad token", "abc.def"])
        tried = []

        def try_it(url, token):
            tried.append((url, token))
            return (True, '{"message": "API running."}') if token == "abc.def" else (False, "refused")
        out = []
        with mock.patch.object(homeassistant, "try_it", try_it):
            code = homeassistant.setup(ask=lambda q: next(answers), secret=lambda q: next(tokens), out=out.append)
        self.assertEqual(code, 0)
        self.assertEqual(tried[-1], ("http://ha.local:8123", "abc.def"))
        cfg = json.load(open(paths.P.config))
        self.assertEqual((cfg["home_assistant"]["enabled"], cfg["home_assistant"]["entity"]), (True, "sensor.my_pc"))
        env = homeassistant.read_env(cfg["home_assistant"]["env_file"])
        self.assertEqual(env, {"HA_URL": "http://ha.local:8123", "HA_TOKEN": "abc.def"})
        self.assertFalse(any("abc.def" in line for line in out))              # (the token is never printed)
        code = homeassistant.setup(off=True, ask=lambda q: "y", out=out.append)
        self.assertEqual(code, 0)
        self.assertFalse(json.load(open(paths.P.config))["home_assistant"]["enabled"])
        self.assertFalse(os.path.exists(cfg["home_assistant"]["env_file"]))

    def test_which_program_an_exe_is(self):
        from hwblackbox.winapi import program_of
        cases = {r"C:\Program Files\Mozilla Firefox\firefox.exe": "Mozilla Firefox",
                 r"C:\Users\bob\AppData\Local\Discord\app-1.0.9200\Discord.exe": "Discord",
                 r"C:\Windows\explorer.exe": "Windows",
                 r"G:\LocalCast\.venv\Scripts\python.exe": "LocalCast",
                 r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.21.2361.0_x64__8wekyb3d8bbwe\wt.exe":
                     "Microsoft.WindowsTerminal",
                 "\\\\server\\share\\x.exe": None, "//server/share/x.exe": None, r"C:\a\..\b.exe": None,
                 "python.exe": None, "": None, None: None}
        for path, want in cases.items():
            self.assertEqual(program_of(path), want, path)


if __name__ == "__main__":
    unittest.main()
