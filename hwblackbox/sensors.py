r"""The sensors: every reading every 5 s, the voltage rails 4 times a second, into crash-safe CSVs.

  logs\flight_YYYYMMDD.csv   every 5 s: the key readings (CPU and GPU temperature, power, load, the rails, memory...)
  logs\rails_YYYYMMDD.csv    4 a second: the +12/+5/+3.3 V rails, Vcore, SoC, and the CPU's power and temperature (its
                             newest reading, taken once a second): the readings that can show a power problem on the
                             way down
  state\sensors.json         every sensor (about 85 on a typical desktop), with its minimum, maximum and average since
                             the service started, for the dashboard

Every row is flushed and fsync'd, so the rows up to a hard power loss survive on disk.

Three lanes, each on a thread of its own: the rails (4 a second), the CPU (once a second) and everything (every 5 s).
The CPU has a lane of its own because reading it takes the reading thread onto each core in turn (LibreHardwareMonitor
reads each core's own registers there), and a core kept busy by a program of higher priority holds that read up for
seconds. On 2026-11-05 a core was kept busy all night (most likely by Windows' desktop compositor), and the rails,
read on the same thread then, slowed to 2 a second; a test with a busy thread of high priority on one core took them
to 0.3 a second. Now the other lanes take the CPU lane's newest reading, and only the CPU's columns wait.

Sources: LibreHardwareMonitorLib (through pythonnet) for the CPU, the board's sensor chip (temperatures, voltages,
fans) and a Corsair digital power supply; NVML for an NVIDIA GPU; Windows for the CPU load and memory. The CPU's and
the board's sensors need ring-0 access, which LibreHardwareMonitor gets through the PawnIO driver: as SYSTEM or an
admin only. Without it there's still the GPU, the CPU load and memory."""
import csv
import datetime as dt
import os
import re
import sys
import threading
import time

from . import paths, winapi
from .util import now_iso, prune, read_json, write_json

COLUMNS = [
    "timestamp", "cpu_temp_c", "cpu_power_w", "vcore_v", "vsoc_v",
    "v12_v", "v5_v", "v33_v", "board_temp_c", "coolant_temp_c",
    "gpu_temp_c", "gpu_power_w", "gpu_util_pct", "gpu_clock_mhz",
    "gpu_vram_mb", "cpu_load_pct", "ram_used_gb", "ram_pct", "fans", "note",
    "battery_pct", "on_ac",              # (1.0.9: a laptop's battery; added last, so a day's earlier rows still read)
]

# The 4-a-second lane: only the channels that move fast enough to matter for a power event, so the row stays small
# (~24 MB a day) and the write stays cheap. (The psu_* columns stay empty without a digital power supply.)
FAST_COLUMNS = [
    "timestamp", "v12_v", "v5_v", "v33_v", "vcore_v", "vsoc_v",
    "cpu_power_w", "cpu_temp_c", "psu_v12_v", "psu_power_w", "psu_temp_c",
]

CPU_INTERVAL = 1.0      # seconds between the CPU lane's reads
FAST_CPU_AGE = 1.5      # the oldest CPU reading a rails row takes (older: its CPU columns stay blank)
SLOW_CPU_AGE = 15.0     # ... and a 5-second row (a CPU lane held up longer leaves them blank: see status)


class LhmBackend:
    """LibreHardwareMonitorLib through pythonnet."""

    # The groups the rails lane reads (the board's sensor chip, a digital power supply), so a sub-second rate costs a
    # fraction of a full sweep. The CPU is read by a lane of its own (CPU_HW).
    FAST_HW = ("Motherboard", "SuperIO", "Psu")
    CPU_HW = ("Cpu",)

    def __init__(self, gpu=False):
        self.computer = None
        self.error = None
        self.gpu = gpu
        self.names = {}                  # hardware key -> its name ("AMD Ryzen 5 5600G", "ITE IT8688E"...)
        # LibreHardwareMonitor isn't thread-safe, and the CPU's power figure is the difference between two reads: the
        # lanes take turns, one device at a time. The CPU has a lock of its own, so a CPU read held up by a busy core
        # holds up nothing else (the CPU and the board's chip don't share anything: each is a driver module of its own,
        # and the buses they use have Windows-wide locks that every monitoring program takes).
        self.lock = threading.Lock()
        self.cpu_lock = threading.Lock()
        try:
            if not os.path.exists(os.path.join(paths.LIB, "LibreHardwareMonitorLib.dll")):
                raise FileNotFoundError("LibreHardwareMonitorLib.dll isn't in %s" % paths.LIB)
            os.environ.setdefault("PYTHONNET_RUNTIME", "netfx")
            if paths.LIB not in sys.path:
                sys.path.insert(0, paths.LIB)
            import clr
            clr.AddReference("LibreHardwareMonitorLib")
            import System
            lib_dir = paths.LIB

            def _resolve(sender, args):
                name = str(args.Name).split(",")[0].strip()
                cand = os.path.join(lib_dir, name + ".dll")
                if os.path.exists(cand):
                    return System.Reflection.Assembly.LoadFile(cand)
                return None

            System.AppDomain.CurrentDomain.AssemblyResolve += System.ResolveEventHandler(_resolve)
            from LibreHardwareMonitor import Hardware
            comp = Hardware.Computer()
            comp.IsCpuEnabled = True
            comp.IsMotherboardEnabled = True
            # Memory comes from Windows; LibreHardwareMonitor's memory group needs an extra SPD assembly for nothing
            # this uses.
            comp.IsMemoryEnabled = False
            # An NVIDIA GPU is read through NVML directly (NvmlBackend): LibreHardwareMonitor's own NVIDIA code has
            # crashed its host process (an access violation in NvmlDeviceGetPowerUsage, which .NET can't catch), and
            # was the slowest part of every sweep. Its GPU code is on only for AMD and Intel GPUs (see Sampler).
            comp.IsGpuEnabled = bool(gpu)
            comp.IsControllerEnabled = True   # fan / pump controllers (Corsair Commander and the like)
            # A laptop's battery: its charge, the rate it charges or drains at, and its wear (the capacity it has
            # left against the one it was made with). No-op without one.
            try:
                comp.IsBatteryEnabled = True
            except AttributeError:
                pass
            # A Corsair digital power supply (RMi/HXi/AXi) reports its own rail voltages, temperature and output over
            # USB: the only reading of the rails at the supply rather than at the far end of the board. No-op
            # without one; iCUE may hold the device, and then its sensors stay absent.
            try:
                comp.IsPsuEnabled = True
            except AttributeError:
                pass
            # The storage group needs DiskInfoToolkit and its dependencies, and crashes on a background thread when
            # any of them is missing.
            comp.IsStorageEnabled = False
            comp.Open()
            self.computer = comp
        except Exception as exc:
            self.error = "%s: %s" % (type(exc).__name__, exc)

    def _read(self, groups=None, skip=()):
        """{(hardware key, sensor_type, sensor_name): value} for every device, or only the top-level devices whose
        type is in `groups`, less those in `skip`. The hardware key is its type ("Cpu", "SuperIO", "GpuAmd"), with
        "#2", "#3"... for a second and third device of the same type (two GPUs), in Windows' order."""
        out = {}
        if self.computer is None:
            return out
        seen = {}

        def walk(hw):
            try:
                hw.Update()
            except Exception:
                return
            kind = str(hw.HardwareType)
            seen[kind] = seen.get(kind, 0) + 1
            key = kind if seen[kind] == 1 else "%s#%d" % (kind, seen[kind])
            try:
                self.names.setdefault(key, str(hw.Name))
            except Exception:
                pass
            for s in hw.Sensors:
                if s.Value is not None:
                    out[(key, str(s.SensorType), str(s.Name))] = float(s.Value)
            for sub in hw.SubHardware:
                walk(sub)

        for hw in self.computer.Hardware:
            kind = str(hw.HardwareType)
            if (groups is None or kind in groups) and kind not in skip:
                with self.cpu_lock if kind in self.CPU_HW else self.lock:
                    walk(hw)
        return out

    def read_all(self, skip=()):
        return self._read(skip=skip)

    def read_fast(self):
        return self._read(self.FAST_HW)

    def read_cpu(self):
        return self._read(self.CPU_HW)


class NvmlBackend:
    """An NVIDIA GPU through NVML (no admin needed).
    A driver update invalidates the handle (the same display reset that makes windows blink): then NVML is dropped
    and attached again on a later read; the GPU columns are blank in between, the rest keeps logging."""

    def __init__(self):
        self.p = None
        self.handle = None
        self.error = None
        self.name = None
        self._init()

    def _init(self):
        try:
            import pynvml
            pynvml.nvmlInit()
            self.p = pynvml
            self.handle = pynvml.nvmlDeviceGetHandleByIndex(0)
            self.error = None
            try:
                n = pynvml.nvmlDeviceGetName(self.handle)
                self.name = n.decode() if isinstance(n, bytes) else str(n)
            except Exception:
                pass
        except Exception as exc:
            self.handle = None
            self.error = "%s: %s" % (type(exc).__name__, exc)

    def read(self):
        if self.handle is None:
            self._init()
            if self.handle is None:
                return {}
        p, h, out = self.p, self.handle, {}
        failed = 0
        for key, fn in (
            ("gpu_temp_c",   lambda: p.nvmlDeviceGetTemperature(h, p.NVML_TEMPERATURE_GPU)),
            ("gpu_power_w",  lambda: round(p.nvmlDeviceGetPowerUsage(h) / 1000.0, 1)),
            ("gpu_util_pct", lambda: p.nvmlDeviceGetUtilizationRates(h).gpu),
            ("gpu_clock_mhz", lambda: p.nvmlDeviceGetClockInfo(h, p.NVML_CLOCK_GRAPHICS)),
            ("gpu_vram_mb",  lambda: round(p.nvmlDeviceGetMemoryInfo(h).used / 1048576)),
            ("gpu_fan_pct",  lambda: p.nvmlDeviceGetFanSpeed(h)),
            ("gpu_mem_clock_mhz", lambda: p.nvmlDeviceGetClockInfo(h, p.NVML_CLOCK_MEM)),
            ("gpu_vram_total_mb", lambda: round(p.nvmlDeviceGetMemoryInfo(h).total / 1048576)),
            ("gpu_power_limit_w", lambda: round(p.nvmlDeviceGetEnforcedPowerLimit(h) / 1000.0, 1)),
            ("gpu_pstate", lambda: p.nvmlDeviceGetPerformanceState(h)),
        ):
            try:
                out[key] = fn()
            except Exception:
                failed += 1
        if failed and not out:
            try:
                p.nvmlShutdown()
            except Exception:
                pass
            self.handle = None
        return out


def _pick(sensors, hw_match, sensor_type, includes, excludes=()):
    for (hw, st, name), val in sensors.items():
        if hw_match and hw_match not in hw:
            continue
        if st != sensor_type:
            continue
        low = name.lower()
        if any(x in low for x in excludes):
            continue
        if any(n in low for n in includes):
            return val
    return None


def _vcore(lhm):
    # The board's own reading first: a CPU's SVI2 sensors can read a flat, made-up value (1.55 V on a Gigabyte B550
    # with a Ryzen 5 5600G)
    v = _pick(lhm, "SuperIO", "Voltage", ("vcore",), ("soc",))
    return v if v is not None else _pick(lhm, "", "Voltage", ("vcore", "core (sv", "cpu core"), ("ncore",))


def _vsoc(lhm):
    v = _pick(lhm, "SuperIO", "Voltage", ("soc",))
    return v if v is not None else _pick(lhm, "", "Voltage", ("soc",))


def _cpu_temp(lhm):
    """The CPU's temperature: AMD's Tctl/Tdie, Intel's package, else the hottest core. (Intel CPUs also list, in °C,
    each core's "Distance to TjMax": how far below its limit it runs, not a temperature, and higher when cooler.)"""
    v = _pick(lhm, "Cpu", "Temperature", ("tctl", "tdie"))
    for name in ("package", "core max"):
        if v is None:
            v = _pick(lhm, "Cpu", "Temperature", (name,), ("distance", "tjmax"))
    if v is None:
        temps = [x for (h, t, n), x in lhm.items() if h == "Cpu" and t == "Temperature" and
                 "distance" not in n.lower() and "tjmax" not in n.lower()]
        v = max(temps) if temps else None
    return v


def _r(v, nd=1):
    return "" if v is None else round(v, nd)


def _temp(v):
    return "" if v is None or v <= 0 or v > 130 else round(v, 1)


GPU_KINDS = ("GpuNvidia", "GpuAmd", "GpuIntel")       # LibreHardwareMonitor's GPU types, the ones preferred first


def nvidia_present():
    """Is there an NVIDIA display adapter? (The display drivers' list in the registry: true even while NVML can't be
    reached, say during a driver update.)"""
    import winreg
    base = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as k:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(k, i)
                except OSError:
                    return False
                i += 1
                try:
                    with winreg.OpenKey(k, sub) as s:
                        if "nvidia" in str(winreg.QueryValueEx(s, "DriverDesc")[0]).lower():
                            return True
                except OSError:
                    continue
    except OSError:
        return False


def gpu_from_lhm(lhm):
    """The 5-second log's GPU columns from LibreHardwareMonitor (an AMD or Intel GPU): the first GPU it lists, a
    discrete maker's before Intel's."""
    for kind in GPU_KINDS:
        mine = {k: v for k, v in lhm.items() if k[0] == kind}
        if mine:
            break
    else:
        return {}
    vram = _pick(mine, kind, "SmallData", ("gpu memory used", "d3d dedicated memory used", "memory used"))
    clock = _pick(mine, kind, "Clock", ("gpu core", "core"))
    out = {"gpu_temp_c": _temp(_pick(mine, kind, "Temperature", ("gpu core", "core", "gpu"))),
           "gpu_power_w": _r(_pick(mine, kind, "Power", ("package", "total", "gpu power", "core"))),
           "gpu_util_pct": _r(_pick(mine, kind, "Load", ("gpu core", "d3d 3d", "core"))),
           "gpu_clock_mhz": "" if clock is None else round(clock),          # (whole MHz and MB, as NVML gives them)
           "gpu_vram_mb": "" if vram is None else round(vram)}
    return {k: v for k, v in out.items() if v != ""}


class Sampler:
    def __init__(self, gpu_mode="auto"):
        import psutil
        self.psutil = psutil
        self.admin = winapi.is_admin()
        self.nvml = NvmlBackend()
        # LibreHardwareMonitor's GPU code: "auto" turns it on only with no NVIDIA GPU (NVML reads that one, and
        # LibreHardwareMonitor's NVIDIA code has crashed its host); true or false force it
        self.lhm_gpu = gpu_mode is True or (gpu_mode == "auto" and self.nvml.handle is None and not nvidia_present())
        self.lhm = LhmBackend(gpu=self.lhm_gpu)
        self.last_nv = {}
        self.ram_total_gb = None
        self.cpu_mark = None             # (time, idle time, total time): the CPU load from the system's own counters
        # Once the CPU lane runs (Sensors._cpu), the other lanes don't read the CPU: they take the lane's newest
        # reading, (time.monotonic(), {(key, type, name): value}), if it's recent enough.
        self.cpu_lane = False
        self.cpu_last = None

    def read_cpu(self):
        """The CPU lane's read: the CPU's sensors, kept for the other lanes."""
        d = self.lhm.read_cpu()
        self.cpu_last = (time.monotonic(), d)
        return d

    def cpu_now(self, max_age):
        """The CPU's sensors for a row: the CPU lane's newest reading if it's at most max_age seconds old (else none:
        blank CPU columns rather than old values passed off as new); without the lane, a read of its own."""
        if not self.cpu_lane:
            return dict(self.read_cpu())
        last = self.cpu_last
        return dict(last[1]) if last and time.monotonic() - last[0] <= max_age else {}

    def cpu_load(self):
        t = self.psutil.cpu_times()
        idle, total = t.idle, sum(t)
        prev, self.cpu_mark = self.cpu_mark, (idle, total)
        if not prev or total <= prev[1]:
            return None
        return round(100.0 * (1 - (idle - prev[0]) / (total - prev[1])), 1)

    def sample(self):
        s = {c: "" for c in COLUMNS}
        s["timestamp"] = now_iso()
        lhm = self.lhm.read_all(skip=LhmBackend.CPU_HW)
        lhm.update(self.cpu_now(SLOW_CPU_AGE))
        if lhm and self.admin:
            # The CPU's own sensors read zeros or made-up values without the ring-0 driver: only trust them elevated.
            s["cpu_temp_c"] = _temp(_cpu_temp(lhm))
            s["cpu_power_w"] = _r(_pick(lhm, "Cpu", "Power", ("package",)))
            s["vcore_v"] = _r(_vcore(lhm), 3)
            s["vsoc_v"] = _r(_vsoc(lhm), 3)
            # Without the driver (PawnIO) LibreHardwareMonitor still gives made-up CPU values (a flat 1.55 V, 0 W) but
            # no temperature: if the temperature didn't read, blank the rest of the CPU too rather than show fakes.
            if s["cpu_temp_c"] == "":
                s["cpu_power_w"] = s["vcore_v"] = s["vsoc_v"] = ""
        if lhm:
            s["v12_v"] = _r(_pick(lhm, "SuperIO", "Voltage", ("+12",)), 3)
            s["v5_v"] = _r(_pick(lhm, "SuperIO", "Voltage", ("+5",), ("5vsb", "standby")), 3)
            s["v33_v"] = _r(_pick(lhm, "SuperIO", "Voltage", ("3vcc", "+3.3"), ("3vsb", "avcc", "vbat", "standby")), 3)
            s["board_temp_c"] = _temp(_pick(lhm, "", "Temperature", ("system",)) or
                                      _pick(lhm, "SuperIO", "Temperature", ("temperature #1",)))
            s["coolant_temp_c"] = _temp(_pick(lhm, "", "Temperature", ("liquid", "coolant", "water")))
            fans = ["%s=%d" % (n, x) for (h, t, n), x in sorted(lhm.items()) if t == "Fan" and x > 0]
            s["fans"] = ";".join(fans)
        nv = self.nvml.read()
        self.last_nv = dict(nv)
        gpu_fan = nv.pop("gpu_fan_pct", None)
        if not nv and self.lhm_gpu and lhm:
            nv = gpu_from_lhm(lhm)
        for k, v in nv.items():
            if k in COLUMNS:
                s[k] = v
        if gpu_fan is not None:
            s["fans"] = ";".join(x for x in (s["fans"], "GPU Fan=%d%%" % gpu_fan) if x)
        load = self.cpu_load()
        s["cpu_load_pct"] = "" if load is None else load
        vm = self.psutil.virtual_memory()
        s["ram_used_gb"] = round((vm.total - vm.available) / 2 ** 30, 2)
        s["ram_pct"] = vm.percent
        self.ram_total_gb = round(vm.total / 2 ** 30, 1)
        try:
            b = self.psutil.sensors_battery()             # (None without a battery)
        except Exception:
            b = None
        if b is not None:
            s["battery_pct"] = round(b.percent, 1)
            s["on_ac"] = "" if b.power_plugged is None else int(b.power_plugged)
        return s, lhm

    def sample_fast(self):
        """The narrow row: rails, Vcore/SoC, CPU package power and temperature (the CPU lane's newest), and a digital
        power supply's own channels. No NVML and no Windows counters: they're most of the cost of a full sample, and
        none of them can show a rail sagging."""
        s = {c: "" for c in FAST_COLUMNS}
        s["timestamp"] = now_iso(ms=True)
        lhm = self.lhm.read_fast()
        if not lhm:
            return s
        lhm.update(self.cpu_now(FAST_CPU_AGE))
        s["v12_v"] = _r(_pick(lhm, "SuperIO", "Voltage", ("+12",)), 3)
        s["v5_v"] = _r(_pick(lhm, "SuperIO", "Voltage", ("+5",), ("5vsb", "standby")), 3)
        s["v33_v"] = _r(_pick(lhm, "SuperIO", "Voltage", ("3vcc", "+3.3"), ("3vsb", "avcc", "vbat", "standby")), 3)
        if self.admin:
            s["cpu_temp_c"] = _temp(_cpu_temp(lhm))
            if s["cpu_temp_c"] != "":
                s["cpu_power_w"] = _r(_pick(lhm, "Cpu", "Power", ("package",)))
                s["vcore_v"] = _r(_vcore(lhm), 3)
                s["vsoc_v"] = _r(_vsoc(lhm), 3)
        s["psu_v12_v"] = _r(_pick(lhm, "Psu", "Voltage", ("+12",)), 3)
        s["psu_power_w"] = _r(_pick(lhm, "Psu", "Power", ("total", "output")))
        s["psu_temp_c"] = _temp(_pick(lhm, "Psu", "Temperature", ("temp",)))
        return s


# every sensor, for the dashboard: state\sensors.json -----------------------------------------------------------

UNITS = {"Temperature": "°C", "Voltage": "V", "Clock": "MHz", "Load": "%", "Fan": "RPM", "Power": "W",
         "Factor": "x", "Data": "GB", "SmallData": "MB", "Throughput": "B/s", "Control": "%", "Level": "%",
         "Frequency": "Hz", "Flow": "L/h", "Current": "A", "Energy": "mWh", "Noise": "dBA", "Humidity": "%"}
GROUPS = {"Cpu": "CPU", "GpuNvidia": "GPU", "GpuAmd": "GPU", "GpuIntel": "GPU", "Motherboard": "Motherboard",
          "SuperIO": "Motherboard", "Psu": "Power supply", "Cooler": "Cooling", "EmbeddedController": "Motherboard",
          "Battery": "Battery"}
TYPE_ORDER = ("Temperature", "Power", "Load", "Clock", "Factor", "Voltage", "Current", "Fan", "Control", "Flow",
              "Level", "Data", "SmallData", "Throughput")
FLAT_AFTER = 60          # samples: a CPU voltage that hasn't moved once in this many isn't a real reading


def _natural(text):
    """'Core #2' before 'Core #10'."""
    return [int(x) if x.isdigit() else x.lower() for x in re.split(r"(\d+)", text)]


class SensorStats:
    """Every sensor's current value and its minimum, maximum and average since the service started."""

    def __init__(self, started):
        self.started = started
        self.stats = {}                  # id -> [min, max, sum, count]
        self.samples = 0

    def entry(self, sid, group, device, st, name, unit, value, nd, note=None):
        value = round(float(value), nd)
        e = self.stats.get(sid)
        if e is None:
            e = self.stats[sid] = [value, value, 0.0, 0]
        e[0], e[1], e[2], e[3] = min(e[0], value), max(e[1], value), e[2] + value, e[3] + 1
        return {"id": sid, "group": group, "device": device, "type": st, "name": name, "unit": unit,
                "value": value, "min": e[0], "max": e[1], "avg": round(e[2] / e[3], nd), "note": note}

    def note(self, sid, hw, st):
        """A CPU-reported voltage that never moves is made up (a real core voltage follows the load every second)."""
        e = self.stats.get(sid)
        if hw == "Cpu" and st == "Voltage" and e and e[3] >= FLAT_AFTER and e[0] == e[1]:
            return "hasn't moved once in %d samples: not a real reading on this PC (the board's own Vcore is)" % e[3]
        return None

    def build(self, sampler, lhm, row):
        self.samples += 1
        out = []
        kind = lambda hw: hw.split("#")[0]                              # noqa: E731 ("GpuAmd#2" is a GpuAmd)
        order = list(GROUPS)
        if lhm:
            for (hw, st, name), v in sorted(lhm.items(), key=lambda kv: (
                    order.index(kind(kv[0][0])) if kind(kv[0][0]) in GROUPS else 99, kv[0][0],
                    TYPE_ORDER.index(kv[0][1]) if kv[0][1] in TYPE_ORDER else 99, _natural(kv[0][2]))):
                if not sampler.admin and not kind(hw).startswith("Gpu"):
                    continue                     # (unelevated, LibreHardwareMonitor's CPU and board values are made up)
                sid = "%s/%s/%s" % (hw, st, name)
                e = self.entry(sid, GROUPS.get(kind(hw), hw), sampler.lhm.names.get(hw, hw), st, name,
                               UNITS.get(st, ""), v, 3 if st == "Voltage" else 1)
                e["note"] = self.note(sid, hw, st)
                out.append(e)
        nv = sampler.last_nv or {}
        gpu = sampler.nvml.name or "GPU"
        for key, st, name, unit in (("gpu_temp_c", "Temperature", "GPU", "°C"),
                                    ("gpu_power_w", "Power", "GPU board power", "W"),
                                    ("gpu_power_limit_w", "Power", "Power limit", "W"),
                                    ("gpu_clock_mhz", "Clock", "Graphics", "MHz"),
                                    ("gpu_mem_clock_mhz", "Clock", "Memory", "MHz"),
                                    ("gpu_util_pct", "Load", "GPU", "%"),
                                    ("gpu_fan_pct", "Fan", "Fan", "%"),
                                    ("gpu_vram_mb", "SmallData", "Memory used", "MB"),
                                    ("gpu_vram_total_mb", "SmallData", "Memory total", "MB"),
                                    ("gpu_pstate", "Level", "Performance state (P0 fastest)", "P")):
            if nv.get(key) is not None:
                out.append(self.entry("Nvml/" + key, "GPU", gpu, st, name, unit, nv[key], 1))
        for key, st, name, unit in (("cpu_load_pct", "Load", "CPU (all threads)", "%"),
                                    ("ram_used_gb", "Data", "Memory used", "GB"),
                                    ("ram_pct", "Load", "Memory", "%")):
            if row.get(key) not in ("", None):
                out.append(self.entry("Psutil/" + key, "System", "Windows", st, name, unit, row[key],
                                      2 if unit == "GB" else 1))
        if sampler.ram_total_gb:
            out.append(self.entry("Psutil/ram_total_gb", "System", "Windows", "Data", "Memory total", "GB",
                                  sampler.ram_total_gb, 1))
        for key, st, name, unit in (("battery_pct", "Level", "Battery charge", "%"),
                                    ("on_ac", "Factor", "Plugged in (1) or on battery (0)", "")):
            if row.get(key) not in ("", None):
                out.append(self.entry("Psutil/" + key, "Battery", "Windows", st, name, unit, row[key], 1))
        return {"ts": row.get("timestamp"), "started": self.started, "samples": self.samples, "admin": sampler.admin,
                # (no NVIDIA GPU: no "Nvml" device, so the page names the GPU LibreHardwareMonitor reads, an Intel one)
                "devices": dict(sampler.lhm.names, **({"Nvml": gpu} if sampler.nvml.handle else {})), "sensors": out}


# crash-safe CSVs -----------------------------------------------------------------------------------------------

class CsvLogger:
    def __init__(self, prefix, columns):
        self.prefix = prefix
        self.columns = columns
        self.day = None
        self.fh = None
        self.writer = None

    def path_for(self, day):
        return os.path.join(paths.P.logs, "%s%s.csv" % (self.prefix, day.replace("-", "")))

    @staticmethod
    def header_of(path):
        """The column names a log file's rows are written under now: its last header row (None: no file, or none).
        Only the last 8 MB are looked through; past that, the first row (at worst, the names are written again)."""
        try:
            with open(path, "rb") as f:
                first = f.readline()
                f.seek(0, 2)
                f.seek(max(0, f.tell() - (8 << 20)))
                tail = f.read()
        except OSError:
            return None
        at = tail.rfind(b"\ntimestamp,")
        line = tail[at + 1:].split(b"\n", 1)[0] if at >= 0 else first
        if not line.startswith(b"timestamp,"):
            return None
        return next(csv.reader([line.decode("utf-8", "replace").strip()]))

    def write(self, row):
        day = row["timestamp"][:10]
        if day != self.day:
            if self.fh:
                self.fh.close()
            path = self.path_for(day)
            head = self.header_of(path)
            self.fh = open(path, "a", newline="", encoding="utf-8")
            self.writer = csv.writer(self.fh)
            # a new file, or a day's file begun by an older version with other columns: the column names (again), and
            # the readers take the rows after them by these
            if head != self.columns:
                self.writer.writerow(self.columns)
            self.day = day
        self.writer.writerow([row.get(c, "") for c in self.columns])
        self.fh.flush()
        os.fsync(self.fh.fileno())

    def close(self):
        if self.fh:
            try:
                self.fh.close()
            except Exception:
                pass
            self.fh = None


class Sensors:
    """The two lanes, each on a thread of its own, and what they report to the service's status."""

    def __init__(self, cfg, jrnl, started):
        self.cfg = cfg["sensors"]
        self.jrnl = jrnl
        self.started = started
        self.lock = threading.Lock()
        self.latest = {}
        self.count = 0
        self.errors = 0
        # time.monotonic() of the last row written: how long ago that was is never thrown by the clock (the rows' own
        # local times repeat an hour when daylight saving ends: on 2026-11-01 that read as "not logging" for an hour)
        self.written = None
        self.fast_count = 0
        self.fast_last = None
        self.fast_mark = None
        self.fast_hz = None
        self.beats = {}                  # lane -> time.monotonic() of its last pass, for the service's supervisor
        self.sampler = None
        self.lhm_count = 0
        self.stats = SensorStats(started)
        self.status_cache = None
        self.board = {}

    def open(self):
        """Open the sensors (slow: a few seconds for LibreHardwareMonitor) and take a first sample."""
        self.sampler = Sampler(gpu_mode=self.cfg.get("lhm_gpu", "auto"))
        row, lhm = self.sampler.sample()
        self.lhm_count = len(lhm)
        self.dump_inventory(lhm)
        try:
            self.board = self.find_board_chip()
        except Exception:
            self.board = {}
        prune(paths.P.logs, "flight_", ".csv", self.cfg["keep_days"])
        prune(paths.P.logs, "rails_", ".csv", self.cfg["rails_keep_days"])
        return row

    def find_board_chip(self):
        """The board's sensor chip, where the rails come from: {"now": its name (None: none found), "before": the chip
        this board had before when none is found now, "portable": a laptop or tablet}. Laptops have no such chip, and
        some desktop boards have one that LibreHardwareMonitor can't read: no rails is no fault there. The chip seen
        is kept in state\\hardware.json, so one that stops answering isn't taken for a board without one."""
        names = self.sampler.lhm.names
        now = next((names[k] for k in sorted(names) if k.split("#")[0] == "SuperIO"), None)
        board = names.get("Motherboard")
        saved = read_json(paths.P.hardware) or {}
        if now and (saved.get("board_chip"), saved.get("board")) != (now, board):
            write_json(paths.P.hardware, {"board": board, "board_chip": now, "seen": now_iso()})
        before = saved.get("board_chip") if not now and board and saved.get("board") == board else None
        return {"now": now, "before": before, "portable": winapi.is_portable()}

    def dump_inventory(self, lhm):
        try:
            write_json(paths.P.inventory, {
                "written": now_iso(), "admin": self.sampler.admin, "lhm_error": self.sampler.lhm.error,
                "nvml_error": self.sampler.nvml.error, "sensor_count": len(lhm),
                "sensors": {"%s | %s | %s" % k: v for k, v in sorted(lhm.items())}}, indent=2)
        except Exception:
            pass

    def start(self, stop):
        if self.sampler.lhm.computer is not None:
            self.sampler.cpu_lane = True             # (open()'s sample read the CPU: the first rows have that)
            threading.Thread(target=self._cpu, args=(stop,), name="cpu", daemon=True).start()
        threading.Thread(target=self._slow, args=(stop,), name="sensors", daemon=True).start()
        if self.rails_on():
            threading.Thread(target=self._fast, args=(stop,), name="rails", daemon=True).start()

    def rails_on(self):
        """The 4-a-second lane needs the board's sensors (elevated): without them its rows would all be empty."""
        s = self.sampler
        return self.cfg["rails_interval_s"] > 0 and bool(s and s.admin and s.lhm.computer)

    def _slow(self, stop):
        interval = self.cfg["interval_s"]
        logger = CsvLogger("flight_", COLUMNS)
        s = self.sampler
        note = "startup HW Blackbox admin=%s lhm=%s nvml=%s" % (
            s.admin, "ok" if s.lhm.computer else (s.lhm.error or "off")[:80],
            "ok" if s.nvml.handle else (s.nvml.error or "off")[:80])
        day = None
        due = time.monotonic()
        while not stop.is_set():
            self.beats["sensors"] = time.monotonic()
            try:
                row, lhm = s.sample()
                row["note"] = note
                note = ""
                logger.write(row)
                try:
                    write_json(paths.P.sensors, self.stats.build(s, lhm, row))      # (never at the CSV's expense)
                except Exception:
                    pass
                with self.lock:
                    self.latest = row
                    self.count += 1
                    self.written = time.monotonic()
                    self.lhm_count = len(lhm)
                if row["timestamp"][:10] != day:
                    if day is not None:           # a new day: the clean-up
                        prune(paths.P.logs, "flight_", ".csv", self.cfg["keep_days"])
                        prune(paths.P.logs, "rails_", ".csv", self.cfg["rails_keep_days"])
                    day = row["timestamp"][:10]
            except Exception as exc:
                with self.lock:
                    self.errors += 1
                try:
                    logger.write({"timestamp": now_iso(), "note": "sampler error: %s" % exc})
                except Exception:
                    pass
            due += interval
            wait = due - time.monotonic()
            if wait < -interval:
                due, wait = time.monotonic(), 0.0
            stop.wait(max(0.0, wait))
        logger.close()

    def _cpu(self, stop):
        """The CPU's sensors once a second, for the other two lanes. Not watched by the service's supervisor: a core
        kept busy by another program can hold this lane up for as long as it likes, and that's no reason for the
        service to end itself. A CPU lane held up for long shows as blank CPU columns and in the status."""
        winapi.raise_thread_priority(highest=True)
        due = time.monotonic()
        while not stop.is_set():
            self.beats["cpu"] = time.monotonic()
            try:
                self.sampler.read_cpu()
            except Exception:
                pass
            due += CPU_INTERVAL
            wait = due - time.monotonic()
            if wait < -CPU_INTERVAL:
                due, wait = time.monotonic(), 0.0
            stop.wait(max(0.0, wait))

    def _fast(self, stop):
        """On its own thread, so a slow read in the 5-second lane can never stall it. It keeps to a schedule: Windows
        rounds every wait up to its 15.6 ms tick, so waiting "the rest of the interval" ran 4 % slow. A late row makes
        the next wait shorter; after a real stall (the sensor lock held, a slow disk) the schedule starts again."""
        winapi.raise_thread_priority(highest=True)
        interval = self.cfg["rails_interval_s"]
        logger = CsvLogger("rails_", FAST_COLUMNS)
        due = time.monotonic()
        while not stop.is_set():
            self.beats["rails"] = time.monotonic()
            try:
                row = self.sampler.sample_fast()
                logger.write(row)
                self.fast_last = row["timestamp"]
                self.fast_count += 1
            except Exception:
                pass
            due += interval
            wait = due - time.monotonic()
            if wait < -interval:
                due, wait = time.monotonic(), 0.0
            stop.wait(max(0.0, wait))
        logger.close()

    def status(self):
        """What the service's status file and Home Assistant get."""
        with self.lock:
            row = dict(self.latest)
            count, errors, written = self.count, self.errors, self.written
        now, rows = time.monotonic(), self.fast_count                # (a clock change can't skew the rate)
        prev, self.fast_mark = self.fast_mark, (now, rows)
        if not self.rails_on():
            self.fast_hz = None
        elif prev and now - prev[0] >= 20:
            self.fast_hz = round((rows - prev[1]) / (now - prev[0]), 2)
        elif prev:
            self.fast_mark = prev                 # (too soon after the last look to measure: keep the older mark)
        s = self.sampler
        cpu_last = s.cpu_last if s and s.cpu_lane else None
        return {"lhm": "ok" if s and s.lhm.computer else ((s.lhm.error if s else None) or "off"),
                "cpu_age_s": None if cpu_last is None else round(now - cpu_last[0], 1),
                "nvml": "ok" if s and s.nvml.handle else ((s.nvml.error if s else None) or "off"),
                "admin": s.admin if s else None, "sensors": self.lhm_count, "last_sample": row.get("timestamp"),
                "last_sample_age_s": None if written is None else round(now - written, 1),
                "rows": count, "errors": errors, "fast_last": self.fast_last, "fast_rows": rows,
                "fast_hz": self.fast_hz, "rails_ok": row.get("v12_v", "") != "",
                "cpu_temp_ok": row.get("cpu_temp_c", "") != "",
                # the driver the CPU's and the board's sensors are read through, and the board's sensor chip
                "driver": winapi.service_state("PawnIO"), "board_chip": self.board.get("now"),
                "board_chip_before": self.board.get("before"), "portable": self.board.get("portable")}
