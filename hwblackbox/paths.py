r"""Where HW Blackbox keeps things.

The program: the folder this package sits in, with the sensor library in lib\ next to it. Installed, that's
C:\Program Files\HWBlackbox\app, which only admins can change.

The data: %ProgramData%\HWBlackbox. Windows (the service, as SYSTEM) and admins write there; everyone can read.
  config.json   the settings
  logs\         flight_YYYYMMDD.csv (every 5 s), rails_YYYYMMDD.csv (4 a second), events_YYYYMMDD.jsonl (the records),
                disks_YYYYMMDD.csv (free space) and programs_YYYYMMDD.csv (each program's use), every minute;
                drives_YYYYMMDD.csv (the drives' health), every hour. The CSVs are packed into .csv.gz once they're
                two days old.
  state\        status.json, sensors.json, ports.json, drives.json, ...: what's true now, rewritten as it changes
  incidents\    a report for every power-off and app crash
  sessions\     one folder per user, sessions\<their SID>, made by the service as they sign in, for that user alone;
                their session agent writes there (users can't make folders here)
  secrets\      the Home Assistant token (admins and SYSTEM only)

--data-dir points all of it at another folder (tests, a second instance).

Windows' own folders come from Windows (the known-folder and system-folder calls), never from environment variables:
a program running as a user can set that user's variables for every program started after (HKCU\Environment),
elevated ones included, and the update, the Home Assistant setup and the installer run elevated from the user's
session. (Until 1.1.3 a variable, HWBLACKBOX_DATA, could even move the data folder: the 2026-11-14 review's H1.)"""
import os

PACKAGE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.dirname(PACKAGE)
LIB = os.path.join(APP, "lib")

PROGRAM_DATA = "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}"     # (FOLDERID_ProgramData)
PROGRAM_FILES = "{905E63B6-C1BF-494E-B29C-65B732D3D21A}"    # (FOLDERID_ProgramFiles)


def known_folder(folder_id, fallback):
    """A Windows known folder's path (SHGetKnownFolderPath), or fallback where Windows can't say."""
    try:
        import ctypes
        import uuid
        from ctypes import wintypes
        guid = (ctypes.c_ubyte * 16).from_buffer_copy(uuid.UUID(folder_id).bytes_le)
        out = ctypes.c_void_p()
        shell = ctypes.WinDLL("shell32")
        shell.SHGetKnownFolderPath.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.HANDLE,
                                               ctypes.POINTER(ctypes.c_void_p)]
        shell.SHGetKnownFolderPath.restype = ctypes.c_long
        hr = shell.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(out))
        try:
            if hr == 0 and out.value:
                return ctypes.wstring_at(out.value)
        finally:
            if out.value:
                ctypes.WinDLL("ole32").CoTaskMemFree(out)
    except Exception:
        pass
    return fallback


def system_dir():
    """C:\\Windows\\System32, from Windows (GetSystemDirectoryW)."""
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(520)
        n = ctypes.WinDLL("kernel32").GetSystemDirectoryW(buf, 520)
        if 0 < n < 520:
            return buf.value
    except Exception:
        pass
    return r"C:\Windows\System32"


DEFAULT_DATA = os.path.join(known_folder(PROGRAM_DATA, r"C:\ProgramData"), "HWBlackbox")


class Paths:
    def __init__(self, data):
        self.data = os.path.abspath(data)
        self.config = os.path.join(self.data, "config.json")
        self.logs = os.path.join(self.data, "logs")
        self.state = os.path.join(self.data, "state")
        self.incidents = os.path.join(self.data, "incidents")
        self.sessions = os.path.join(self.data, "sessions")
        self.secrets = os.path.join(self.data, "secrets")
        # the service's state files
        self.status = os.path.join(self.state, "status.json")
        self.sensors = os.path.join(self.state, "sensors.json")
        self.ports = os.path.join(self.state, "ports.json")
        self.eventpos = os.path.join(self.state, "eventpos.json")
        self.last_incident = os.path.join(self.state, "last_incident.json")
        self.inventory = os.path.join(self.state, "sensor_inventory.json")
        self.hardware = os.path.join(self.state, "hardware.json")
        self.drives = os.path.join(self.state, "drives.json")
        self.crash_log = os.path.join(self.data, "crash.log")

    def session_dir(self, user):
        """A session agent's folder: sessions\\<user>."""
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in (user or "unknown"))[:64]
        return os.path.join(self.sessions, safe)

    def make(self, *names):
        for n in names or ("logs", "state", "incidents"):
            os.makedirs(getattr(self, n), exist_ok=True)


P = Paths(DEFAULT_DATA)


def init(data_dir=None):
    """Point everything at data_dir (None: the default, %ProgramData%\\HWBlackbox)."""
    global P
    P = Paths(data_dir or DEFAULT_DATA)
    return P
