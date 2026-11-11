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

--data-dir points all of it at another folder (tests, a second instance)."""
import os

PACKAGE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.dirname(PACKAGE)
LIB = os.path.join(APP, "lib")
DEFAULT_DATA = os.path.join(os.environ.get("ProgramData") or r"C:\ProgramData", "HWBlackbox")


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


P = Paths(os.environ.get("HWBLACKBOX_DATA") or DEFAULT_DATA)


def init(data_dir=None):
    """Point everything at data_dir (None: the default, or HWBLACKBOX_DATA)."""
    global P
    P = Paths(data_dir or os.environ.get("HWBLACKBOX_DATA") or DEFAULT_DATA)
    return P
