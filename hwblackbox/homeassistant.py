"""The status, sent to Home Assistant as one sensor entity (POST /api/states/<entity>)."""
import json
import threading
import urllib.error
import urllib.request

from .util import now_iso


def read_env(path):
    """KEY=value lines (HA_URL, HA_TOKEN). The token never goes into a log or a record."""
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    return out


class HaReporter:
    """Sends from a thread of its own, so a slow or unreachable Home Assistant never holds anything else up. Only the
    newest status waits to be sent."""

    def __init__(self):
        self.lock = threading.Lock()
        self.job = None
        self.wake = threading.Event()
        self.result = {"ok": None, "at": None, "error": None}
        self.beat = None
        threading.Thread(target=self._run, name="home-assistant", daemon=True).start()

    def submit(self, settings, payload):
        with self.lock:
            self.job = (dict(settings), payload)
        self.wake.set()

    def _run(self):
        while True:
            self.wake.wait()
            self.wake.clear()
            with self.lock:
                job, self.job = self.job, None
            if job:
                self.result = self._post(*job)

    @staticmethod
    def _post(settings, payload):
        at = now_iso()
        try:
            env = read_env(settings["env_file"])
            url, token = env.get("HA_URL", "").rstrip("/"), env.get("HA_TOKEN", "")
            if not url or not token:
                return {"ok": False, "at": at, "error": "no HA_URL / HA_TOKEN in the env file"}
            if not url.startswith(("http://", "https://")):
                return {"ok": False, "at": at, "error": "HA_URL isn't an http(s) address"}
            req = urllib.request.Request(
                "%s/api/states/%s" % (url, settings["entity"]), data=json.dumps(payload, default=str).encode(),
                headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=10) as r:
                r.read()
            return {"ok": True, "at": at, "error": None}
        except urllib.error.HTTPError as e:
            return {"ok": False, "at": at, "error": "HTTP %d" % e.code}
        except FileNotFoundError:
            return {"ok": False, "at": at, "error": "the env file isn't there"}
        except Exception as e:
            return {"ok": False, "at": at, "error": ("%s: %s" % (type(e).__name__, e))[:160]}
