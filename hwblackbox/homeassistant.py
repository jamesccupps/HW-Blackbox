r"""The status, sent to Home Assistant as one sensor entity (POST /api/states/<entity>): an add-on, off unless it's set
up. `python -m hwblackbox homeassistant` sets it up (as admin: the page's Settings tab starts it), asking for the
address and a token, trying them, and keeping the token in secrets\home_assistant.env (SYSTEM and admins only)."""
import json
import os
import re
import threading
import urllib.error
import urllib.request

from .util import now_iso


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an error, not followed: urllib would send the token on to wherever it points."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


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


def try_it(url, token, timeout=10):
    """(True, Home Assistant's answer) if the address and token work (GET /api/), else (False, why, in words)."""
    try:
        req = urllib.request.Request(url.rstrip("/") + "/api/", headers={"Authorization": "Bearer " + token})
        with OPENER.open(req, timeout=timeout) as r:
            body = r.read(4096).decode("utf-8", "replace")
        return True, body.strip()[:80]
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return False, "Home Assistant refused the token (401): make a new one and paste it whole"
        if 300 <= e.code < 400:
            return False, "Home Assistant redirects (HTTP %d): use the address it sends you to (https?)" % e.code
        return False, "HTTP %d from that address: is it Home Assistant?" % e.code
    except Exception as e:
        return False, "couldn't reach it: %s" % (getattr(e, "reason", None) or e)


def setup(off=False, ask=input, secret=None, out=print):
    """Set up (or with off, turn off) the Home Assistant add-on: the address, a token (tried before it's kept), the
    sensor's name. As admin: config.json and secrets\\ are admins' only. Returns the exit code."""
    import getpass
    from . import config, paths
    from .util import read_json, write_json
    secret = secret or getpass.getpass
    cfg = read_json(paths.P.config)
    if not isinstance(cfg, dict):
        out("No readable %s: is HW Blackbox installed (or run init first)?" % paths.P.config)
        return 1
    ha = cfg.get("home_assistant") if isinstance(cfg.get("home_assistant"), dict) else {}
    defaults = config.defaults()["home_assistant"]
    mine = os.path.join(paths.P.secrets, "home_assistant.env")
    env_file = ha.get("env_file") or mine
    if off:
        ha["enabled"] = False
        cfg["home_assistant"] = ha
        write_json(paths.P.config, cfg, indent=2)
        out("Home Assistant is off: HW Blackbox sends it nothing from now on (within a minute).")
        if os.path.normcase(os.path.abspath(env_file)) == os.path.normcase(mine) and os.path.exists(mine):
            if (ask("Delete the saved token too? [Y/n] ").strip().lower() or "y").startswith("y"):
                os.remove(mine)
                out("Deleted %s. (Revoke the token in Home Assistant too: your profile, Security.)" % mine)
        return 0
    out("HW Blackbox: Home Assistant\n\nThis PC's status goes to your Home Assistant every minute, as one sensor: OK or "
        "a problem, the last power-off, crash and hardware error, and the like. Nothing else leaves the PC.\n")
    try:
        old = read_env(env_file)
    except OSError:
        old = {}
    url_default = old.get("HA_URL") or "http://homeassistant.local:8123"
    for _ in range(3):
        url = (ask("Home Assistant's address [%s]: " % url_default).strip() or url_default).rstrip("/")
        if not re.match(r"^https?://[^\s/]+(:\d+)?(/[^\s]*)?$", url):
            out("  That isn't an address like http://homeassistant.local:8123")
            continue
        out("A long-lived access token: in Home Assistant, your profile -> Security -> Long-lived access tokens -> "
            "Create token.")
        token = secret("Paste it here (it doesn't show)%s: " % (" [Enter: keep the saved one]" if old.get("HA_TOKEN")
                                                                else "")).strip() or old.get("HA_TOKEN", "")
        if not token or any(c.isspace() for c in token):
            out("  No token (or one with spaces in it): try again.")
            continue
        out("Trying them...")
        ok, said = try_it(url, token)
        if ok:
            out("  Home Assistant answered: %s" % said)
            break
        out("  %s" % said)
    else:
        out("\nNothing was changed.")
        return 1
    entity_default = ha.get("entity") or defaults["entity"]
    while True:
        entity = ask("The sensor's name in Home Assistant [%s]: " % entity_default).strip() or entity_default
        if re.match(r"^sensor\.[a-z0-9_]+$", entity):
            break
        out("  It has to look like sensor.my_pc (small letters, digits and _)")
    os.makedirs(paths.P.secrets, exist_ok=True)
    with open(mine, "w", encoding="utf-8") as f:
        f.write("# HW Blackbox's Home Assistant: the address and a long-lived token (SYSTEM and admins only)\n"
                "HA_URL=%s\nHA_TOKEN=%s\n" % (url, token))
    ha.update(enabled=True, env_file=mine, entity=entity, name=ha.get("name") or defaults["name"])
    cfg["home_assistant"] = ha
    write_json(paths.P.config, cfg, indent=2)
    out("\nDone. HW Blackbox sends this PC's status within a minute: in Home Assistant, Developer tools -> States -> %s."
        "\nThe page's Settings tab shows how it's going." % entity)
    return 0


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
            with OPENER.open(req, timeout=10) as r:
                r.read()
            return {"ok": True, "at": at, "error": None}
        except urllib.error.HTTPError as e:
            moved = " (Home Assistant redirects: set HA_URL to the address it sends you to)" if 300 <= e.code < 400 \
                else ""
            return {"ok": False, "at": at, "error": "HTTP %d%s" % (e.code, moved)}
        except FileNotFoundError:
            return {"ok": False, "at": at, "error": "the env file isn't there"}
        except Exception as e:
            return {"ok": False, "at": at, "error": ("%s: %s" % (type(e).__name__, e))[:160]}
