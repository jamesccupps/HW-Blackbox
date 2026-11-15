r"""Updates from GitHub.

The page asks GitHub for the latest published release of REPO, at most once a day and when asked ("Check now"), and a
newer one shows at the top of the page. Nothing updates by itself: HW Blackbox runs as SYSTEM, so a new version is
installed only when someone at the PC asks for it and says yes to Windows' admin prompt.

"Update" starts `hwblackbox update` elevated, from the installed program (in Program Files, which only admins can
change). It downloads the release's zip into the data folder's update\ (only SYSTEM and admins can write there, so a
program running as the user can't swap anything between the check and the install), checks it against the SHA-256
GitHub gives for it (and the one in the release notes, which must agree), unpacks it there, checks that its
MANIFEST.json is that version and that its install.ps1 and HWBlackbox.cat are signed by James Cupps (PUBLISHER; every
release from 1.1.1 is), then runs that version's own installer in the same window. The installer keeps the
settings and the history, checks every file against the manifest, and offers the PawnIO driver if it's missing.

What this needs from a release never changes, as every version already out there reads it: the tag vX.Y.Z, published
(not a draft or a pre-release), with the asset HWBlackbox-win64.zip holding HWBlackbox\ as tools\build.py --zip makes
it. GitHub computes every asset's SHA-256 itself; the notes' "SHA-256: `...`" line, when there is one, has to agree."""
import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.request
import zipfile

from . import VERSION, paths
from .util import read_json, write_json

REPO = "jamesccupps/HW-Blackbox"
LATEST = "https://api.github.com/repos/%s/releases/latest" % REPO
ASSET = "HWBlackbox-win64.zip"
DOWNLOADS = "https://github.com/%s/releases/download/" % REPO
MAX_ZIP = 200 << 20              # (the zip is about 25 MB)
# From 1.1.1 a release is signed by James Cupps (Azure Artifact Signing; the certificate's subject starts with this,
# the place follows), and an update installs only a release whose installer and catalog of every file are signed so:
# the installer then checks every file it installs against the catalog. A subject is only a name, which another
# certificate authority could put in a certificate too; Artifact Signing's certificates last three days, so there's no
# certificate to pin, but each carries its signing identity as a key usage that stays the same from one certificate to
# the next (IDENTITY; Slate's certificates from 2026-10-29 to 11-12 all had this one). From 1.1.3 both must match. If
# Azure ever gives the account a new identity, change IDENTITY: the versions before that one then can't update by
# themselves (the package job's check of a signed build fails first, so a signtest shows it).
PUBLISHER = "CN=James Cupps, O=James Cupps"
IDENTITY = "1.3.6.1.4.1.311.97.968698399.443447148.280534441.161049353"
SIGNED = ("install.ps1", "HWBlackbox.cat")
POWERSHELL = os.path.join(paths.system_dir(), "WindowsPowerShell", "v1.0")
CHECK_EVERY = 24 * 3600          # seconds between the page's checks; after a failed one, an hour
RETRY_AFTER = 3600


def parse_version(s):
    """(1, 0, 10) from "v1.0.10" or "1.0" (build metadata after + ignored); None for anything else, a pre-release
    ("1.1.0-beta") included: those are never offered."""
    m = re.fullmatch(r"[vV]?(\d+)\.(\d+)(?:\.(\d+))?", str(s or "").strip().split("+")[0])
    return tuple(int(x or 0) for x in m.groups()) if m else None


def fmt(v):
    return "%d.%d.%d" % v


def current():
    return parse_version(VERSION) or (0, 0, 0)


def _open(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": "HW-Blackbox/" + VERSION,
                                               "Accept": "application/vnd.github+json"})
    return urllib.request.urlopen(req, timeout=timeout)


def latest_release(timeout=20):
    """GitHub's latest published release of REPO (drafts and pre-releases are never "latest")."""
    with _open(LATEST, timeout) as r:
        return json.loads(r.read(4 << 20).decode("utf-8"))


def offer(rel, cur):
    """What a release offers a PC on version `cur`: {"version", "tag", "page", "published", "zip_url", "size",
    "sha256", "notes"}, or None when it's no newer. ValueError when it's newer but can't be installed safely (no zip,
    no SHA-256, two that disagree, a download from somewhere else)."""
    if not isinstance(rel, dict) or rel.get("draft") or rel.get("prerelease"):
        return None
    tag = rel.get("tag_name")
    v = parse_version(tag)
    if v is None or v <= cur:
        return None
    asset = next((a for a in rel.get("assets") or [] if isinstance(a, dict) and a.get("name") == ASSET), None)
    if asset is None:
        raise ValueError("release %s has no %s" % (tag, ASSET))
    url = str(asset.get("browser_download_url") or "")
    if not url.startswith(DOWNLOADS):
        raise ValueError("release %s's %s isn't a download from %s" % (tag, ASSET, REPO))
    digest = str(asset.get("digest") or "").lower()
    sha = digest[7:] if digest.startswith("sha256:") else None
    m = re.search(r"SHA-256:\s*`([0-9a-fA-F]{64})`", str(rel.get("body") or ""))
    noted = m.group(1).lower() if m else None
    if sha and noted and sha != noted:
        raise ValueError("release %s: GitHub's SHA-256 for %s isn't the one in its notes" % (tag, ASSET))
    sha = sha or noted
    if not sha or not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise ValueError("release %s gives no SHA-256 for %s" % (tag, ASSET))
    size = asset.get("size")
    if not isinstance(size, int) or not 0 < size <= MAX_ZIP:
        raise ValueError("release %s's %s has an odd size (%r)" % (tag, ASSET, size))
    page = str(rel.get("html_url") or "")
    return {"version": fmt(v), "tag": tag, "page": page if page.startswith("https://github.com/%s/" % REPO) else None,
            "published": rel.get("published_at"), "zip_url": url, "size": size, "sha256": sha,
            "notes": str(rel.get("body") or "")[:20000]}


# the page's check (in the session agent, as the user) --------------------------------------------------------------

class Checker:
    """GitHub at most once a day (an hour after a failed look), or now when asked, in the background: the page never
    waits for it. The result is kept in the user's session folder, so a restart doesn't ask again."""

    def __init__(self, path=None):
        self.path = path
        self.lock = threading.Lock()
        self.state = (read_json(path) if path else None) or {}
        self.busy = False

    def view(self, enabled=True, now=False):
        """The state for the page. enabled: the daily look (config.json's updates.check); now: look now (a click on
        "check now", which counts even with the daily look off)."""
        with self.lock:
            st = dict(self.state)
            age = time.time() - (st.get("checked") or 0)
            due = now or (enabled and (age > CHECK_EVERY or (st.get("error") and age > RETRY_AFTER)))
            if due and not self.busy:
                self.busy = True
                threading.Thread(target=self._check, name="update-check", daemon=True).start()
            busy = self.busy
        off = st.get("offer")
        if off and (parse_version(off.get("version")) or (0, 0, 0)) <= current():
            off = None                   # (offered before this version was installed)
        return {"enabled": enabled, "current": VERSION, "checking": busy, "checked": st.get("checked"),
                "latest": st.get("latest"), "offer": off, "error": st.get("error")}

    def _check(self):
        try:
            rel = latest_release()
            new = {"checked": time.time(), "latest": str(rel.get("tag_name") or "").lstrip("vV") or None,
                   "offer": offer(rel, current()), "error": None}
        except Exception as e:
            new = dict(self.state, checked=time.time(), error="%s: %s" % (type(e).__name__, e))
        with self.lock:
            self.state = new
            self.busy = False
        if self.path:
            try:
                write_json(self.path, new)
            except Exception:
                pass


def installed_python():
    """The installed program's python.exe, when this is the installed program (Program Files\\HWBlackbox); else None:
    a copy run from elsewhere (a build, a checkout) isn't what an update would replace."""
    root = os.path.join(paths.known_folder(paths.PROGRAM_FILES, r"C:\Program Files"), "HWBlackbox")
    py = os.path.join(root, "python", "python.exe")
    here = os.path.normcase(os.path.abspath(paths.APP))
    if here != os.path.normcase(os.path.join(root, "app")) or not os.path.isfile(py):
        return None
    return py


def launch():
    """The page's "Update": the installed updater, elevated. Returns {"started": True} or {"error": ...}."""
    return launch_elevated("update", "the update", "update it with the new version's Setup.exe")


# the commands the page may start elevated (fixed: nothing from a request goes into one)
ELEVATED = {"update": "update", "homeassistant": "homeassistant", "homeassistant-off": "homeassistant --off"}


def launch_elevated(name, what, otherwise):
    """One of HW Blackbox's own commands (ELEVATED[name]), from the installed program, in a window of its own, as
    admin. Windows asks for an admin first (through PowerShell, so the prompt names Microsoft's PowerShell, a
    publisher people know, rather than Python). Returns {"started": True} or {"error": ...}."""
    import ctypes
    from ctypes import wintypes
    py = installed_python()
    if py is None:
        return {"error": "This isn't the installed HW Blackbox (it runs from %s): %s" % (paths.APP, otherwise)}
    ps = os.path.join(POWERSHELL, "powershell.exe")
    params = "-NoProfile -ExecutionPolicy Bypass -Command \"& '%s' -m hwblackbox %s; exit $LASTEXITCODE\"" % (
        py.replace("'", "''"), ELEVATED[name])

    class SEI(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND),
                    ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                    ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                    ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                    ("dwHotKey", wintypes.DWORD), ("hIcon", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]
    sei = SEI(cbSize=ctypes.sizeof(SEI), fMask=0x00000100 | 0x00000400,     # (NOASYNC, FLAG_NO_UI)
              lpVerb="runas", lpFile=ps, lpParameters=params, nShow=1)
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.ShellExecuteExW.argtypes = [ctypes.POINTER(SEI)]
    if shell.ShellExecuteExW(ctypes.byref(sei)):
        return {"started": True}
    err = ctypes.get_last_error()
    if err == 1223:                                      # ERROR_CANCELLED: no to the admin prompt
        return {"error": "Windows didn't get admin rights, so nothing changed"}
    return {"error": "Windows couldn't start %s (error %d)" % (what, err)}


# the update itself (elevated, from the installed program) ------------------------------------------------------------

def _is_link(p):
    return os.path.islink(p) or (hasattr(os.path, "isjunction") and os.path.isjunction(p))


ADMINS_ONLY = "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"


def _admins_folder(path):
    """path made again, empty, for SYSTEM and the administrators only, in a folder of theirs (the data folder): the
    real update's staging folder. Anything there before goes, a link without being followed. Until 1.1.3 the folder
    was kept as found, which was safe only while the data folder's own permissions were right: a folder a user had
    made there first, or a data folder elsewhere (the 2026-11-14 review's H1), would have let a program running as the
    user rewrite the release between its checks and the install."""
    import win32file
    import win32security
    from .agents import ADMINS, SYSTEM, owner_of
    parent = os.path.dirname(os.path.abspath(path))
    if _is_link(parent) or owner_of(parent) not in (SYSTEM, ADMINS):
        raise ValueError("%s isn't HW Blackbox's own data folder (made by SYSTEM or the administrators)" % parent)
    if _is_link(path):
        os.unlink(path) if os.path.islink(path) else os.rmdir(path)
    elif os.path.lexists(path):
        shutil.rmtree(path)               # (it doesn't go into links: Python 3.12 removes a junction it meets)
    sa = win32security.SECURITY_ATTRIBUTES()
    sa.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(ADMINS_ONLY, 1)
    win32file.CreateDirectory(path, sa)
    if _is_link(path) or owner_of(path) not in (SYSTEM, ADMINS):
        raise ValueError("%s isn't the administrators' after making it" % path)


def _fresh_dir(path):
    """An empty folder at path (what was in it removed; links removed, never followed)."""
    if _is_link(path):
        os.unlink(path) if os.path.islink(path) else os.rmdir(path)
    os.makedirs(path, exist_ok=True)
    for name in os.listdir(path):
        p = os.path.join(path, name)
        if _is_link(p):
            os.unlink(p) if os.path.islink(p) else os.rmdir(p)
        elif os.path.isdir(p):
            shutil.rmtree(p)
        else:
            os.remove(p)


def download(off, dest, out=print):
    """The release's zip into dest, checked against its SHA-256 (and size) as it comes; deleted if it doesn't match."""
    h, n = hashlib.sha256(), 0
    try:
        with _open(off["zip_url"], 120) as r, open(dest, "wb") as f:
            last = 0
            while True:
                b = r.read(1 << 20)
                if not b:
                    break
                n += len(b)
                if n > off["size"]:
                    raise ValueError("the download is bigger than the release says (%d bytes)" % off["size"])
                h.update(b)
                f.write(b)
                if n - last >= 5 << 20:
                    out("  %d of %d MB" % (n >> 20, off["size"] >> 20))
                    last = n
        if n != off["size"]:
            raise ValueError("the download stopped at %d of %d bytes" % (n, off["size"]))
        if h.hexdigest() != off["sha256"]:
            raise ValueError("the download's SHA-256 isn't the release's: not installing it")
    except BaseException:
        try:
            os.remove(dest)
        except OSError:
            pass
        raise
    return h.hexdigest()


def unpack(zpath, dest):
    """The zip into dest, refusing any name that would land outside it, and anything not under HWBlackbox\\."""
    with zipfile.ZipFile(zpath) as z:
        for info in z.infolist():
            name = info.filename.replace("\\", "/")
            parts = [p for p in name.split("/") if p not in ("", ".")]
            if name.startswith("/") or ":" in name or ".." in parts or not parts or parts[0] != "HWBlackbox":
                raise ValueError("the zip has a file that doesn't belong: %r" % info.filename)
        z.extractall(dest)
    return os.path.join(dest, "HWBlackbox")


def stage(off, staging, out=print, from_zip=None, protect=False):
    """Download (or take from_zip), check, unpack and check the manifest: the folder to install from. protect (the real
    update): staging made again for SYSTEM and the administrators only (_admins_folder)."""
    _admins_folder(staging) if protect else _fresh_dir(staging)
    zpath = os.path.join(staging, "HWBlackbox-%s-win64.zip" % off["version"])
    if from_zip:
        out("taking %s" % from_zip)
        h = hashlib.sha256()
        with open(from_zip, "rb") as src, open(zpath, "wb") as dst:
            for b in iter(lambda: src.read(1 << 20), b""):
                h.update(b)
                dst.write(b)
        if h.hexdigest() != off["sha256"]:
            os.remove(zpath)
            raise ValueError("the zip's SHA-256 isn't the one given: not installing it")
    else:
        out("downloading %s (%d MB)" % (off["zip_url"], off["size"] >> 20))
        download(off, zpath, out)
    out("SHA-256 %s: as the release says" % off["sha256"])
    build = unpack(zpath, os.path.join(staging, off["version"]))
    man = read_json(os.path.join(build, "MANIFEST.json")) or {}
    if man.get("version") != off["version"]:
        raise ValueError("the zip holds HW Blackbox %s, not %s" % (man.get("version"), off["version"]))
    if not os.path.isfile(os.path.join(build, "install.ps1")):
        raise ValueError("the zip has no install.ps1")
    out("unpacked HW Blackbox %s (%s files) into %s" % (man["version"], man.get("files"), build))
    check_signed(build)
    out("signed by James Cupps: its installer, and the catalog it checks every file against")
    return build


def signatures(files):
    """[(status, signer's subject, [the certificate's key usages])] for each file: Windows PowerShell's
    Get-AuthenticodeSignature, with its own modules (the paths in an environment variable, never in the command)."""
    script = ("[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
              "foreach ($p in $env:HWB_FILES.Split('|')) { $s = Get-AuthenticodeSignature -LiteralPath $p; $who = ''; "
              "$eku = ''; if ($s.SignerCertificate) { $who = $s.SignerCertificate.Subject; "
              "$eku = (@($s.SignerCertificate.EnhancedKeyUsageList) | ForEach-Object { $_.ObjectId }) -join ',' }; "
              "[string]$s.Status + '|' + $eku + '|' + $who }")
    env = dict(os.environ, HWB_FILES="|".join(files), PSModulePath=os.path.join(POWERSHELL, "Modules"))
    r = subprocess.run([os.path.join(POWERSHELL, "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", script],
                       env=env, capture_output=True, timeout=120, creationflags=0x08000000)    # (CREATE_NO_WINDOW)
    got = []
    for ln in r.stdout.decode("utf-8", "replace").splitlines():
        if ln.count("|") >= 2:
            status, eku, who = ln.split("|", 2)
            got.append((status, who, [x for x in eku.split(",") if x]))
    if len(got) != len(files):
        raise ValueError("Windows couldn't check the release's signatures: %s"
                         % (r.stderr.decode("utf-8", "replace").strip()[-200:] or "no answer"))
    return got


def check_signed(build):
    """The release's installer and catalog signed by PUBLISHER, with its signing identity (IDENTITY), or ValueError."""
    files = [os.path.join(build, name) for name in SIGNED]
    for name, path in zip(SIGNED, files):
        if not os.path.isfile(path) or _is_link(path):
            raise ValueError("the zip has no %s, so it isn't a signed release: not installing it" % name)
    for name, (status, who, ekus) in zip(SIGNED, signatures(files)):
        if status != "Valid" or not (who == PUBLISHER or who.startswith(PUBLISHER + ",")):
            raise ValueError("its %s isn't signed by James Cupps (%s%s): not installing it"
                             % (name, status, ", by " + who if who and status == "Valid" else ""))
        if IDENTITY not in ekus:
            raise ValueError("its %s is signed in James Cupps's name, but not with James Cupps's signing identity: "
                             "not installing it" % name)


def install_script(build, staging, version):
    """A .cmd that runs the new version's installer in this window and removes the download and the unpacked copy
    (~85 MB; the report stays). Done, the window closes by itself after 15 seconds (2026-11-06: waiting for a key, it
    sat open for minutes, unnoticed); with problems it stays open until a key, so they can be read."""
    report = os.path.join(staging, "install-report.txt")
    cmd = os.path.join(staging, "run-install.cmd")
    with open(cmd, "w", encoding="ascii", newline="\r\n") as f:
        f.write("@echo off\ntitle HW Blackbox: updating to %s\n" % version)
        # (Windows PowerShell's own modules, for the installer's catalog check: PowerShell 7's don't load in it)
        f.write('set "PSModulePath=%s"\n' % os.path.join(POWERSHELL, "Modules"))
        # (programs by their full path: cmd looks in the current folder, then PATH, for a bare name)
        f.write('"%s" -NoProfile -ExecutionPolicy Bypass -File "%s" -Report "%s"\n'
                % (os.path.join(POWERSHELL, "powershell.exe"), os.path.join(build, "install.ps1"), report))
        f.write("set rc=%errorlevel%\n")
        f.write('rmdir /s /q "%s"\n' % os.path.dirname(build))
        f.write('del /q "%s"\n' % os.path.join(staging, "HWBlackbox-%s-win64.zip" % version))
        f.write("echo.\n")
        f.write('if "%%rc%%"=="0" (\n  echo Done: HW Blackbox %s is installed. This window closes in 15 seconds, or press a key.\n'
                '  "%s" /t 15 >nul\n  exit /b 0\n)\n' % (version, os.path.join(paths.system_dir(), "timeout.exe")))
        f.write("echo The installer had problems (exit %%rc%%): see above, or its report: %s\npause\n" % report)
    return cmd


def run(dry_run=False, pretend=None, from_zip=None, sha256=None, staging=None, out=print, wait=None):
    """`hwblackbox update`: the newest release, checked and installed. dry_run: everything but the install (and
    without admin rights); pretend: be this version (to try it against the current release). from_zip with sha256:
    a zip on this PC instead of the download. wait: called before returning without starting the installer (the
    update's window would otherwise close before anyone could read why). Returns the exit code."""
    code = _run(dry_run, pretend, from_zip, sha256, staging, out)
    if code != "started" and wait:
        wait()
    return 0 if code == "started" else code


def no_quick_edit():
    """QuickEdit off for this window: a click in it starts selecting text, and while it selects, whatever writes to it
    waits (2026-11-06: the update's installer sat at its last step, the title "Select ...", until it was closed). The
    installer turns it off too; this covers the download before it."""
    try:
        import ctypes
        k = ctypes.windll.kernel32
        k.GetStdHandle.restype = ctypes.c_void_p
        h = ctypes.c_void_p(k.GetStdHandle(-10))
        mode = ctypes.c_uint32()
        if k.GetConsoleMode(h, ctypes.byref(mode)):
            k.SetConsoleMode(h, ctypes.c_uint32((mode.value | 0x80) & ~0x40))
    except Exception:
        pass


def _run(dry_run, pretend, from_zip, sha256, staging, out):
    from . import winapi
    if not dry_run:
        no_quick_edit()
    cur = parse_version(pretend) if pretend else current()
    if cur is None:
        out("not a version: %r" % pretend)
        return 2
    if not dry_run and not winapi.is_admin():
        out("Updating needs admin rights: the page's Update button asks Windows for them.")
        return 1
    try:
        if from_zip:
            if not sha256 or not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
                out("--from-zip needs --sha256 (the zip's, 64 hex digits)")
                return 2
            with zipfile.ZipFile(from_zip) as z:
                man = json.loads(z.read("HWBlackbox/MANIFEST.json").decode("utf-8-sig"))
            off = {"version": man["version"], "zip_url": None, "size": os.path.getsize(from_zip),
                   "sha256": sha256.lower()}
        else:
            out("HW Blackbox %s: asking GitHub for the latest release" % fmt(cur))
            off = offer(latest_release(), cur)
            if off is None:
                out("This is the newest version.")
                return 0
            out("HW Blackbox %s is out (%s)" % (off["version"], off.get("page") or off["tag"]))
        staging = staging or os.path.join(paths.P.data, "update")
        build = stage(off, staging, out, from_zip=from_zip, protect=not dry_run)
        cmd = install_script(build, staging, off["version"])
    except Exception as e:
        out("The update stopped: %s: %s" % (type(e).__name__, e))
        out("Nothing was installed; HW Blackbox %s keeps running." % VERSION)
        return 1
    if dry_run:
        out("dry run: would run %s" % cmd)
        return 0
    out("starting the installer of %s (it stops HW Blackbox, installs, and starts it again)" % off["version"])
    # (in this window, after this process has ended: the installer replaces the program this runs from)
    subprocess.Popen([os.path.join(paths.system_dir(), "cmd.exe"), "/c", cmd], cwd=staging)
    return "started"
