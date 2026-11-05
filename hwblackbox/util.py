"""Small helpers every part uses."""
import datetime as dt
import json
import os
import time


def now_iso(ms=False):
    """Local time, ISO, no offset: how every HW Blackbox file writes times."""
    return dt.datetime.now().isoformat(timespec="milliseconds" if ms else "seconds")


def parse_iso(text):
    """A local ISO time as epoch seconds; None if it isn't one."""
    try:
        return dt.datetime.fromisoformat(text).timestamp()
    except (TypeError, ValueError):
        return None


def read_json(path, limit=16 << 20):
    """The file's JSON, or None (missing, unreadable, damaged, or bigger than `limit` bytes)."""
    try:
        with open(path, "rb") as f:
            data = f.read(limit + 1)
        if len(data) > limit:
            return None
        return json.loads(data.decode("utf-8-sig"))         # (a byte-order mark: Notepad, PowerShell 5's utf8)
    except Exception:
        return None


def write_json(path, data, durable=False, indent=None):
    """Write to a temporary file and swap it in, so a reader never sees half a file. durable: fsync first."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, default=str, indent=indent)
        if durable:
            f.flush()
            os.fsync(f.fileno())
    try:
        os.replace(tmp, path)
    except OSError:                     # (the target held open by a reader: next time)
        pass


def age(path):
    """Seconds since the file was last written; None if it isn't there."""
    try:
        return time.time() - os.path.getmtime(path)
    except OSError:
        return None


def prune(folder, prefix, suffix, keep_days):
    """Delete prefixYYYYMMDD...suffix files whose date (in the name) is more than keep_days ago."""
    cutoff = (dt.date.today() - dt.timedelta(days=keep_days)).strftime("%Y%m%d")
    try:
        names = os.listdir(folder)
    except OSError:
        return 0
    gone = 0
    for f in names:
        stamp = f[len(prefix):len(prefix) + 8]
        if f.startswith(prefix) and f.endswith(suffix) and len(stamp) == 8 and stamp.isdigit() and stamp < cutoff:
            try:
                os.remove(os.path.join(folder, f))
                gone += 1
            except OSError:
                pass
    return gone


def tail_lines(path, n, line_guess=200):
    """The last n lines of a text file, read from the end."""
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - line_guess * n - 1024))
            return f.read().replace(b"\x00", b"").decode("utf-8", "replace").splitlines()[-n:]
    except OSError:
        return []


def is_link(path):
    """A junction or a symbolic link (a folder that stands for another path)? The service, as SYSTEM, never writes
    through one, nor reads users' folders through one."""
    try:
        return bool(os.lstat(path).st_file_attributes & 0x400)        # FILE_ATTRIBUTE_REPARSE_POINT
    except (OSError, AttributeError):
        return False


def safe_name(text, n=40):
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in (text or "?"))[:n]


def fmt_dur(seconds):
    s = max(0, int(seconds))
    return "%dh %02dm %02ds" % (s // 3600, s % 3600 // 60, s % 60)
