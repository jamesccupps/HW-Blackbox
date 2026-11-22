"""Small helpers every part uses."""
import datetime as dt
import gzip
import json
import os
import re
import threading
import time


def now_iso(ms=False):
    """Local time, ISO, with its offset from UTC ("2026-11-10T18:23:02-05:00"): how every HW Blackbox file writes
    times since 1.1.0. Until then the offset was left out, and the hour that repeats when daylight saving ends (01:00
    to 02:00 twice, on 2026-11-01) couldn't be told apart from the first one."""
    return dt.datetime.now().astimezone().isoformat(timespec="milliseconds" if ms else "seconds")


def parse_iso(text, after=None):
    """An ISO time as epoch seconds; None if it isn't one. A time without an offset (written before 1.1.0) is local
    time; when it falls in the hour that repeats as daylight saving ends, it's taken as the first of the two, unless
    `after` (the row before it) says the log had already passed that: then it's the second."""
    try:
        d = dt.datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    t = d.timestamp()
    if after is not None and d.tzinfo is None and t < after - 60:
        t2 = d.replace(fold=1).timestamp()
        if t2 > t:
            t = t2
    return t


def local_text(t, seconds=True):
    """Epoch seconds as local time in words' format, "2026-11-10 18:23:02" (no offset: for the status's lines and the
    reports' text, which people read)."""
    return dt.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S" if seconds else "%Y-%m-%d %H:%M")


def iso_at(t, ms=False):
    """Epoch seconds as now_iso writes them (local, with the offset of that moment)."""
    return dt.datetime.fromtimestamp(t).astimezone().isoformat(timespec="milliseconds" if ms else "seconds")


# the day logs: logs\<prefix>YYYYMMDD.csv, packed into .csv.gz once they're two days old (see pack_logs) ---------------

def log_path(path):
    """A day's log where it is now: the .csv (or the records' .jsonl), else the .gz it was packed into (else the
    plain file's name)."""
    if os.path.exists(path) or not path.endswith((".csv", ".jsonl")):
        return path
    return path + ".gz" if os.path.exists(path + ".gz") else path


def open_log(path):
    """A day's log for reading as text, packed or not (OSError if neither is there)."""
    path = log_path(path)
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="")
    return open(path, encoding="utf-8", errors="replace", newline="")


def read_log_bytes(path):
    """A whole day's log, packed or not, as bytes (OSError if neither is there)."""
    path = log_path(path)
    if path.endswith(".gz"):
        with gzip.open(path, "rb") as f:
            return f.read()
    with open(path, "rb") as f:
        return f.read()


def pack_logs(folder, prefixes, today=None, done=None, suffix=".csv", older_days=1):
    """Pack the day logs older than yesterday into .csv.gz, about a tenth of the size: a .gz.tmp first, synced to the
    disk, swapped in, and only then the .csv removed, so a power loss at any point leaves one whole copy. (Until 1.2.0
    the packed file wasn't synced: Windows writes a file's data out some seconds later, so a power loss just after
    could leave a short .csv.gz with the .csv already gone.) Today's and yesterday's stay plain: they are still
    written, or read from the end (the rails' last minutes, a power-off's last rows). suffix / older_days: the records
    (.jsonl) are packed too, from 1.2.0, once they're older than the page ever reads (older_days 35). Returns how many
    were packed; `done` (a threading.Event) stops it between files."""
    today = today or dt.date.today()
    cutoff = (today - dt.timedelta(days=older_days)).strftime("%Y%m%d")
    n = 0
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return 0
    for f in names:
        if done is not None and done.is_set():
            break
        prefix = next((p for p in prefixes if f.startswith(p)), None)
        stamp = f[len(prefix):len(prefix) + 8] if prefix else ""
        if not (prefix and f.endswith(suffix) and len(f) == len(prefix) + 8 + len(suffix) and stamp.isdigit() and
                stamp < cutoff):
            continue
        src = os.path.join(folder, f)
        tmp = src + ".gz.tmp"
        try:
            if is_link(src):
                continue
            with open(src, "rb") as fin, open(tmp, "wb") as raw:
                with gzip.GzipFile(filename=f + ".gz", mode="wb", compresslevel=6, fileobj=raw) as fout:
                    for chunk in iter(lambda: fin.read(1 << 20), b""):
                        fout.write(chunk.replace(b"\x00", b""))
                raw.flush()
                os.fsync(raw.fileno())
            os.replace(tmp, src + ".gz")
            os.remove(src)
            n += 1
        except OSError:
            try:
                os.remove(tmp)
            except OSError:
                pass
    return n


def ensure_line_end(path):
    """After a power loss a log can end in half a row (and the zeros Windows fills a cut-off write with): end it with a
    line break before anything more is appended, so the next row isn't glued onto the broken one."""
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            if not size:
                return
            f.seek(max(0, size - 4096))
            tail = f.read().rstrip(b"\x00")
        if tail and not tail.endswith(b"\n"):
            with open(path, "ab") as f:
                f.write(b"\n")
    except OSError:
        pass


def read_json(path, limit=16 << 20, nofollow=False):
    """The file's JSON, or None (missing, unreadable, damaged, or bigger than `limit` bytes). nofollow: a link isn't
    followed (open_no_link)."""
    try:
        with (open_no_link(path) if nofollow else open(path, "rb")) as f:
            data = f.read(limit + 1)
        return json_of(data, limit)
    except Exception:
        return None


def json_of(data, limit=16 << 20):
    """bytes' JSON, or None (damaged, or bigger than `limit`)."""
    try:
        if data is None or len(data) > limit:
            return None
        return json.loads(data.decode("utf-8-sig"))         # (a byte-order mark: Notepad, PowerShell 5's utf8)
    except Exception:
        return None


def open_no_link(path):
    """A file opened for reading (binary) without following a link: OSError when the path itself is a junction or a
    symbolic link, or a folder. For the service reading a user's own folder as SYSTEM: a link there to a share would
    make it sign in to that share as the PC (the 2026-11-14 review's H3); and a check of the path before an open()
    can't hold, since the user can swap the file in between. Opened sharing delete too, so the agent can still swap a
    new file in while it's read."""
    import msvcrt
    import pywintypes
    import win32file
    try:
        h = win32file.CreateFile(path, win32file.GENERIC_READ,
                                 win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE | win32file.FILE_SHARE_DELETE,
                                 None, win32file.OPEN_EXISTING, OPEN_REPARSE_POINT | win32file.FILE_ATTRIBUTE_NORMAL,
                                 None)
    except pywintypes.error as e:
        raise OSError(e.winerror, e.strerror, path)
    try:
        attrs = win32file.GetFileInformationByHandle(h)[0]
        if attrs & (REPARSE_POINT | 0x10):                    # (FILE_ATTRIBUTE_DIRECTORY)
            raise OSError("%s is a link or a folder: not read" % path)
        fd = msvcrt.open_osfhandle(h.Detach(), os.O_RDONLY | getattr(os, "O_BINARY", 0))
    except BaseException:
        h.Close()
        raise
    return os.fdopen(fd, "rb")


REPARSE_POINT = 0x400                  # FILE_ATTRIBUTE_REPARSE_POINT
OPEN_REPARSE_POINT = 0x00200000        # FILE_FLAG_OPEN_REPARSE_POINT


def write_json(path, data, durable=False, indent=None):
    """Write to a temporary file and swap it in, so a reader never sees half a file. durable: fsync first. The
    temporary file is this process's and thread's own (until 1.1.4 every writer used path.tmp, so two writing the same
    file at once could swap in each other's half-written one), and it's never left behind."""
    tmp = "%s.%d-%d.tmp" % (path, os.getpid(), threading.get_ident())
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, default=str, indent=indent)
            if durable:
                f.flush()
                os.fsync(f.fileno())
        try:
            os.replace(tmp, path)
        except OSError:                 # (the target held open by a reader: next time)
            pass
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


# A text a spreadsheet takes for a formula when the file is opened in it: =, +, - or @ first (and a tab or a return,
# which Excel skips). Our CSV logs hold program names and command lines, which their owners choose.
FORMULA_FIRST = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(text):
    """A text for a CSV log: with a ' before it when it would start a formula."""
    return "'" + text if isinstance(text, str) and text.startswith(FORMULA_FIRST) else text


def csv_text(text):
    """A CSV log's text as it was before csv_safe."""
    return text[1:] if isinstance(text, str) and text.startswith("'") and text[1:].startswith(FORMULA_FIRST) else text


def age(path):
    """Seconds since the file was last written; None if it isn't there."""
    try:
        return time.time() - os.path.getmtime(path)
    except OSError:
        return None


JUMP_DAYS = 2           # today more than this many days after the newest day file: the clock may be wrong
DAY_FILE = re.compile(r"^[a-z]+_(\d{8})\.")


def clock_jumped(names, today):
    """Has the date jumped forward? True when the newest day file of the folder before today's (any log's: the
    5-second log is written every few seconds the service runs) is more than JUMP_DAYS older than today. A clock set
    months ahead (Windows' own time seeding has done it, and so does a date typed wrong in the BIOS) would otherwise
    have the clean-up delete every day file at the first record written at the wrong date. A PC that was simply off
    for a while cleans up a day later: by then yesterday's files are there, written at the date that held."""
    stamp = today.strftime("%Y%m%d")
    past = [m.group(1) for m in map(DAY_FILE.match, names) if m and m.group(1) < stamp]
    if not past:
        return False
    try:
        newest = dt.datetime.strptime(max(past), "%Y%m%d").date()
    except ValueError:
        return False
    return (today - newest).days > JUMP_DAYS


def prune(folder, prefix, suffix, keep_days, today=None):
    """Delete prefixYYYYMMDD...suffix files (and their packed .gz) whose date (in the name) is more than keep_days
    ago; nothing while the date has just jumped forward (clock_jumped)."""
    today = today or dt.date.today()
    cutoff = (today - dt.timedelta(days=keep_days)).strftime("%Y%m%d")
    try:
        names = os.listdir(folder)
    except OSError:
        return 0
    if clock_jumped(names, today):
        return 0
    gone = 0
    for f in names:
        stamp = f[len(prefix):len(prefix) + 8]
        if f.startswith(prefix) and f.endswith((suffix, suffix + ".gz")) and len(stamp) == 8 and stamp.isdigit() \
                and stamp < cutoff:
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
