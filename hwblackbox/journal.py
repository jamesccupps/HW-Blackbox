"""The records: JSON lines, one file a day."""
import collections
import datetime as dt
import json
import os
import threading
import time

from .util import now_iso, prune


class Journal:
    """prefix_YYYYMMDD.jsonl in `folder`, one record a line: {"ts": local time, "kind": ..., ...}.
    Every record is flushed, and unless hard=False also fsync'd, so the trail up to a hard power-off survives on disk.
    The last records also stay in memory (`ring`), for incident reports. Files older than keep_days are deleted at the
    first record of each day."""

    def __init__(self, folder, prefix, keep_days, ring=4000):
        self.folder = folder
        self.prefix = prefix
        self.keep_days = keep_days
        self.ring = collections.deque(maxlen=ring)
        self.lock = threading.Lock()
        self.day = None
        self.fh = None
        self.errors = 0
        os.makedirs(folder, exist_ok=True)

    def path_for(self, day):
        return os.path.join(self.folder, "%s_%s.jsonl" % (self.prefix, day.strftime("%Y%m%d")))

    def _roll(self):
        day = dt.date.today()
        if day != self.day:
            if self.fh:
                self.fh.close()
            self.fh = open(self.path_for(day), "a", encoding="utf-8")
            self.day = day
            prune(self.folder, self.prefix + "_", ".jsonl", self.keep_days)

    def write(self, kind, payload=None, hard=True):
        rec = {"ts": now_iso(ms=True), "kind": kind}
        rec.update(payload or {})
        line = json.dumps(rec, default=str)
        with self.lock:
            self.ring.append((time.time(), rec))
            try:
                self._roll()
                self.fh.write(line + "\n")
                self.fh.flush()
                if hard:
                    os.fsync(self.fh.fileno())
            except Exception:
                self.errors += 1
        return rec

    def recent(self, seconds):
        cutoff = time.time() - seconds
        with self.lock:
            return [r for t, r in self.ring if t >= cutoff]

    def close(self):
        with self.lock:
            if self.fh:
                try:
                    self.fh.flush()
                    os.fsync(self.fh.fileno())
                    self.fh.close()
                except Exception:
                    pass
                self.fh = None


def read_tail(path, seconds, limit_bytes=2 << 20):
    """Records from the end of a journal file written in the last `seconds` (for another process's journal)."""
    cutoff = time.time() - seconds
    out = []
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - limit_bytes))
            lines = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return out
    for line in lines:
        try:
            rec = json.loads(line)
            t = dt.datetime.fromisoformat(rec["ts"]).timestamp()
        except (ValueError, KeyError, TypeError):
            continue
        if t >= cutoff:
            out.append(rec)
    return out
