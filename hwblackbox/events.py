"""Windows' own records: crashes, hangs and error reports for any app, display driver resets, low memory, the power
trail (who asked for a shutdown or restart, power losses, boots and shutdowns), and since 1.1.0 the hardware's own
error reports (WHEA) and the drives' errors (bad blocks, retries, controller resets, a damaged file system)."""
import datetime as dt
import os
import re

import pywintypes
import win32evtlog

from .util import read_json, write_json

WHEA = "Microsoft-Windows-WHEA-Logger"
STORAGE_DRIVERS = ("stornvme", "storahci", "secnvme", "iaStorA", "iaStorAC", "iaStorAVC", "iaStorVD", "amd_sata",
                   "amdsata", "nvme")
# log -> {source: event ids (None: all of them)}
EVENT_SOURCES = {
    "Application": {"Application Error": None, "Application Hang": None, "Windows Error Reporting": None,
                    "Winlogon": {1002}},
    "System": dict({"Display": {4101}, "Microsoft-Windows-Resource-Exhaustion-Detector": {2004},
                    "Application Popup": {26},
                    "User32": {1074},                                  # who asked for a shutdown or restart, and why
                    "Microsoft-Windows-Kernel-Power": {41},            # rebooted without a clean shutdown
                    "EventLog": {6008},                                # "the previous shutdown was unexpected"
                    "Microsoft-Windows-Kernel-General": {12, 13},      # Windows started / is shutting down
                    "Service Control Manager": {7031, 7034},           # a service ended unexpectedly (this one too)
                    WHEA: None,                                        # the hardware's own error reports
                    "disk": {7, 11, 51, 153, 154},                     # a drive: bad block, errors, retries
                    "Ntfs": {55, 98, 140}, "Microsoft-Windows-Ntfs": {55, 98, 140}},     # a damaged file system
                   **{d: {9, 11, 129} for d in STORAGE_DRIVERS}),      # a drive's controller reset, or no answer
}
# sources whose records count only as errors and warnings (Ntfs writes "volume is healthy" as information at each boot;
# WHEA's informational records are no fault)
ERRORS_ONLY = {WHEA, "disk", "Ntfs", "Microsoft-Windows-Ntfs"} | set(STORAGE_DRIVERS)
LEVELS = {1: "error", 2: "warning", 4: "information", 8: "audit success", 16: "audit failure"}
BACKFILL_MAX = 5000      # records per log read at start, for the time the service wasn't running


class EventReader:
    """New records of the logs above since the last look, read forwards from the last record number. Where it got to
    is kept in a file, so records written while the service wasn't running (before a reboot) are read at its next
    start, marked "backfill"."""

    def __init__(self, pos_path):
        self.pos_path = pos_path
        self.last = {}
        self.started = dt.datetime.now() - dt.timedelta(seconds=5)
        saved = read_json(pos_path) or {}
        for log in EVENT_SOURCES:
            try:
                h = win32evtlog.OpenEventLog(None, log)
                oldest = win32evtlog.GetOldestEventLogRecord(h)
                newest = oldest + win32evtlog.GetNumberOfEventLogRecords(h) - 1
                win32evtlog.CloseEventLog(h)
                pos = saved.get(log)
                if isinstance(pos, int) and oldest - 1 <= pos <= newest:
                    self.last[log] = max(pos, newest - BACKFILL_MAX)
                else:
                    self.last[log] = newest
            except Exception:
                self.last[log] = None
        self.saved = dict(self.last)

    def save(self):
        if self.last != self.saved:
            write_json(self.pos_path, self.last)
            self.saved = dict(self.last)

    def new_records(self):
        out = []
        for log, sources in EVENT_SOURCES.items():
            last = self.last.get(log)
            if last is None:
                continue
            try:
                h = win32evtlog.OpenEventLog(None, log)
            except Exception:
                continue
            try:
                oldest = win32evtlog.GetOldestEventLogRecord(h)
                newest = oldest + win32evtlog.GetNumberOfEventLogRecords(h) - 1
                if newest < last or last < oldest - 1:  # the log was cleared, or wrapped past us
                    last = oldest - 1
                while last < newest:
                    flags = win32evtlog.EVENTLOG_SEEK_READ | win32evtlog.EVENTLOG_FORWARDS_READ
                    try:
                        batch = win32evtlog.ReadEventLog(h, flags, last + 1)
                    except pywintypes.error:
                        break
                    if not batch:
                        break
                    for ev in batch:
                        last = max(last, ev.RecordNumber)
                        ids = sources.get(ev.SourceName, "no")
                        if ids == "no":
                            continue
                        eid = ev.EventID & 0xFFFF
                        if ids is not None and eid not in ids:
                            continue
                        if ev.SourceName in ERRORS_ONLY and ev.EventType not in (1, 2):
                            continue
                        local = ev.TimeGenerated.Format("%Y-%m-%dT%H:%M:%S")
                        inserts = [str(x)[:200] for x in (ev.StringInserts or [])][:14]
                        rec = {"log": log, "source": ev.SourceName, "id": eid, "at": local, "inserts": inserts,
                               "level": LEVELS.get(ev.EventType, str(ev.EventType))}
                        try:
                            when = dt.datetime.strptime(local, "%Y-%m-%dT%H:%M:%S")
                            rec["at"] = when.astimezone().isoformat(timespec="seconds")      # (with the offset)
                            if when < self.started:
                                rec["backfill"] = True
                        except ValueError:
                            pass
                        out.append(rec)
                self.last[log] = last
            except Exception:
                pass
            finally:
                win32evtlog.CloseEventLog(h)
        return out


def newest_event(log, xpath):
    """The newest record matching xpath, as (local time 'YYYY-MM-DD HH:MM:SS', {data name: value}), or (None, {}).
    The data also has "_id", "_level", "_provider" and "_values" (every data value in order: classic sources' have
    no names). An indexed query, so it's quick however far back the record is."""
    try:
        q = win32evtlog.EvtQuery(log, win32evtlog.EvtQueryReverseDirection, xpath)
        evs = win32evtlog.EvtNext(q, 1)
        if not evs:
            return None, {}
        xml = win32evtlog.EvtRender(evs[0], win32evtlog.EvtRenderEventXml)
        m = re.search(r"SystemTime=['\"](\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)", xml)
        when = dt.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc).astimezone()
        data = dict(re.findall(r"<Data Name=['\"]([^'\"]+)['\"]>([^<]*)</Data>", xml))
        eid, lvl = re.search(r"<EventID[^>]*>(\d+)<", xml), re.search(r"<Level>(\d+)<", xml)
        prov = re.search(r"<Provider Name=['\"]([^'\"]+)['\"]", xml)
        data.update(_id=int(eid.group(1)) if eid else None, _level=int(lvl.group(1)) if lvl else None,
                    _provider=prov.group(1) if prov else None,
                    _values=re.findall(r"<Data(?: Name=['\"][^'\"]*['\"])?>([^<]*)</Data>", xml))
        return when.strftime("%Y-%m-%d %H:%M:%S"), data
    except Exception:
        return None, {}


def describe_1074(at, process, kind, reason):
    return "%s: %s by %s (%s)" % (at, kind or "?", os.path.basename((process or "?").split(" (")[0]), reason or "?")


# Windows Error Reporting files reports about much more than apps (Store and Update failures every few hours); keep
# the ones about an app crashing, hanging or leaking, a driver hiccup (LiveKernelEvent) or a blue screen.
WER_KEEP = ("APPCRASH", "BEX", "BEX64", "MoAppCrash", "MoAppHang", "CLR20r3", "BlueScreen")
WER_KEEP_PREFIX = ("RADAR_PRE_LEAK", "AppHang", "LiveKernelEvent")


def wanted(rec):
    if rec.get("source") != "Windows Error Reporting":
        return True
    ins = rec.get("inserts") or []
    name = ins[2] if len(ins) > 2 else ""
    return name in WER_KEEP or name.startswith(WER_KEEP_PREFIX)


# The hardware's own error reports (WHEA-Logger): which part each record is about, by its event ID (the provider's own
# messages: 16/17 PCI Express, 18/19 the CPU's machine check, 20/21 an AMD CPU's northbridge, 46 to 49 the memory).
# Fatal or corrected is the record's level: an error is fatal (it took Windows down: written at the boot after it), a
# warning was corrected by the hardware (no harm done, but a sign).
WHEA_PART = {16: "PCI Express", 17: "PCI Express", 18: "CPU", 19: "CPU", 20: "CPU", 21: "CPU",
             46: "memory", 47: "memory", 48: "memory", 49: "memory"}
WHEA_WORDS = {"PCI Express": "a PCI Express link (the graphics card, an NVMe drive, or a slot or port of the board)",
              "CPU": "the CPU (a machine check)", "memory": "the memory (RAM)", None: "the hardware"}


def hardware_error(rec):
    """(part, fatal) for a WHEA record (part: "PCI Express", "CPU", "memory" or None), else None."""
    if rec.get("source") != WHEA:
        return None
    return WHEA_PART.get(rec.get("id")), rec.get("level") == "error"


# The drives' error records: what each says, and how bad it is ("bad": data at risk, "warn": a sign).
DISK_EVENTS = {
    ("disk", 7): ("a bad block on the drive (part of it can't be read)", "bad"),
    ("disk", 11): ("the drive's controller reported an error", "warn"),
    ("disk", 51): ("an error reading or writing the page file on the drive", "warn"),
    ("disk", 153): ("a read or write had to be retried (the drive was slow to answer)", "warn"),
    ("disk", 154): ("a read or write failed with a hardware error", "bad"),
    ("Ntfs", 55): ("the file system on a drive is damaged", "bad"),
    ("Ntfs", 98): ("a drive's file system needs checking (chkdsk)", "warn"),
    ("Ntfs", 140): ("Windows couldn't save data to a drive (a write failed)", "warn"),
    ("storage", 9): ("the drive didn't answer in time", "warn"),
    ("storage", 11): ("the drive's controller reported an error", "warn"),
    ("storage", 129): ("Windows reset the drive (it had stopped answering)", "warn"),
}


WHEA_SHORT = {"PCI Express": "a PCI Express link", "CPU": "the CPU", "memory": "the memory", None: "the hardware"}


def hardware_note(source, eid, level):
    """A WHEA record in a few words, for the status: "a corrected hardware error in the CPU (WHEA 19)"."""
    fatal = level in ("error", 1, 2)
    return "a %s hardware error in %s (WHEA %d)" % ("fatal" if fatal else "corrected", WHEA_SHORT[WHEA_PART.get(eid)],
                                                   eid)


def drive_note(rec):
    """A drive's error record in a few words, for the status: "disk 1: Windows reset the drive (...) (stornvme 129)",
    or None."""
    got = disk_error(rec)
    if not got:
        return None
    what, _level, disk = got
    return "%s%s (%s %d)" % ("disk %d: " % disk if disk is not None else "", what, rec.get("source"), rec.get("id"))


DRIVE_QUERY = ("*[System[Provider[%s] and (Level=1 or Level=2 or Level=3) and (%s)]]" % (
    " or ".join("@Name='%s'" % s for s in ("disk", "Ntfs", "Microsoft-Windows-Ntfs") + STORAGE_DRIVERS),
    " or ".join("EventID=%d" % i for i in (7, 9, 11, 51, 55, 98, 129, 140, 153, 154))))
WHEA_QUERY = "*[System[Provider[@Name='%s'] and (Level=1 or Level=2 or Level=3)]]" % WHEA


def disk_error(rec):
    """(what happened, "bad" or "warn", the drive's number or None) for a drive's error record, else None. The drive's
    number is Windows' (\\Device\\Harddisk1 is disk 1: Disk Management's and Get-PhysicalDisk's DeviceId)."""
    src = rec.get("source")
    key = "Ntfs" if src in ("Ntfs", "Microsoft-Windows-Ntfs") else "storage" if src in STORAGE_DRIVERS else src
    got = DISK_EVENTS.get((key, rec.get("id")))
    if not got:
        return None
    m = re.search(r"Harddisk(\d+)", " ".join(rec.get("inserts") or []))
    return got[0], got[1], int(m.group(1)) if m else None


def hardware_records(lo, hi, limit=30):
    """The WHEA records written between lo and hi (epoch seconds), oldest first: [{"at": local time, "id", "fatal",
    "part", "text": Windows' own message, its first lines}]. For the power-off report."""
    out = []
    try:
        span = [dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z") for t in (lo, hi)]
        q = win32evtlog.EvtQuery("System", win32evtlog.EvtQueryForwardDirection,
                                 "*[System[Provider[@Name='%s'] and (Level=1 or Level=2 or Level=3) and "
                                 "TimeCreated[@SystemTime>='%s' and @SystemTime<='%s']]]" % (WHEA, span[0], span[1]))
        try:
            meta = win32evtlog.EvtOpenPublisherMetadata(WHEA)
        except Exception:
            meta = None
        while len(out) < limit:
            evs = win32evtlog.EvtNext(q, 10)
            if not evs:
                break
            for ev in evs:
                xml = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
                m = re.search(r"SystemTime=['\"](\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)", xml)
                eid = re.search(r"<EventID[^>]*>(\d+)<", xml)
                lvl = re.search(r"<Level>(\d+)<", xml)
                if not (m and eid):
                    continue
                when = dt.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc)
                text = ""
                if meta is not None:
                    try:
                        text = win32evtlog.EvtFormatMessage(meta, ev, win32evtlog.EvtFormatMessageEvent)
                    except Exception:
                        text = ""
                lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip() and "details view" not in ln]
                out.append({"at": when.astimezone().strftime("%Y-%m-%d %H:%M:%S"), "id": int(eid.group(1)),
                            "fatal": bool(lvl and lvl.group(1) in ("1", "2")), "part": WHEA_PART.get(int(eid.group(1))),
                            "text": "; ".join(lines[:6])[:400] or "(no message)"})
    except Exception:
        pass
    return out[:limit]


def event_app(rec):
    """The app a crash/hang/report record is about, and whether it is a crash."""
    ins = rec.get("inserts") or []
    src, eid = rec["source"], rec["id"]
    if src in ("Application Error", "Application Hang") and ins:
        return ins[0], src == "Application Error"
    if src == "Windows Error Reporting" and len(ins) > 5:
        # inserts: bucket, type, event name, response, cab id, P1 (app), P2, P3 (version), P4 (module)...
        name = ins[2]
        return ins[5], name in ("APPCRASH", "BEX", "BEX64", "MoAppCrash", "CLR20r3")
    if src == "Winlogon" and eid == 1002:
        return "explorer.exe", True
    if src == "Service Control Manager" and ins:
        return ins[0], False         # (the service's display name; a record, not an incident: some services crash daily)
    return None, False
