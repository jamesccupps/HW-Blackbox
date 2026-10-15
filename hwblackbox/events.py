"""Windows' own records: crashes, hangs and error reports for any app, display driver resets, low memory, and the
power trail (who asked for a shutdown or restart, power losses, boots and shutdowns)."""
import datetime as dt
import os
import re

import pywintypes
import win32evtlog

from .util import read_json, write_json

# log -> {source: event ids (None: all of them)}
EVENT_SOURCES = {
    "Application": {"Application Error": None, "Application Hang": None, "Windows Error Reporting": None,
                    "Winlogon": {1002}},
    "System": {"Display": {4101}, "Microsoft-Windows-Resource-Exhaustion-Detector": {2004},
               "Application Popup": {26},
               "User32": {1074},                                  # who asked for a shutdown or restart, and why
               "Microsoft-Windows-Kernel-Power": {41},            # rebooted without a clean shutdown
               "EventLog": {6008},                                # "the previous shutdown was unexpected"
               "Microsoft-Windows-Kernel-General": {12, 13},      # Windows started / is shutting down
               "Service Control Manager": {7031, 7034}},          # a service ended unexpectedly (this one too)
}
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
                        at = ev.TimeGenerated.Format("%Y-%m-%dT%H:%M:%S")
                        inserts = [str(x)[:200] for x in (ev.StringInserts or [])][:14]
                        rec = {"log": log, "source": ev.SourceName, "id": eid, "at": at, "inserts": inserts}
                        try:
                            if dt.datetime.strptime(at, "%Y-%m-%dT%H:%M:%S") < self.started:
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
    An indexed query, so it's quick however far back the record is."""
    try:
        q = win32evtlog.EvtQuery(log, win32evtlog.EvtQueryReverseDirection, xpath)
        evs = win32evtlog.EvtNext(q, 1)
        if not evs:
            return None, {}
        xml = win32evtlog.EvtRender(evs[0], win32evtlog.EvtRenderEventXml)
        m = re.search(r"SystemTime=['\"](\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)", xml)
        when = dt.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc).astimezone()
        data = dict(re.findall(r"<Data Name=['\"]([^'\"]+)['\"]>([^<]*)</Data>", xml))
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
