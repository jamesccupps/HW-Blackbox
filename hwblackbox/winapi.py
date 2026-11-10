"""What HW Blackbox asks Windows directly, through ctypes: every process in one call, the TCP listeners, the sessions
and who is signed in, priorities, tokens. (x64 only: the structures below are laid out for 64-bit Windows.)"""
import collections
import ctypes
import os
import re
import socket
import struct
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
adv = ctypes.WinDLL("advapi32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")
iphlp = ctypes.WinDLL("iphlpapi")
wts = ctypes.WinDLL("wtsapi32", use_last_error=True)

k32.GetCurrentProcess.restype = wintypes.HANDLE
k32.GetCurrentThread.restype = wintypes.HANDLE
k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]
k32.SetThreadPriority.argtypes = [wintypes.HANDLE, ctypes.c_int]
k32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
k32.WTSGetActiveConsoleSessionId.restype = wintypes.DWORD
k32.GetLongPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
k32.GetLongPathNameW.restype = wintypes.DWORD
ntdll.NtQuerySystemInformation.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong,
                                           ctypes.POINTER(ctypes.c_ulong)]
ntdll.NtQuerySystemInformation.restype = ctypes.c_long
iphlp.GetExtendedTcpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
                                      wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
iphlp.GetExtendedTcpTable.restype = wintypes.DWORD
wts.WTSEnumerateSessionsW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
                                      ctypes.POINTER(wintypes.DWORD)]
wts.WTSQuerySessionInformationW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_int,
                                            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
wts.WTSFreeMemory.argtypes = [ctypes.c_void_p]

ABOVE_NORMAL_PRIORITY_CLASS = 0x8000
THREAD_PRIORITY_ABOVE_NORMAL = 1
THREAD_PRIORITY_HIGHEST = 2
EPOCH_1601 = 11644473600

# every process in one call -----------------------------------------------------------------------------------------

Proc = collections.namedtuple("Proc", "name ppid session created cpu private")


def process_snapshot():
    """{pid: Proc(name, parent pid, session, created (epoch s), CPU time (100 ns units), private bytes)} for every
    process, from one NtQuerySystemInformation(SystemProcessInformation) call, about 10 ms. Asking process by process
    (psutil) takes seconds, and can't open some of them."""
    size = 1 << 20
    while True:
        buf = ctypes.create_string_buffer(size)
        need = ctypes.c_ulong(0)
        st = ntdll.NtQuerySystemInformation(5, buf, size, ctypes.byref(need)) & 0xFFFFFFFF
        if st == 0:
            break
        if st != 0xC0000004 or size > 1 << 27:                    # (STATUS_INFO_LENGTH_MISMATCH: grow and again)
            raise OSError("NtQuerySystemInformation: 0x%08X" % st)
        size = max(size * 2, need.value + 65536)
    out, off = {}, 0
    while True:
        # SYSTEM_PROCESS_INFORMATION (x64): CreateTime @32, UserTime @40, KernelTime @48, ImageName @56 (length) and
        # @64 (buffer), UniqueProcessId @80, InheritedFromUniqueProcessId @88, SessionId @100, PagefileUsage @184
        nxt = struct.unpack_from("<I", buf, off)[0]
        created, user, kernel = struct.unpack_from("<qqq", buf, off + 32)
        nlen, nptr = struct.unpack_from("<H", buf, off + 56)[0], struct.unpack_from("<Q", buf, off + 64)[0]
        pid, ppid = struct.unpack_from("<QQ", buf, off + 80)
        session = struct.unpack_from("<I", buf, off + 100)[0]
        private = struct.unpack_from("<Q", buf, off + 184)[0]
        name = ctypes.wstring_at(nptr, nlen // 2) if nptr and nlen else ("System Idle Process" if pid == 0 else "?")
        out[pid] = Proc(name, ppid, session, created / 1e7 - EPOCH_1601 if created else 0.0, user + kernel, private)
        if not nxt:
            break
        off += nxt
    return out


# the TCP listeners -------------------------------------------------------------------------------------------------

TCP_TABLE_OWNER_PID_LISTENER = 3


def tcp_listeners():
    """{(ip, port): pid} for every listening TCP socket, IPv4 and IPv6, from Windows' own listener table
    (GetExtendedTcpTable with TCP_TABLE_OWNER_PID_LISTENER).
    Not the full table filtered by state, as psutil, netstat and Get-NetTCPConnection do: on some Windows builds
    (seen on Insider build 28120) that state field is garbage. Listeners come back as 0, 1, 2 or 6, and bound
    sockets of outgoing connections as LISTEN, so those tools list the wrong ports. The listener table is right."""
    out = {}
    for family in (socket.AF_INET, socket.AF_INET6):
        size = wintypes.DWORD(0)
        iphlp.GetExtendedTcpTable(None, ctypes.byref(size), False, family, TCP_TABLE_OWNER_PID_LISTENER, 0)
        rc = 0
        for _ in range(4):
            buf = ctypes.create_string_buffer(size.value + 4096)
            size = wintypes.DWORD(len(buf))
            rc = iphlp.GetExtendedTcpTable(buf, ctypes.byref(size), False, family, TCP_TABLE_OWNER_PID_LISTENER, 0)
            if rc != 122:                        # ERROR_INSUFFICIENT_BUFFER: the table grew meanwhile, again
                break
        if rc:
            raise OSError(rc, "GetExtendedTcpTable")
        for i in range(struct.unpack_from("<I", buf, 0)[0]):
            if family == socket.AF_INET:         # MIB_TCPROW_OWNER_PID: state, local addr, port, remote x2, pid
                _st, addr, port, _ra, _rp, pid = struct.unpack_from("<IIIIII", buf, 4 + i * 24)
                ip = socket.inet_ntoa(struct.pack("<I", addr))
            else:                                # MIB_TCP6ROW_OWNER_PID: addr[16], scope, port, remote..., state, pid
                o = 4 + i * 56
                ip = socket.inet_ntop(socket.AF_INET6, buf.raw[o:o + 16])
                port = struct.unpack_from("<I", buf, o + 20)[0]
                pid = struct.unpack_from("<I", buf, o + 52)[0]
            if pid:
                out[(ip, socket.ntohs(port & 0xFFFF))] = pid
    return out


# sessions and users ------------------------------------------------------------------------------------------------

WTS_STATES = {0: "active", 1: "connected", 2: "connecting", 3: "shadowing", 4: "disconnected", 5: "idle",
              6: "listening", 7: "reset", 8: "down", 9: "starting"}


def _wts_text(session, info_class):
    ptr, n = ctypes.c_void_p(), wintypes.DWORD()
    if not wts.WTSQuerySessionInformationW(None, session, info_class, ctypes.byref(ptr), ctypes.byref(n)):
        return None
    try:
        return ctypes.wstring_at(ptr.value) if ptr.value else None
    finally:
        wts.WTSFreeMemory(ptr)


def sessions():
    """[{"id", "state", "user", "station"}] for every Windows session that has a user (signed in, locked or
    disconnected)."""
    ptr, count = ctypes.c_void_p(), wintypes.DWORD()
    if not wts.WTSEnumerateSessionsW(None, 0, 1, ctypes.byref(ptr), ctypes.byref(count)):
        return []
    out = []
    try:
        for i in range(count.value):                # WTS_SESSION_INFOW (x64): SessionId @0, pWinStationName @8, State @16
            base = ptr.value + i * 24
            sid = ctypes.c_uint32.from_address(base).value
            station_p = ctypes.c_void_p.from_address(base + 8).value
            state = ctypes.c_int.from_address(base + 16).value
            user = _wts_text(sid, 5)                # WTSUserName
            if not user:
                continue
            domain = _wts_text(sid, 7) or ""        # WTSDomainName
            out.append({"id": sid, "state": WTS_STATES.get(state, str(state)), "user": user, "domain": domain,
                        "station": ctypes.wstring_at(station_p) if station_p else ""})
    finally:
        wts.WTSFreeMemory(ptr)
    return out


def console_session():
    """The session on the physical screen and keyboard (None if none)."""
    sid = k32.WTSGetActiveConsoleSessionId()
    return None if sid == 0xFFFFFFFF else sid


def session_of(pid=None):
    sid = wintypes.DWORD()
    return sid.value if k32.ProcessIdToSessionId(pid or os.getpid(), ctypes.byref(sid)) else None


def user_name():
    """This process's user name (not the USERNAME variable, which a caller can set)."""
    n = wintypes.DWORD(257)
    buf = ctypes.create_unicode_buffer(257)
    if adv.GetUserNameW(buf, ctypes.byref(n)):
        return buf.value
    return os.environ.get("USERNAME") or "unknown"


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def token_sid():
    """This process's user SID, as text ("S-1-5-18" is SYSTEM)."""
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
    adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    tok = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x0008, ctypes.byref(tok)):
        return None
    try:
        buf = ctypes.create_string_buffer(256)
        n = wintypes.DWORD()
        if not adv.GetTokenInformation(tok, 1, buf, 256, ctypes.byref(n)):     # TokenUser
            return None
        sid = ctypes.c_void_p.from_buffer(buf).value
        out = ctypes.c_void_p()
        if not adv.ConvertSidToStringSidW(sid, ctypes.byref(out)):
            return None
        try:
            return ctypes.wstring_at(out.value)
        finally:
            k32.LocalFree.argtypes = [ctypes.c_void_p]
            k32.LocalFree(out)
    finally:
        k32.CloseHandle(tok)


def is_system():
    return token_sid() == "S-1-5-18"


# this PC --------------------------------------------------------------------------------------------------------------

def service_state(name):
    """A service's or driver's state: "running", "stopped" (or "starting", "stopping"...), "missing" when it isn't
    installed, or None when it can't be told."""
    import pywintypes
    import win32service
    try:
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    except pywintypes.error:
        return None
    try:
        try:
            h = win32service.OpenService(scm, name, win32service.SERVICE_QUERY_STATUS)
        except pywintypes.error as e:
            return "missing" if e.winerror == 1060 else None          # (ERROR_SERVICE_DOES_NOT_EXIST)
        try:
            state = win32service.QueryServiceStatus(h)[1]
        finally:
            win32service.CloseServiceHandle(h)
        return {1: "stopped", 2: "starting", 3: "stopping", 4: "running", 5: "continuing", 6: "pausing",
                7: "paused"}.get(state, "state %d" % state)
    except pywintypes.error:
        return None
    finally:
        win32service.CloseServiceHandle(scm)


def is_portable():
    """A laptop or a tablet: the power profile its firmware gives (mobile or slate). None if it can't be told."""
    try:
        fn = ctypes.windll.powrprof.PowerDeterminePlatformRoleEx
        fn.argtypes, fn.restype = [wintypes.ULONG], wintypes.ULONG
        return fn(2) in (2, 8)              # (POWER_PLATFORM_ROLE_V2: PlatformRoleMobile, PlatformRoleSlate)
    except Exception:
        return None


def long_path(path):
    """The full form of a path written short ("C:\\PROGRA~1\\QGIS34~1.15" -> "C:\\Program Files\\QGIS 3.40.15"); the
    path as it was when that can't be found. Local drives only: never a network path."""
    if not isinstance(path, str) or not re.match(r"^[A-Za-z]:[\\/]", path):
        return path
    buf = ctypes.create_unicode_buffer(1024)
    n = k32.GetLongPathNameW(path, buf, 1024)
    return buf.value if 0 < n < 1024 else path


# folders that say nothing about which program it is
GENERIC = {"bin", "bin64", "bin32", "x64", "x86", "amd64", "win64", "win32", "app", "apps", "current", "scripts",
           "release", "lib", "program", "programs", "exe", "runtime", "local", "roaming", "appdata", "common files",
           "tools", "sbin", "cmd", ".venv", "venv", "env"}


def program_of(path):
    """Which program an exe belongs to, from where it is: "QGIS 3.40.15" for C:\\PROGRA~1\\QGIS34~1.15\\bin\\python.exe
    (a program's own python.exe, not HW Blackbox's or the one people install). None when that can't be told. Only
    ever a local path: a crash record can be written by anyone, under any name, and the service doesn't reach out to
    another PC for one (as SYSTEM, it would be the PC's own account)."""
    if not isinstance(path, str) or not re.match(r"^[A-Za-z]:[\\/]", path) or ".." in path:
        return None
    # Short names (QGIS34~1.15) are looked up only under Program Files, where only admins make folders: elsewhere a
    # user's folder could be a link to another PC, and the look-up would follow it.
    if re.match(r"^[A-Za-z]:[\\/](PROGRA~[12]|Program Files|Program Files \(x86\))[\\/]", path, re.I):
        path = long_path(path)
    parts = [p for p in re.split(r"[\\/]+", path) if p]
    low = [p.lower() for p in parts]
    folders = parts[1:-1]
    if not folders:
        return None
    if low[1] == "windows":
        return "Windows"
    if low[1] in ("program files", "program files (x86)", "programdata") and len(parts) > 3:
        if low[2] == "windowsapps" and len(parts) > 4:
            return parts[3].split("_")[0]                      # (a Store app's package: Publisher.App_1.2.3_x64__id)
        return parts[2] if low[2] not in GENERIC else (parts[3] if len(parts) > 4 else None)
    if "appdata" in low:
        rest = [p for p in folders[low.index("appdata"):] if p.lower() not in GENERIC]
        return rest[0] if rest else None
    for name in reversed(folders):
        if name.lower() not in GENERIC and not re.match(r"^(app-|v)?\d[\d.]*$", name, re.I):
            return name
    return None


# priorities --------------------------------------------------------------------------------------------------------

def raise_process_priority():
    """Above normal: a busy PC is exactly when the monitors must keep up (a job holding every core can starve a
    logger running at normal priority)."""
    return bool(k32.SetPriorityClass(k32.GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS))


def lower_thread_priority():
    """Below normal: for a chore (packing old logs) that must never get in the way of anything."""
    return bool(k32.SetThreadPriority(k32.GetCurrentThread(), -1))       # (THREAD_PRIORITY_BELOW_NORMAL)


def raise_thread_priority(highest=False):
    return bool(k32.SetThreadPriority(k32.GetCurrentThread(),
                                      THREAD_PRIORITY_HIGHEST if highest else THREAD_PRIORITY_ABOVE_NORMAL))
