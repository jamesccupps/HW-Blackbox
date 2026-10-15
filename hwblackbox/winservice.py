"""Running as a Windows service, through the service manager's own API (ctypes: no pythonservice.exe, so the
service is the interpreter itself, and nothing else has to be registered).

ServiceHost(name, app).dispatch() hands the calling thread to the service manager; it returns when the service has
stopped, or False at once when this process wasn't started by the service manager (run by hand). The app gets
  app.run(host)            on the service's own thread: start, call host.running(), return once host.stop is set
  app.control(kind, info)  from the manager, quickly: "stop", "preshutdown" (Windows is shutting down: the last
                           moment to write anything), "session" ((event, session id)), "power" (event), "timechange"
"""
import ctypes
import threading
import traceback
from ctypes import wintypes

adv = ctypes.WinDLL("advapi32", use_last_error=True)

SERVICE_WIN32_OWN_PROCESS = 0x10
STOPPED, START_PENDING, STOP_PENDING, RUNNING = 1, 2, 3, 4
ACCEPT_STOP, ACCEPT_SHUTDOWN, ACCEPT_POWEREVENT, ACCEPT_SESSIONCHANGE = 0x1, 0x4, 0x40, 0x80
ACCEPT_PRESHUTDOWN, ACCEPT_TIMECHANGE = 0x100, 0x200
CONTROL_STOP, CONTROL_INTERROGATE, CONTROL_SHUTDOWN = 1, 4, 5
CONTROL_POWEREVENT, CONTROL_SESSIONCHANGE, CONTROL_PRESHUTDOWN, CONTROL_TIMECHANGE = 0xD, 0xE, 0xF, 0x10
NO_ERROR = 0
ERROR_CALL_NOT_IMPLEMENTED = 120
ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 1063
ERROR_SERVICE_SPECIFIC_ERROR = 1066


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [("dwServiceType", wintypes.DWORD), ("dwCurrentState", wintypes.DWORD),
                ("dwControlsAccepted", wintypes.DWORD), ("dwWin32ExitCode", wintypes.DWORD),
                ("dwServiceSpecificExitCode", wintypes.DWORD), ("dwCheckPoint", wintypes.DWORD),
                ("dwWaitHint", wintypes.DWORD)]


SERVICE_MAIN = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))
HANDLER_EX = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p)


class SERVICE_TABLE_ENTRYW(ctypes.Structure):
    _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpServiceProc", SERVICE_MAIN)]


adv.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(SERVICE_TABLE_ENTRYW)]
adv.RegisterServiceCtrlHandlerExW.argtypes = [wintypes.LPCWSTR, HANDLER_EX, ctypes.c_void_p]
adv.RegisterServiceCtrlHandlerExW.restype = ctypes.c_void_p
adv.SetServiceStatus.argtypes = [ctypes.c_void_p, ctypes.POINTER(SERVICE_STATUS)]


class ServiceHost:
    ACCEPTS = ACCEPT_STOP | ACCEPT_PRESHUTDOWN | ACCEPT_SESSIONCHANGE | ACCEPT_POWEREVENT | ACCEPT_TIMECHANGE

    def __init__(self, name, app, log=None):
        self.name = name
        self.app = app
        self.log = log or (lambda text: None)
        self.handle = None
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.status = SERVICE_STATUS(SERVICE_WIN32_OWN_PROCESS, START_PENDING, 0, 0, 0, 0, 0)
        # (kept on the object: ctypes callbacks must outlive every call into them)
        self._main = SERVICE_MAIN(self._service_main)
        self._handler = HANDLER_EX(self._handler_ex)
        self.exit_code = 0

    def set(self, state, wait_hint=0, specific=0):
        with self.lock:
            s = self.status
            s.dwCurrentState = state
            s.dwControlsAccepted = self.ACCEPTS if state == RUNNING else 0
            s.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR if specific else NO_ERROR
            s.dwServiceSpecificExitCode = specific
            s.dwCheckPoint = 0 if state in (RUNNING, STOPPED) else s.dwCheckPoint + 1
            s.dwWaitHint = wait_hint
            if self.handle:
                adv.SetServiceStatus(self.handle, ctypes.byref(s))

    def running(self):
        self.set(RUNNING)

    def pending(self, wait_hint=10000):
        """Another checkpoint while starting or stopping takes a while."""
        self.set(self.status.dwCurrentState, wait_hint)

    def dispatch(self):
        table = (SERVICE_TABLE_ENTRYW * 2)()
        table[0].lpServiceName = self.name
        table[0].lpServiceProc = self._main
        if adv.StartServiceCtrlDispatcherW(table):
            return True
        err = ctypes.get_last_error()
        if err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
            return False
        raise OSError(err, "StartServiceCtrlDispatcherW")

    def _service_main(self, argc, argv):
        try:
            self.handle = adv.RegisterServiceCtrlHandlerExW(self.name, self._handler, None)
            if not self.handle:
                self.log("RegisterServiceCtrlHandlerExW failed: %d" % ctypes.get_last_error())
                return
            self.set(START_PENDING, 30000)
            try:
                self.app.run(self)
            except BaseException:
                self.exit_code = 1
                self.log("the service failed:\n" + traceback.format_exc())
            # a failure exit code makes the service manager's recovery (restart) kick in
            self.set(STOPPED, specific=self.exit_code)
        except BaseException:
            self.log("ServiceMain:\n" + traceback.format_exc())

    def _handler_ex(self, control, event_type, event_data, context):
        try:
            if control == CONTROL_INTERROGATE:
                return NO_ERROR
            if control in (CONTROL_STOP, CONTROL_PRESHUTDOWN, CONTROL_SHUTDOWN):
                self.set(STOP_PENDING, 20000)
                try:
                    self.app.control("preshutdown" if control == CONTROL_PRESHUTDOWN else "stop", None)
                finally:
                    self.stop.set()
                return NO_ERROR
            if control == CONTROL_SESSIONCHANGE:
                sid = ctypes.c_uint32.from_address(event_data + 4).value if event_data else None
                self.app.control("session", (event_type, sid))         # (WTSSESSION_NOTIFICATION: dwSessionId @4)
                return NO_ERROR
            if control == CONTROL_POWEREVENT:
                self.app.control("power", event_type)
                return NO_ERROR
            if control == CONTROL_TIMECHANGE:
                self.app.control("timechange", None)
                return NO_ERROR
            return ERROR_CALL_NOT_IMPLEMENTED
        except BaseException:
            self.log("control %d:\n%s" % (control, traceback.format_exc()))
            return NO_ERROR


class ConsoleHost:
    """The same contract in a console (testing, or run by hand): Ctrl+C stops it."""

    def __init__(self, app):
        self.app = app
        self.stop = threading.Event()
        self.exit_code = 0

    def running(self):
        pass

    def pending(self, wait_hint=10000):
        pass

    def set(self, *a, **k):
        pass

    def dispatch(self):
        t = threading.Thread(target=self._run, name="service", daemon=True)
        t.start()
        try:
            while t.is_alive():
                t.join(0.5)
        except KeyboardInterrupt:
            self.app.control("stop", None)
            self.stop.set()
            t.join(30)
        return True

    def _run(self):
        try:
            self.app.run(self)
        except BaseException:
            self.exit_code = 1
            traceback.print_exc()
