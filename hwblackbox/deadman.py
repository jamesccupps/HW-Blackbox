"""A dead man's switch: if the service stops checking in, Windows ends it, and the service manager starts it again
(its recovery settings: restart on failure).

A Python thread can't be the one to do it: when the interpreter is wedged (a native call that never returns while
holding the GIL, a deadlock), no Python code runs at all. So it's a thread-pool timer whose callback is
TerminateProcess itself, with this process's pseudo-handle as its argument: no Python involved. The service pushes
the deadline back every few seconds while all its parts are moving.

(The timer calls callback(parameter, TRUE); on x64 that's TerminateProcess(-1 = this process, exit code 1).)"""
import ctypes
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateTimerQueueTimer.argtypes = [ctypes.POINTER(wintypes.HANDLE), wintypes.HANDLE, ctypes.c_void_p,
                                      ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.ULONG]
k32.ChangeTimerQueueTimer.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.ULONG, wintypes.ULONG]
k32.DeleteTimerQueueTimer.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE]
k32.GetModuleHandleW.restype = wintypes.HMODULE
k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [wintypes.HMODULE, ctypes.c_char_p]

WT_EXECUTEINTIMERTHREAD = 0x20
CURRENT_PROCESS = ctypes.c_void_p(0xFFFFFFFFFFFFFFFF)      # (HANDLE)-1
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1)


class DeadMan:
    def __init__(self, timeout_s):
        self.ms = int(timeout_s * 1000)
        self.timer = wintypes.HANDLE()
        fn = k32.GetProcAddress(k32.GetModuleHandleW("kernel32.dll"), b"TerminateProcess")
        if not fn or not k32.CreateTimerQueueTimer(ctypes.byref(self.timer), None, fn, CURRENT_PROCESS, self.ms,
                                                   self.ms, WT_EXECUTEINTIMERTHREAD):
            raise OSError(ctypes.get_last_error(), "CreateTimerQueueTimer")

    def pet(self):
        """Push the deadline back to timeout_s from now."""
        if self.timer:
            k32.ChangeTimerQueueTimer(None, self.timer, self.ms, self.ms)

    def cancel(self):
        """Off for good (a clean stop): waits for a callback in flight, so none can run after this returns."""
        if self.timer:
            k32.DeleteTimerQueueTimer(None, self.timer, INVALID_HANDLE_VALUE)
            self.timer = wintypes.HANDLE()
