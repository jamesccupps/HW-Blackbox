"""HW Blackbox: a hardware monitor and a black box for a Windows PC.

Three parts, one install:
  the service   (Windows service "HWBlackbox", as SYSTEM, from boot): every sensor every 5 s and the voltage rails
                4 times a second into crash-safe logs; the apps on the watch list (starts, exits and exit codes,
                memory); Windows' own records (crashes, hangs, who asked for a shutdown, power losses); who listens
                on which port; an incident report for every power-off and app crash; a status for Home Assistant.
  the agent     (in each signed-in session, from sign-in): what only a session can see (the screens, the app in
                front, the taskbar, Windows asking the session to end) and the dashboard on 127.0.0.1.
  the dashboard (a page in the browser): all of it, like HWiNFO with the black box's history on top.
"""

NAME = "HW Blackbox"
VERSION = "1.0.6"
SERVICE = "HWBlackbox"                 # the Windows service
AGENT_TASK = "HWBlackboxAgent"         # the scheduled task that starts the agent at sign-in
