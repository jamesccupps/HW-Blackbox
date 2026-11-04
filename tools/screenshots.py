r"""The README's screenshots: the dashboard over the made-up demo data, captured by Edge in headless mode (no window,
and a throwaway profile, so nothing of the person running it gets in).

  python tools\make_demo.py --out %TEMP%\hwb-demo --live 600          (in one window)
  python -m hwblackbox serve --data-dir %TEMP%\hwb-demo               (in another: port 9079, from its config)
  python tools\screenshots.py [--port 9079] [--out docs\screenshots]
"""
import argparse
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EDGE = (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe")
SHOTS = [("overview", "#overview", 1440, 1000), ("sensors", "#sensors:logger", 1440, 1040),
         ("charts", "#charts:72:cpu_temp_c,gpu_temp_c,cpu_power_w,gpu_power_w,v12_v", 1440, 1060),
         ("power", "#power", 1440, 1040), ("events", "#events", 1440, 900), ("ports", "#ports", 1440, 760),
         ("incident", "#incidents:{report}", 1440, 900)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9079)
    ap.add_argument("--out", default=os.path.join(ROOT, "docs", "screenshots"))
    args = ap.parse_args()
    edge = next((p for p in EDGE if os.path.exists(p)), None)
    if not edge:
        raise SystemExit("Microsoft Edge isn't installed")
    base = "http://127.0.0.1:%d/" % args.port
    with urllib.request.urlopen(base + "api/incidents", timeout=10) as r:
        reports = json.loads(r.read())["incidents"]
    report = next((x["name"] for x in reports if x["src"] == "power"), "")
    os.makedirs(args.out, exist_ok=True)
    failed = 0
    for name, frag, w, h in SHOTS:
        # each shot into a new file, with a profile of its own (an Edge still closing would hand the next one to
        # itself and take no picture), and only a new picture replaces the old one: a failure can't pass as done
        path = os.path.join(args.out, name + ".png")
        new = path + ".new.png"
        if os.path.exists(new):
            os.remove(new)
        profile = tempfile.mkdtemp(prefix="hwb-edge-")
        try:
            r = subprocess.run([edge, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
                                "--no-default-browser-check", "--force-device-scale-factor=1",
                                "--user-data-dir=" + profile, "--window-size=%d,%d" % (w, h),
                                "--virtual-time-budget=15000", "--screenshot=" + new,
                                base + frag.format(report=report)], capture_output=True, text=True, timeout=120)
            # (msedge.exe can return before its browser process has written the picture: wait for the file, and
            # for it to stop growing)
            deadline, last = time.time() + 60, -1
            while time.time() < deadline:
                size = os.path.getsize(new) if os.path.exists(new) else -1
                if size > 0 and size == last:
                    break
                last = size
                time.sleep(1)
        finally:
            shutil.rmtree(profile, ignore_errors=True)
        if os.path.exists(new) and os.path.getsize(new) > 0:
            os.replace(new, path)
            print("%-9s %d KB" % (name, os.path.getsize(path) // 1024))
        else:
            failed += 1
            print("%-9s FAILED (exit %s) %s" % (name, r.returncode, (r.stderr or "").strip()[-300:]))
    if failed:
        raise SystemExit("%d screenshots failed" % failed)


if __name__ == "__main__":
    main()
