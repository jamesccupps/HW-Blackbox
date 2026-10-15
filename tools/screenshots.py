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
    profile = tempfile.mkdtemp(prefix="hwb-edge-")
    try:
        for name, frag, w, h in SHOTS:
            path = os.path.join(args.out, name + ".png")
            subprocess.run([edge, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
                            "--no-default-browser-check", "--force-device-scale-factor=1", "--user-data-dir=" + profile,
                            "--window-size=%d,%d" % (w, h), "--virtual-time-budget=15000", "--screenshot=" + path,
                            base + frag.format(report=report)], capture_output=True, timeout=120)
            print("%-9s %s" % (name, "%d KB" % (os.path.getsize(path) // 1024) if os.path.exists(path) else "FAILED"))
    finally:
        shutil.rmtree(profile, ignore_errors=True)


if __name__ == "__main__":
    main()
