r"""Build the folder the installer copies to C:\Program Files\HWBlackbox:

  python\          a private Python: the interpreter and the standard library (copied from the Python this runs on,
                   without its tests, tkinter, IDLE and its own site-packages), the packages HW Blackbox needs (copied
                   from this venv's site-packages), and python312._pth, which fixes the module path to these folders
                   only (no PYTHONPATH, no user site-packages, no current folder)
  app\hwblackbox\   the program
  app\lib\         LibreHardwareMonitorLib and its dependencies (from lib\)
  licenses\        the full license texts of the bundled .NET libraries (MPL-2.0, Apache-2.0, MIT)
  install.ps1, README.md, LICENSE, THIRD_PARTY_NOTICES.md, MANIFEST.json

The service runs as SYSTEM, so everything it loads has to be where only admins can write: hence a Python of its own
in Program Files, not the venv or the per-user Python install.

  python tools\build.py [--out build\HWBlackbox]     (run with the project's venv: .venv\Scripts\python.exe)
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_LIB = {"site-packages", "test", "idlelib", "tkinter", "turtledemo", "ensurepip", "lib2to3", "pydoc_data",
            "__pycache__", "turtle.py"}
SKIP_DLLS = {"_tkinter.pyd", "tcl86t.dll", "tk86t.dll"}
SKIP_SITE = {"pip", "setuptools", "_distutils_hack", "distutils-precedence.pth", "hwblackbox_dev.pth", "__pycache__",
             "example.py"}
RUNTIME_FILES = ("python.exe", "pythonw.exe", "python3.dll", "python312.dll", "vcruntime140.dll", "vcruntime140_1.dll",
                 "LICENSE.txt")
PTH = "python312.zip\n.\nDLLs\nLib\nLib\\site-packages\n..\\app\nimport site\n"
NEEDED = ("pythonnet", "clr_loader", "cffi", "pycparser", "psutil", "win32", "win32com", "pywin32_system32",
          "pynvml.py", "pywin32.pth")


def copytree(src, dst, skip=()):
    os.makedirs(dst, exist_ok=True)
    for e in os.scandir(src):
        if e.name in skip or e.name.endswith((".pyc", ".pyo")) or e.name.startswith("pip-"):
            continue
        target = os.path.join(dst, e.name)
        if e.is_dir():
            copytree(e.path, target, {"__pycache__"})
        else:
            shutil.copy2(e.path, target)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "build", "HWBlackbox"))
    ap.add_argument("--zip", action="store_true", help="also dist\\HWBlackbox-<version>-win64.zip, for a release")
    args = ap.parse_args()
    out = os.path.abspath(args.out)
    base = sys.base_prefix
    site = os.path.join(sys.prefix, "Lib", "site-packages")
    if sys.version_info[:2] != (3, 12):
        sys.exit("build with Python 3.12 (python312._pth and the packages' binaries are for 3.12)")
    if sys.prefix == base:
        sys.exit("run this with the project's venv (.venv\\Scripts\\python.exe): its site-packages are what's shipped")
    missing = [n for n in NEEDED if not os.path.exists(os.path.join(site, n))]
    if missing:
        sys.exit("the venv lacks %s" % ", ".join(missing))
    if not os.path.exists(os.path.join(ROOT, "lib", "LibreHardwareMonitorLib.dll")):
        sys.exit("lib\\LibreHardwareMonitorLib.dll is missing (see README: Building)")
    t0 = time.time()
    if os.path.exists(out):
        shutil.rmtree(out)
    py = os.path.join(out, "python")
    os.makedirs(py)
    for name in RUNTIME_FILES:
        shutil.copy2(os.path.join(base, name), os.path.join(py, name))
    copytree(os.path.join(base, "DLLs"), os.path.join(py, "DLLs"), SKIP_DLLS)
    copytree(os.path.join(base, "Lib"), os.path.join(py, "Lib"), SKIP_LIB)
    copytree(site, os.path.join(py, "Lib", "site-packages"), SKIP_SITE)
    with open(os.path.join(py, "python312._pth"), "w", encoding="ascii") as f:
        f.write(PTH)
    copytree(os.path.join(ROOT, "hwblackbox"), os.path.join(out, "app", "hwblackbox"), {"__pycache__"})
    copytree(os.path.join(ROOT, "lib"), os.path.join(out, "app", "lib"))
    for name in ("install.ps1", "Install.cmd", "Uninstall.cmd", "README.md", "LICENSE", "THIRD_PARTY_NOTICES.md"):
        if os.path.exists(os.path.join(ROOT, name)):
            shutil.copy2(os.path.join(ROOT, name), os.path.join(out, name))
    copytree(os.path.join(ROOT, "licenses"), os.path.join(out, "licenses"))     # (the bundled DLLs' license texts)
    exe = os.path.join(py, "python.exe")
    # compiled now, so nothing is written next to the program at run time
    subprocess.run([exe, "-m", "compileall", "-q", "-j", "0", os.path.join(py, "Lib"), os.path.join(out, "app")],
                   check=True)
    # does it run on its own? (the module path comes only from python312._pth)
    probe = subprocess.run([exe, "-c", "import sys, hwblackbox, hwblackbox.service, hwblackbox.agent, "
                            "hwblackbox.dashboard.server, win32api, win32evtlog, win32com.client, clr_loader, psutil, "
                            "pynvml; print(hwblackbox.VERSION, sys.flags.isolated, sys.path)"],
                           capture_output=True, text=True, env={k: v for k, v in os.environ.items()
                                                                  if not k.startswith("PYTHON")})
    if probe.returncode:
        sys.exit("the built runtime doesn't import HW Blackbox:\n" + probe.stderr)
    tmp = tempfile.mkdtemp(prefix="hwb-build-")
    once = subprocess.run([exe, "-m", "hwblackbox", "once", "--no-sensors", "--data-dir", tmp],
                          capture_output=True, text=True, timeout=120)
    shutil.rmtree(tmp, ignore_errors=True)
    if once.returncode or '"kind": "watching"' not in once.stdout:
        sys.exit("the built runtime's 'once' failed:\n" + once.stdout[-2000:] + once.stderr[-2000:])
    files, total = {}, 0
    for dirpath, _dirs, names in os.walk(out):
        for n in names:
            p = os.path.join(dirpath, n)
            rel = os.path.relpath(p, out)
            if rel == "MANIFEST.json":
                continue
            files[rel.replace("\\", "/")] = sha256(p)
            total += os.path.getsize(p)
    sys.path.insert(0, ROOT)
    import hwblackbox
    with open(os.path.join(out, "MANIFEST.json"), "w", encoding="utf-8") as f:
        json.dump({"name": hwblackbox.NAME, "version": hwblackbox.VERSION, "built": time.strftime("%Y-%m-%dT%H:%M:%S"),
                   "python": sys.version.split()[0], "files": len(files), "bytes": total, "sha256": files}, f, indent=1)
    print("built %s %s: %d files, %.1f MB, in %.0f s -> %s" % (hwblackbox.NAME, hwblackbox.VERSION, len(files),
                                                              total / 2**20, time.time() - t0, out))
    print("probe: " + probe.stdout.strip())
    if args.zip:
        # the release: the built folder in a zip, under a folder of the same name
        name = "HWBlackbox-%s-win64" % hwblackbox.VERSION
        dist = os.path.join(ROOT, "dist")
        os.makedirs(dist, exist_ok=True)
        archive = shutil.make_archive(os.path.join(dist, name), "zip", os.path.dirname(out), os.path.basename(out))
        final = os.path.join(dist, name + ".zip")
        if archive != final:
            os.replace(archive, final)
        print("release: %s (%.1f MB), SHA-256 %s" % (final, os.path.getsize(final) / 2**20, sha256(final)))


if __name__ == "__main__":
    main()
