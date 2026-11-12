r"""lib\ for a build: LibreHardwareMonitorLib and the .NET libraries it needs, from their NuGet packages on nuget.org
(build.py's LIB_PACKAGES), each kept only when its SHA-256 is the one build.py pins (LIB_SHA256): the files shipped
since 1.0.0. A package holds a copy per .NET version (lib\net472, lib\netstandard2.0...): the one that matches is
taken. Nothing is run from a package; only the one file is written.

  python tools\fetch_lib.py [--out lib]          (on GitHub, for the release build; a PC keeps its own lib\)"""
import argparse
import hashlib
import io
import os
import sys
import urllib.request
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build import LIB_PACKAGES, LIB_SHA256, ROOT  # noqa: E402

FEED = "https://api.nuget.org/v3-flatcontainer/%s/%s/%s.%s.nupkg"


def fetch(package, version):
    pid, ver = package.lower(), version.lower()
    req = urllib.request.Request(FEED % (pid, ver, pid, ver), headers={"User-Agent": "hwblackbox-build"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read(64 << 20)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "lib"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    nupkgs, failed = {}, []
    for dll, (package, version) in sorted(LIB_PACKAGES.items()):
        key = (package, version)
        if key not in nupkgs:
            nupkgs[key] = zipfile.ZipFile(io.BytesIO(fetch(package, version)))
        z, found = nupkgs[key], []
        for name in z.namelist():
            # lib/<.NET version>/<dll>, or, in a package with a copy per platform (LibreHardwareMonitorLib's),
            # runtimes/win-x64/lib/<.NET version>/<dll>
            parts = name.split("/")
            if parts[:2] == ["runtimes", "win-x64"]:
                parts = parts[2:]
            if len(parts) == 3 and parts[0] == "lib" and parts[2].lower() == dll.lower():
                data = z.read(name)
                h = hashlib.sha256(data).hexdigest()
                found.append((parts[1], h))
                if h == LIB_SHA256[dll]:
                    with open(os.path.join(args.out, dll), "wb") as f:
                        f.write(data)
                    print("%s: %s %s, %s" % (dll, package, version, parts[1]))
                    break
        else:
            failed.append(dll)
            print("%s: no copy in %s %s has the pinned SHA-256; the package has: %s" % (
                dll, package, version, ", ".join("%s %s" % f for f in found) or "none"))
    if failed:
        sys.exit("lib\\ is incomplete: %s" % ", ".join(failed))


if __name__ == "__main__":
    main()
