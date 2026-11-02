# Third-party software

The built program (`build\HWBlackbox`, installed to `C:\Program Files\HWBlackbox`) bundles the software below, each
used unmodified under its own license. The license texts ship with it:
- `licenses\MPL-2.0.txt` (LibreHardwareMonitorLib, RAMSPDToolkit), `licenses\Apache-2.0.txt` (HidSharp) and
  `licenses\dotnet-runtime-MIT.txt` (the System.* libraries), for the .NET libraries in `app\lib\`;
- CPython's `python\LICENSE.txt`;
- the Python packages' `*.dist-info` folders under `python\Lib\site-packages`.

The MPL-2.0 libraries' source code is at the links below.

| Software | Version | License | Where |
|---|---|---|---|
| [CPython](https://www.python.org) (the interpreter and its standard library) | 3.12 | Python Software Foundation License | `python\` (its `LICENSE.txt`) |
| [LibreHardwareMonitorLib](https://github.com/LibreHardwareMonitor/LibreHardwareMonitor) | 0.9.6 | Mozilla Public License 2.0 | `app\lib\LibreHardwareMonitorLib.dll` |
| [HidSharp](http://software.seekye.com/hidsharp) | 2.6.4 | Apache License 2.0 | `app\lib\HidSharp.dll` |
| [RAMSPDToolkit](https://github.com/Blacktempel/RAMSPDToolkit) (LibreHardwareMonitorLib's dependency) | 1.4.2 | Mozilla Public License 2.0 | `app\lib\RAMSPDToolkit-NDD.dll` |
| System.Buffers, System.Memory, System.Numerics.Vectors, System.Runtime.CompilerServices.Unsafe, System.Threading.AccessControl, System.Threading.Tasks.Extensions ([.NET](https://github.com/dotnet/runtime)) | 4.x–10.x | MIT | `app\lib\` |
| [pythonnet](https://github.com/pythonnet/pythonnet) | 3.1.0 | MIT | `python\Lib\site-packages` |
| [clr-loader](https://github.com/pythonnet/clr-loader) | 0.3.1 | MIT | 〃 |
| [cffi](https://github.com/python-cffi/cffi) | 2.0.0 | MIT | 〃 |
| [pycparser](https://github.com/eliben/pycparser) | 3.0 | BSD 3-Clause | 〃 |
| [psutil](https://github.com/giampaolo/psutil) | 7.2.2 | BSD 3-Clause | 〃 |
| [pywin32](https://github.com/mhammond/pywin32) | 312 | Python Software Foundation License | 〃 |
| [nvidia-ml-py](https://pypi.org/project/nvidia-ml-py/) (NVML bindings) | 13.610.43 | BSD 3-Clause | 〃 |

Not bundled, but used when present:

- **PawnIO** (namazso), the signed driver LibreHardwareMonitor uses for the CPU's and the motherboard's sensors.
  Installed separately (`winget install namazso.PawnIO`), under its own license.
- **NVML** (`nvml.dll`), part of NVIDIA's display driver.
