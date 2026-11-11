// HW Blackbox's Setup.exe: what someone double-clicks in the unzipped release (it replaced Install.cmd in 1.1.1).
//
// Its manifest asks Windows for an administrator before it starts, so the prompt is Windows' own and names the
// publisher, James Cupps, when the release is signed. Then it runs install.ps1 from its own folder, in this window,
// and waits: the install's report shows as it happens. A signed Setup.exe runs only an install.ps1 signed by the same
// publisher: a script changed after the release was made is refused.
//
// Built by tools\build.py with the C# compiler every Windows has (.NET Framework 4's csc.exe, C# 5): no SDK.
using System;
using System.Diagnostics;
using System.IO;

static class Setup
{
    // The check and the run, in Windows PowerShell. The paths come in environment variables, never in the command.
    const string Command =
        "$ErrorActionPreference = 'Stop'\n" +
        "$me = Get-AuthenticodeSignature -LiteralPath $env:HWB_SETUP\n" +
        "$it = Get-AuthenticodeSignature -LiteralPath $env:HWB_SCRIPT\n" +
        "if ($me.Status -eq 'Valid' -and ($it.Status -ne 'Valid' -or " +
        "$it.SignerCertificate.Subject -ne $me.SignerCertificate.Subject)) {\n" +
        "  Write-Host ('install.ps1 is not signed by ' + $me.SignerCertificate.GetNameInfo('SimpleName', $false) + " +
        "' (' + $it.Status + '): it was changed after the release was made. Nothing was installed: download the " +
        "release again.') -ForegroundColor Red\n" +
        "  exit 3\n" +
        "}\n" +
        "& $env:HWB_SCRIPT -Pause\n" +
        "exit $LASTEXITCODE\n";

    static int Main()
    {
        Console.Title = "HW Blackbox setup";
        string here = AppDomain.CurrentDomain.BaseDirectory;
        string script = Path.Combine(here, "install.ps1");
        if (!File.Exists(script))
        {
            Console.WriteLine("install.ps1 isn't next to Setup.exe. Unzip the whole release, then run Setup.exe from " +
                              "the folder it unzipped to.");
            return Wait(1);
        }
        string ps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                                 @"WindowsPowerShell\v1.0\powershell.exe");
        // (encoded: a fixed command, PowerShell's way of taking one whole. The keyboard stays this window's, for the
        // installer's questions and its "press a key")
        string encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(Command));
        var start = new ProcessStartInfo(ps, "-NoProfile -ExecutionPolicy Bypass -EncodedCommand " + encoded);
        start.UseShellExecute = false;           // (in this window: the install's report shows here as it runs)
        start.EnvironmentVariables["HWB_SETUP"] = Process.GetCurrentProcess().MainModule.FileName;
        start.EnvironmentVariables["HWB_SCRIPT"] = script;
        start.WorkingDirectory = here;
        try
        {
            using (var p = Process.Start(start))
            {
                p.WaitForExit();
                return p.ExitCode;
            }
        }
        catch (Exception e)
        {
            Console.WriteLine("Windows PowerShell couldn't be started (" + e.Message + "), so nothing was installed.");
            return Wait(1);
        }
    }

    // (an error before the install's own report: keep the window open, so it can be read)
    static int Wait(int code)
    {
        Console.WriteLine();
        Console.WriteLine("Press a key to close this window.");
        try { Console.ReadKey(true); } catch (InvalidOperationException) { }
        return code;
    }
}
