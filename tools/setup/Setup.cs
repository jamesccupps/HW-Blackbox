// HW Blackbox's Setup.exe: what someone double-clicks in the unzipped release (it replaced Install.cmd in 1.1.1).
//
// Its manifest asks Windows for an administrator before it starts, so the prompt is Windows' own and names the
// publisher, James Cupps, when the release is signed. Then it runs install.ps1 from its own folder, in this window,
// and waits: the install's report shows as it happens.
//
// A signed Setup.exe runs only an install.ps1 signed by the same publisher, checked here with Windows' own
// WinVerifyTrust: a script changed after the release was made is refused. From the check until the install ends,
// Setup.exe holds the script open so that nothing else can change, rename or delete it, and runs it by the path
// Windows gives for that open file (no folder link in between). The DLLs it loads by name come from System32 only,
// never from the download folder it runs in.
//
// Built by tools\build.py with the C# compiler every Windows has (.NET Framework 4's csc.exe, C# 5): no SDK.
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

static class Setup
{
    static int Main()
    {
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
        Console.Title = "HW Blackbox setup";
        string here = AppDomain.CurrentDomain.BaseDirectory;
        string script = Path.Combine(here, "install.ps1");
        FileStream held;
        try
        {
            // (others may read it, nothing more, until the install ends)
            held = new FileStream(script, FileMode.Open, FileAccess.Read, FileShare.Read);
        }
        catch (Exception e)
        {
            if (e is FileNotFoundException || e is DirectoryNotFoundException)
                Console.WriteLine("install.ps1 isn't next to Setup.exe. Unzip the whole release, then run Setup.exe " +
                                  "from the folder it unzipped to.");
            else
                Console.WriteLine("install.ps1 couldn't be opened (" + e.Message + "), so nothing was installed.");
            return Wait(1);
        }
        using (held)
        {
            IntPtr handle = held.SafeFileHandle.DangerousGetHandle();
            string path = FinalPath(handle) ?? script;
            X509Certificate2 mine = SignerOf(Process.GetCurrentProcess().MainModule.FileName, IntPtr.Zero);
            if (mine != null)
            {
                X509Certificate2 its = SignerOf(path, handle);
                if (its == null || its.Subject != mine.Subject)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("install.ps1 isn't signed by " + mine.GetNameInfo(X509NameType.SimpleName, false) +
                                      ": it was changed after the release was made. Nothing was installed: download " +
                                      "the release again.");
                    Console.ResetColor();
                    return Wait(3);
                }
            }
            string ps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                                     @"WindowsPowerShell\v1.0\powershell.exe");
            var start = new ProcessStartInfo(ps, "-NoProfile -ExecutionPolicy Bypass -File \"" + path + "\" -Pause");
            start.UseShellExecute = false;           // (in this window: the install's report shows here as it runs)
            start.WorkingDirectory = Path.GetDirectoryName(path);
            // Windows PowerShell's own modules: started from PowerShell 7, the module path it hands down puts 7's
            // first, and those don't load in Windows PowerShell (Get-AuthenticodeSignature, for the catalog check)
            start.EnvironmentVariables["PSModulePath"] = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\Modules");
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
    }

    // (an error before the install's own report: keep the window open, so it can be read)
    static int Wait(int code)
    {
        Console.WriteLine();
        Console.WriteLine("Press a key to close this window.");
        try { Console.ReadKey(true); } catch (InvalidOperationException) { }
        return code;
    }

    // The open file's own path, with any folder link resolved (null if Windows can't say)
    static string FinalPath(IntPtr handle)
    {
        var buf = new StringBuilder(1024);
        uint n = GetFinalPathNameByHandleW(handle, buf, (uint)buf.Capacity, 0);
        if (n == 0 || n >= buf.Capacity)
            return null;
        string p = buf.ToString();
        if (p.StartsWith(@"\\?\UNC\"))
            return @"\\" + p.Substring(8);
        return p.StartsWith(@"\\?\") ? p.Substring(4) : p;
    }

    // The certificate a file is validly Authenticode-signed with, or null: WinVerifyTrust (the check behind Windows'
    // "Verified publisher" and PowerShell's Get-AuthenticodeSignature), on the open file when there's a handle
    static X509Certificate2 SignerOf(string path, IntPtr handle)
    {
        var file = new TrustFileInfo();
        file.cbStruct = (uint)Marshal.SizeOf(typeof(TrustFileInfo));
        file.pcwszFilePath = path;
        file.hFile = handle;
        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TrustFileInfo)));
        Marshal.StructureToPtr(file, pFile, false);
        var data = new TrustData();
        data.cbStruct = (uint)Marshal.SizeOf(typeof(TrustData));
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.pFile = pFile;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        Guid action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        X509Certificate2 signer = null;
        try
        {
            if (WinVerifyTrust(new IntPtr(-1), ref action, ref data) == 0)
            {
                // CRYPT_PROVIDER_SGNR: csCertChain at 12, pasCertChain at 16; CRYPT_PROVIDER_CERT: pCert after a DWORD
                IntPtr prov = WTHelperProvDataFromStateData(data.hWVTStateData);
                IntPtr sgnr = prov == IntPtr.Zero ? IntPtr.Zero : WTHelperGetProvSignerFromChain(prov, 0, false, 0);
                if (sgnr != IntPtr.Zero && Marshal.ReadInt32(sgnr, 12) > 0)
                {
                    IntPtr chain = Marshal.ReadIntPtr(sgnr, 16);
                    IntPtr cert = chain == IntPtr.Zero ? IntPtr.Zero : Marshal.ReadIntPtr(chain, IntPtr.Size);
                    if (cert != IntPtr.Zero)
                        signer = new X509Certificate2(cert);       // (a copy: it outlives the state closed below)
                }
            }
        }
        finally
        {
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(new IntPtr(-1), ref action, ref data);
            Marshal.DestroyStructure(pFile, typeof(TrustFileInfo));
            Marshal.FreeHGlobal(pFile);
        }
        return signer;
    }

    const uint LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800;
    const uint WTD_UI_NONE = 2, WTD_REVOKE_NONE = 0, WTD_CHOICE_FILE = 1;
    const uint WTD_STATEACTION_VERIFY = 1, WTD_STATEACTION_CLOSE = 2;
    static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct TrustFileInfo                                     // WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TrustData                                         // WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetDefaultDllDirectories(uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetFinalPathNameByHandleW(IntPtr file, StringBuilder path, uint size, uint flags);

    [DllImport("wintrust.dll")]
    static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref TrustData data);

    [DllImport("wintrust.dll")]
    static extern IntPtr WTHelperProvDataFromStateData(IntPtr state);

    [DllImport("wintrust.dll")]
    static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr provData, uint signer, bool counterSigner,
                                                        uint counterSignerIndex);
}
