# Sign a built release folder as James Cupps (Azure Artifact Signing: the account and certificate profile Slate,
# NoteForge, PingerPlot, UniFi Stock Watcher, Protect Panes and HVAC Network Scanner sign with), with an RFC 3161
# timestamp so the signatures stay valid after the short-lived certificate expires:
#   1. Setup.exe and install.ps1 (what someone runs, and what runs as an administrator)
#   2. MANIFEST.json's hashes for those two, which signing changed
#   3. HWBlackbox.cat: a catalog of every file in the folder (Windows' own format; New-FileCatalog), so the whole
#      release can be checked against one signature: Test-FileCatalog, and the installer does
#   4. the catalog itself
# Throws unless everything comes out validly signed, and every file matches the catalog.
#
# CI's authenticode job runs it, signed in to Azure through GitHub's OIDC token (no password or key anywhere), with
# the ArtifactSigning module at the version below. It runs nothing but PowerShell: never Python, never the program.
# -NoSign makes the manifest and an unsigned catalog only (to try it without Azure).
#
#   pwsh tools/sign_release.ps1 -Folder build\HWBlackbox [-NoSign]
param([Parameter(Mandatory)][string]$Folder, [switch]$NoSign)
$ErrorActionPreference = 'Stop'
$Folder = (Resolve-Path -LiteralPath $Folder).Path
$cat = Join-Path $Folder 'HWBlackbox.cat'
$signed = 'Setup.exe', 'install.ps1'

function Sign([string]$path) {
    Invoke-ArtifactSigning -Endpoint 'https://eus.codesigning.azure.net/' `
        -CodeSigningAccountName 'SlateAccount' -CertificateProfileName 'Slate' `
        -Files $path -FileDigest SHA256 -TimestampRfc3161 'http://timestamp.acs.microsoft.com' -TimestampDigest SHA256
    # A signing failure must stop the build here, not surface as an unsigned file in a release.
    $s = Get-AuthenticodeSignature -LiteralPath $path
    if ($s.Status -ne 'Valid') { throw "$path isn't validly signed after signing: $($s.Status) $($s.StatusMessage)" }
    "signed: $(Split-Path $path -Leaf)"
}

if (-not $NoSign) { Import-Module ArtifactSigning -RequiredVersion 0.1.8 }
if (Test-Path -LiteralPath $cat) { Remove-Item -LiteralPath $cat }
foreach ($name in $signed) {
    $p = Join-Path $Folder $name
    if (-not (Test-Path -LiteralPath $p)) { throw "$name isn't in $Folder" }
    if (-not $NoSign) { Sign $p }
}

# the manifest: the signed files' new hashes and the folder's size (the installer checks every file against it)
$mpath = Join-Path $Folder 'MANIFEST.json'
$m = Get-Content -LiteralPath $mpath -Raw | ConvertFrom-Json
foreach ($name in $signed) {
    $h = (Get-FileHash -LiteralPath (Join-Path $Folder $name) -Algorithm SHA256).Hash.ToLower()
    $m.sha256 | Add-Member -NotePropertyName $name -NotePropertyValue $h -Force
}
$m.files = @($m.sha256.PSObject.Properties).Count
$m.bytes = (Get-ChildItem -LiteralPath $Folder -Recurse -File | Where-Object Name -ne 'MANIFEST.json' |
            Measure-Object -Property Length -Sum).Sum
# (UTF-8 without a byte-order mark, as build.py writes it)
[IO.File]::WriteAllText($mpath, ($m | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding $false))
"MANIFEST.json: $($m.files) files"

# the catalog: every file, the manifest included (SHA-256: catalog version 2)
$null = New-FileCatalog -Path $Folder -CatalogFilePath $cat -CatalogVersion 2.0
if (-not $NoSign) { Sign $cat }
$check = Test-FileCatalog -Path $Folder -CatalogFilePath $cat -FilesToSkip 'HWBlackbox.cat'
if ("$check" -ne 'Valid') { throw "the folder doesn't match its catalog: $check" }
"HWBlackbox.cat: every file matches"
