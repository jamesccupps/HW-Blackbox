# HW Blackbox: notes for working on it

A hardware monitor and black box for Windows: a LocalSystem service, a session agent per signed-in user, and a
dashboard on 127.0.0.1. The README says what it does and how it's built; this file is what to keep in mind when
changing or releasing it.

## Commands

- Tests: `build\HWBlackbox\python\python.exe tests\test_core.py` (or `python -m unittest discover -s tests`). GitHub's
  runner is elevated: a new file there is owned by the administrators, not the user, so tests about owners set them.
- Build: `.venv\Scripts\python.exe tools\build.py [--zip]` (the venv from `requirements.txt`; `lib\` holds
  LibreHardwareMonitorLib 0.9.6 and its DLLs, checked by SHA-256).
- Try it next to the installed one: `python -m hwblackbox console --test --data-dir C:\temp\hwb --run-for 120` and
  `python -m hwblackbox agent --test --data-dir C:\temp\hwb`.
- Demo data and screenshots: `tools\make_demo.py`, `tools\screenshots.py` (made-up data only).

## Releasing

- From 1.1.1 a release is built on GitHub: bump `hwblackbox.VERSION`, write `release-notes/vX.Y.Z.md` with
  `{SHA256}` where the zip's hash goes, commit, and push an annotated tag `vX.Y.Z`. `.github/workflows/release.yml`
  builds, signs (see Code signing), checks and zips it, attests it, and makes a draft release titled
  `HW Blackbox X.Y.Z` with the notes (their title line dropped, `{SHA256}` filled in) and the zip as
  `HWBlackbox-win64.zip`. Look at the draft, then publish it as the latest release, not a pre-release. Never build the
  release zip on a PC: it wouldn't be signed.
- The zip's name stays `HWBlackbox-win64.zip`: the download links and the updater look for it. The updater installs a
  release only when GitHub's digest for the zip and the SHA-256 in the notes agree. Never replace a file on a release
  that's out: publish a new version instead.
- `.github/workflows/checksums.yml` adds `SHA256SUMS.txt` to every published release (it never replaces one): keep
  its `contents: write`.
- After publishing: the public download's hash, a dry run of the updater from the previous version
  (`python -m hwblackbox update --dry-run --pretend-version X`), the tests' run on GitHub, the site.

## Code signing

From 1.1.1, release.yml's `authenticode` job signs `Setup.exe`, `install.ps1` and `HWBlackbox.cat` (a catalog of every
file, made after the manifest) as James Cupps: Azure Artifact Signing, the account and certificate the other apps use
(account `SlateAccount`, profile `Slate`, endpoint `https://eus.codesigning.azure.net/`). Azure trusts GitHub's OIDC
token through a federated credential on the "Slate signing" app registration for this repository's `release`
environment, which admits `v*` tags only. This repository sends GitHub's immutable subject format, so the credential's
subject is `repo:jamesccupps@148652101/HW-Blackbox@1443134825:environment:release` (not the classic
`repo:jamesccupps/HW-Blackbox:...`). The environment's secrets `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and
`AZURE_SUBSCRIPTION_ID` name the app; no password or key is stored. The job runs only when the repository variable
`SIGNING` is `on`, and a `v*` tag it didn't sign stops at `package` (no unsigned release); it runs only pinned actions,
Microsoft's ArtifactSigning module and `tools/sign_release.ps1`, never Python, pip or the program
(`test_the_signing_job_runs_nothing_else`). Setup.exe checks with WinVerifyTrust that `install.ps1` is signed by its
own publisher, holds it locked until the install ends, and runs it with `-File` (no `-EncodedCommand`: the first
Setup.exe drew 11/70 on VirusTotal, a Bitdefender-family `Gen:Variant.Lazy`, as a dropper's shape). A signed
`install.ps1` installs only files that match the signed catalog, and from 1.1.1 the updater installs only a release
whose `install.ps1` and `HWBlackbox.cat` are signed by `CN=James Cupps, O=James Cupps` (`update.PUBLISHER`). A tag
`vX.Y.Z-signtest.N` runs all but the draft: don't release from it, and delete the tag. Before a release, scan the
signtest's signed Setup.exe and zip on VirusTotal; if the Bitdefender family still flags it, report that exact signed
file to Bitdefender as a false positive, or fall back to Install.cmd beside the signed `install.ps1` and catalog.

## Not in the Scoop bucket (deliberate)

HW Blackbox isn't in jamesccupps/scoop-bucket, and that's on purpose: Scoop installs apps per user without admin rights
and updates them itself, while HW Blackbox needs admin rights, installs a service, a sign-in task and the PawnIO
driver, and updates itself from its page (decided 2026-11-11). winget would fit better, if ever.

## Conventions

- US spelling in the README, docs and pages. Plain words; say what something does for the person using it.
- The site's `site/index.html` keeps its SEO tags (title 60 characters or less, description 160 or less, canonical,
  `og:*`, theme color, image sizes) and ends with the "More tools" section (`.jc-more-grid`).
- The repository's About description starts with what it is; change it when the README's opening line changes.
- Example addresses in docs and tests come from 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24, and example names
  are made up: never a real network, PC or person.
- Commits as `James Cupps <148652101+jamesccupps@users.noreply.github.com>`. Session notes and handoffs stay out of
  git.

## Rules the code keeps

- The service runs as SYSTEM: everything it loads is under Program Files, it never writes through a link, never follows
  a path from another program's record to a network share, and the data folder belongs to the administrators.
- Each user's folder (`sessions\<SID>`) is made by the service for that user alone; users can't make folders there.
- The page changes nothing but the user's own notification settings; anything needing an admin starts a fixed command
  through Windows' admin prompt (`update.ELEVATED`). Requests are accepted from the page itself only.
- Times are written with their UTC offset (`util.now_iso`); old files without one are read with `parse_iso(after=)`.
