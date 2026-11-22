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

- From 1.1.2 a release is built on GitHub (1.1.1 was too, but withdrawn): bump `hwblackbox.VERSION`, write `release-notes/vX.Y.Z.md` with
  `{SHA256}` where the zip's hash goes, commit, and push an annotated tag `vX.Y.Z`. `.github/workflows/release.yml`
  builds, signs (see Code signing), checks and zips it, attests it, and makes a draft release titled
  `HW Blackbox X.Y.Z` with the notes (their title line dropped, `{SHA256}` filled in) and the zip as
  `HWBlackbox-win64.zip`. Then its `virustotal` job (`.github/workflows/virustotal.yml`, `tools/virustotal.py`, the
  repository secret `VT_API_KEY` from James's free VirusTotal account) scans the zip and the Setup.exe in it: the
  run's summary lists every engine that flags one, a major engine (`MAJOR`) flagging one fails the run, and the
  draft's notes get a "VirusTotal, scanned when this was released" line under "Check the download" (never ahead of
  the notes' `SHA-256:` line, which the updater reads). Look at the draft and that verdict, ask James, then publish it
  as the latest release, not a pre-release. Never build the release zip on a PC: it wouldn't be signed.
- The release folder must reach the zip exactly as the manifest and the catalog describe it. The package job runs the
  shipped Python only with `-B` (otherwise it rewrites the folder's own `__pycache__` files, whose sources have new
  times after the artifact round trip), and then unpacks the zip and checks it as the installer will
  (`test_packaging_never_rewrites_the_release`). 1.1.1 shipped 81 rewritten `.pyc` files, so its installer refused
  every install and update; it was set back to a pre-release within the hour and 1.1.2 replaced it.
- From 1.1.4 the package job also installs the release from the unpacked zip on the runner (Setup.exe for a signed
  build, install.ps1 for a run by hand), checks the service, Program Files and Installed apps, then runs Installed
  apps' own Uninstall command (read from the registry) and `-Uninstall -RemoveData`, and checks nothing is left. A
  run by hand of release.yml on a branch tries it unsigned before a tag.
- The build compiles every `.pyc` as an unchecked hash (`--invalidation-mode unchecked-hash`): Python never compares
  them with their sources' times, which an unzip resets, so the installed program never rewrites them (it did until
  1.1.3). An edit to a `.py` in a built folder doesn't take: build again.
- The zip's name stays `HWBlackbox-win64.zip`: the download links and the updater look for it. The updater installs a
  release only when GitHub's digest for the zip and the SHA-256 in the notes agree. Never replace a file on a release
  that's out: publish a new version instead.
- `.github/workflows/checksums.yml` adds `SHA256SUMS.txt` to every published release (it never replaces one): keep
  its `contents: write`.
- After publishing: the public download's hash (the SHA-256 VirusTotal scanned; running the VirusTotal workflow by
  hand with the tag looks it up again, uploading nothing), a dry run of the updater from the previous version
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
`install.ps1` installs only files that match the signed catalog, and from 1.1.2 the updater installs only a release
whose `install.ps1` and `HWBlackbox.cat` are signed by `CN=James Cupps, O=James Cupps` (`update.PUBLISHER`). From
1.1.3 all three (Setup.exe, the installer's catalog check, the updater) also check the signing identity: Artifact
Signing's three-day certificates carry the account's identity as a key usage that stays the same from one
certificate to the next (`update.IDENTITY`, `1.3.6.1.4.1.311.97.968698399.443447148.280534441.161049353`, read from
Slate's certificates of 2026-10-29 to 11-12). If Azure ever gives the account a new identity, change `IDENTITY`;
versions before that can't then update by themselves (Setup.exe works). The
unsigned tests never reach these signed paths, so a signed build's `package` job tries them: Setup.exe run from a
copy in Program Files must start the signed `install.ps1` (which stops at its "run the install from the built folder"
guard, installing nothing) and refuse it with one byte changed (exit 3), and `update.check_signed` must take the one
and refuse the other. A tag
`vX.Y.Z-signtest.N` runs all but the draft: don't release from it, and delete the tag. Its `virustotal` job scans the
signtest's signed Setup.exe and zip (the verdict is in the run's summary); if the Bitdefender family still flags it,
report that exact signed file to Bitdefender as a false positive, or fall back to Install.cmd beside the signed
`install.ps1` and catalog.

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
  The user can change anything in it at any moment, links included: the service reads its files without following
  a link (`util.open_no_link`) and changes what's in it only through a handle it checked (`agents.inherit_children`,
  `agents._make_theirs`), never check-by-path-then-act-by-path (the 2026-11-14 review's H3).
- What runs elevated from a user's session (the update, the Home Assistant setup, the installer) takes Windows'
  folders from Windows (`paths.known_folder`, `paths.system_dir`; `[Environment]::GetFolderPath` in install.ps1),
  never from environment variables, which that user's programs can set; programs by their full path. The data
  folder moves only with `--data-dir` (HWBLACKBOX_DATA is gone). The update stages in a folder made again for SYSTEM
  and the administrators (`update._admins_folder`). The installer's report goes to `logs\install.txt` in the data
  folder, never TEMP.
- The page changes nothing but the user's own notification settings; anything needing an admin starts a fixed command
  through Windows' admin prompt (`update.ELEVATED`). Requests are accepted from the page itself only, and from 1.1.3
  only from programs in the page's own Windows session (`Handler.same_session`: the connection's other end, from
  Windows' TCP table): a token in the page wouldn't do, since another user's program could read the page too.
- Times are written with their UTC offset (`util.now_iso`); old files without one are read with `parse_iso(after=)`.
- A problem's words: the notifications know a problem by its words with the measurements taken out
  (`notify.problem_key`: a number with a unit, "3 min", "41.2 GB", "2 programs"). Give a moving number a unit, and
  keep a number that says what the problem is about (a port, "disk 1") without one, or a new problem's notification
  never fires (until 1.2.0 most never did: the 2026-11-21 audit's finding 1).
- Never trust the clock to delete: `util.prune` deletes nothing while the date has jumped ahead of the newest day
  file (`util.clock_jumped`), and the power-off report takes the newest rows when the clock reads earlier than they
  do (`poweroff.clock_set_back`).
