# Security

HW Blackbox runs as a Windows service under LocalSystem, from boot, so a security problem in it matters. Please report
one privately, not in a public issue.

## Reporting a problem

Use GitHub's private reporting: **[Report a vulnerability](https://github.com/jamesccupps/HW-Blackbox/security/advisories/new)**
(the repository's Security tab). Only the maintainer sees it. Please include:

- what's affected, and what someone could do with it;
- how to make it happen;
- the HW Blackbox version (the dashboard's Service card) and the Windows version.

Once it's fixed, the release notes say what was fixed (and who found it, if you'd like that).

## What's covered

- the release zips from the [releases](https://github.com/jamesccupps/HW-Blackbox/releases): the installer, the
  service, the session agent and the dashboard on `127.0.0.1`;
- the website at `https://jamesccupps.github.io/HW-Blackbox/`.

Some things are so by design:

- the records, the ports' table, the programs log (for programs of 1 GB or more) and the incident reports in
  `C:\ProgramData\HWBlackbox` are readable by every user of the PC, and they hold other programs' command lines (cut
  short, with what looks like a password or a token hidden);
- the Home Assistant token is kept as it is in `secrets\home_assistant.env`, a folder only SYSTEM and the
  administrators can open: the service has to send it as it is;
- the dashboard is one per PC, not per user: the first session to sign in serves it, and it answers programs in
  that session only;
- a report's **Save as a zip** (from 1.2.0) packs that report with the logs of its day and the status, the command
  lines above among them, for the user to hand to someone helping: it's a download from the page, to the user's
  own PC, and nothing is sent anywhere;
- Setup.exe and the updater check signatures without asking the certificate authority whether a certificate was
  revoked (they work offline). They check the signer's name and James Cupps's Azure signing identity.

Only the latest release gets fixes. To update, click **Update** on its page, or run the new release's `Setup.exe`:
both keep the settings and the history.
