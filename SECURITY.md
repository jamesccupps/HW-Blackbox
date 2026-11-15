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

- the records, the ports' table and the incident reports in `C:\ProgramData\HWBlackbox` are readable by every
  user of the PC, and they hold other programs' command lines (cut short, with what looks like a password or a
  token hidden);
- the dashboard is one per PC, not per user: the first session to sign in serves it, and it answers programs in
  that session only;
- Setup.exe and the updater check signatures without asking the certificate authority whether a certificate was
  revoked (they work offline). They check the signer's name and James Cupps's Azure signing identity.

Only the latest release gets fixes. To update, click **Update** on its page, or run the new release's `Setup.exe`:
both keep the settings and the history.
