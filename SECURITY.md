# Security Policy

## Supported versions

Security fixes are applied to the latest v0.6.x release line. Older builds may
receive no fixes and should be upgraded after reviewing release notes and
making a verified backup.

## Reporting a vulnerability

Do not disclose vulnerabilities, exploit code, credentials, private keys,
tokens, logs, or production data in a public issue.

Until GitHub private vulnerability reporting is enabled for this repository,
open a public issue containing only the title `Security contact request` and
the affected version. Do not include technical details. A maintainer will
provide a private channel. The private report should include:

- affected version and commit;
- operating system and deployment topology;
- minimal reproduction steps;
- security impact and required privileges;
- proposed mitigation, if available.

## Deployment expectations

KunPanel performs privileged server operations. Bind it to
`127.0.0.1`, deploy it behind HTTPS and an access restriction, use a strong
unique administrator password, enable TOTP, keep offline backups, and review
audit logs after maintenance tasks.

Do not run SSH port migration or password-login disabling without an existing
key-authenticated session and provider console access.
