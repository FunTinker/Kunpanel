# Changelog

## v0.7.0 - 2026-08-29

- Block SSRF through webhook and signed-upgrade URLs, including redirect and DNS resolution checks.
- Constrain ZIP and tar extraction with `os.Root`; reject traversal, links, devices, and non-regular targets.
- Make session and maintenance cookies secure by default and trust forwarded HTTPS only from loopback proxies.
- Invalidate a user's existing sessions after password or role changes and prevent deleted/recreated-account session reuse.
- Serialize configuration mutations with atomic persistence and clean multipart upload temporary files.
- Replace native browser prompts and confirmations with accessible in-panel dialogs.
- Upgrade to Go 1.25, `golang.org/x/crypto` 0.55, Vite 8.2, Vue 3.5, and current GitHub Actions.

## v0.6.1 - 2026-07-18

- Redact terminal and sensitive task audit data, rotate audit logs, and bound job resources.
- Migrate password hashing to Argon2id with automatic legacy-hash upgrades.
- Add atomic nftables updates, SSH rollback, backup validation, and signed upgrade health rollback.
