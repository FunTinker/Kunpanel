# Changelog

## v0.8.0 - 2026-08-29

- Enable the KunPanel nftables table automatically at startup with an inbound default-deny policy and current SSH access only.
- Detect single-source brute force, IPv4 `/24` and IPv6 `/64` rotation, cross-IP account spraying, and high-volume distributed login failures.
- Persist expiring IPv4/IPv6 source bans and restore them atomically whenever the firewall is reloaded.
- Drop invalid packets, TCP NULL/XMAS probes, abusive SYN and UDP source rates, and excessive global new connections before user allow rules.
- Require a concrete port and purpose for every new inbound allow rule; record who opened and closed it and when.
- Add manual source block/unblock controls, recent security events, protection status, and port lifecycle details to the firewall UI.
- Add a bootstrap firewall CLI, a KunPanel Fail2ban filter/jail, and Linux CI validation with `nft -c`.

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
