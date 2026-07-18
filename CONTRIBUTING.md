# Contributing to KunPanel

KunPanel is developed in the open. Pull requests are welcome for fixes,
features, documentation, translations, tests, and application manifests.

## Development

```bash
go test ./...
go vet ./...
cd frontend && npm ci && npm run build
```

The frontend build writes embedded assets to `web/dist`. Do not commit
`frontend/node_modules`, runtime data, logs, passwords, private keys, or
compiled binaries.

## Application manifests

Applications must use fixed, reviewable commands and declare their source,
license, dependencies, health checks, upgrade path, and uninstall behavior.
Never accept arbitrary shell text from a remote registry. Registry changes
must be reviewed and signed before distribution.

## Pull requests

Explain the user-facing behavior, security implications, migration needs, and
the tests you ran. Changes that execute privileged operations must include
validation, maintenance unlock, audit logging, and rollback behavior.
