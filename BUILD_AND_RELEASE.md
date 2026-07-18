# KunPanel Build And Release

Source lives at:

```bash
/home/wwwroot/Kunpanel.456.life/source
```

Build without replacing production:

```bash
/usr/local/sbin/kunpanel-build
```

Smoke-test a candidate binary:

```bash
/usr/local/sbin/kunpanel-smoke /home/wwwroot/Kunpanel.456.life/builds/latest/tryallfun-panel
```

Deploy a candidate with automatic backup and rollback on failed healthcheck:

```bash
/usr/local/sbin/kunpanel-deploy /home/wwwroot/Kunpanel.456.life/builds/latest/tryallfun-panel
```

Rollback to the latest saved production binary:

```bash
/usr/local/sbin/kunpanel-rollback
```

Frontend rebuilds are intentionally guarded because `frontend/src` is not yet the full production UI source. The production UI currently lives in `web/dist`.

Only rebuild frontend after restoring the full frontend source:

```bash
KUNPANEL_ALLOW_FRONTEND_REBUILD=1 /usr/local/sbin/kunpanel-build --frontend
```

Production binary:

```bash
/home/wwwroot/Kunpanel.456.life/tryallfun-panel
```
