# KunPanel Source Restore Notes

Restored on: 20260630-224227
Source archive: /home/wwwroot/tryallfun-panel/v2rayn-127-0-0-1-10808/v2rayn-127-0-0-1-10808
Installed to: /home/wwwroot/Kunpanel.456.life/source

The historical build artifact `work/kunpanel-v03-linux` matches the currently deployed binary hash.

Current production binary:
`/home/wwwroot/Kunpanel.456.life/tryallfun-panel`

Useful commands:

```bash
cd /home/wwwroot/Kunpanel.456.life/source
go test ./...
go build -trimpath -o ../tryallfun-panel.new .
```

Do not replace production directly without making a backup and running a smoke test.
