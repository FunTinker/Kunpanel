# KunPanel 备份、恢复与回滚

本文采用公开安装手册中的默认布局。自定义路径时应同步替换命令中的目录。

## 备份范围

| 路径 | 内容 |
| --- | --- |
| `/var/lib/tryallfun-panel` | 面板配置、用户、审计、指标、任务数据、备份配置、节点 SSH 私钥 |
| `/opt/kunpanel/source` | 当前源码和 Git 历史 |
| `/opt/kunpanel/kunpanel` | 当前生产二进制 |
| `/home/wwwroot` | 网站和部署项目 |
| `/etc/nginx` | Nginx 配置和证书引用 |

数据库必须使用对应工具建立一致性备份，例如 `mariadb-dump`、`pg_dump` 或存储快照。只复制数据库数据目录可能无法可靠恢复。

## 建立面板备份

```bash
install -d -m 0700 /root/kunpanel-backup
systemctl stop kunpanel
tar -czf /root/kunpanel-backup/panel-data.tar.gz \
  -C /var/lib tryallfun-panel
cp -a /opt/kunpanel/kunpanel /root/kunpanel-backup/kunpanel.binary
git -C /opt/kunpanel/source rev-parse HEAD \
  > /root/kunpanel-backup/source-commit.txt
systemctl start kunpanel
```

计算校验值：

```bash
cd /root/kunpanel-backup
sha256sum panel-data.tar.gz kunpanel.binary > SHA256SUMS
```

将备份复制到另一台服务器或加密离线介质。面板数据包含 SSH 私钥，不能放在公开对象存储桶中。

## 恢复前检查

1. 确认操作系统、CPU 架构和 KunPanel 版本兼容。
2. 验证 `SHA256SUMS`。
3. 保留当前故障现场的额外副本。
4. 停止 KunPanel。
5. 确认恢复目标路径正确，避免覆盖其他应用。

## 恢复面板数据和二进制

```bash
systemctl stop kunpanel
mv /var/lib/tryallfun-panel /var/lib/tryallfun-panel.before-restore
install -d -m 0700 /var/lib/tryallfun-panel
tar -xzf /root/kunpanel-backup/panel-data.tar.gz -C /var/lib
install -m 0755 /root/kunpanel-backup/kunpanel.binary \
  /opt/kunpanel/kunpanel
systemctl start kunpanel
```

验证：

```bash
systemctl is-active kunpanel
curl -fsS http://127.0.0.1:8088/api/status
journalctl -u kunpanel --since "5 minutes ago" --no-pager
```

确认用户、站点、节点和审计数据正常后，再决定是否删除 `before-restore` 目录。

## 仅回滚二进制

如果升级未改变数据格式：

```bash
systemctl stop kunpanel
install -m 0755 /opt/kunpanel/kunpanel.rollback \
  /opt/kunpanel/kunpanel
systemctl start kunpanel
```

如果升级包含数据迁移，必须恢复与旧二进制匹配的数据备份。不要让旧程序直接写入新格式数据。

## SSH 节点密钥恢复

节点私钥默认位于：

```text
/var/lib/tryallfun-panel/ssh/id_ed25519
```

恢复后确认权限：

```bash
chmod 0700 /var/lib/tryallfun-panel/ssh
chmod 0600 /var/lib/tryallfun-panel/ssh/id_ed25519
chmod 0644 /var/lib/tryallfun-panel/ssh/id_ed25519.pub
```

如果私钥泄漏，应立即从所有受管节点的 `authorized_keys` 删除对应公钥，重新生成面板密钥并逐台下发。

## 灾难恢复顺序

1. 恢复操作系统和 SSH 管理能力。
2. 安装 Nginx、数据库和运行依赖。
3. 恢复数据库。
4. 恢复 `/home/wwwroot` 和 Nginx 配置。
5. 恢复 KunPanel 二进制和数据目录。
6. 启动面板并在本机执行健康检查。
7. 恢复 HTTPS 和访问限制。
8. 验证审计、站点、数据库、任务和节点连接。

恢复演练应定期在隔离服务器执行。未验证过的备份不能视为可靠备份。
