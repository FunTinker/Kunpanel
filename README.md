# KunPanel / 鲲面板

KunPanel 是面向 Debian 12 的自由、私有 VPS 管理面板。无需手机号、实名或云端账号，管理服务和数据全部运行在自己的服务器上。

项目完整源代码以 [Apache License 2.0](LICENSE) 开源，公开仓库为 <https://github.com/FunTinker/Kunpanel>。

## v0.5.1 功能

- Go 单二进制服务，内嵌可从 `frontend` 源码重新构建的管理前端
- CPU、内存、磁盘、网络监控以及 1 小时至 30 天聚合趋势
- Nginx 静态站、PHP、WordPress、反向代理和 Let's Encrypt 证书管理
- MariaDB、PostgreSQL 和 Redis 管理，数据库用户及数据操作
- 文件上传、编辑、下载、压缩、权限、安全回收站和在线终端
- nftables 防火墙、Fail2ban、SSH 策略、进程、端口、磁盘和系统日志
- systemd 服务控制、Cron、配置备份恢复、Webhook 通知和签名自动升级
- Docker 容器管理以及 Docker Compose 项目的创建、启停、重启和日志
- Git 仓库部署与安全参数校验后的拉取更新
- 管理员、操作员、只读用户三级 RBAC 权限
- 登录失败限流、主管理员 TOTP 动态验证码和敏感任务日志脱敏
- rclone 远程备份，面板不保存对象存储或网盘凭据
- JSON 扩展应用注册表，可发布自定义安装、更新、卸载和检测清单
- Cloudflare 流量/CPU 持续阈值触发 DNS 橙云代理，并记录执行结果
- JSONL 操作审计、敏感操作维护解锁、HttpOnly 签名会话和安全响应头

## 应用商城

内置应用覆盖 Nginx、Apache、Caddy、Docker、PHP、Node.js、Python、Go、Java、MariaDB、PostgreSQL、Redis、MongoDB、RabbitMQ、Supervisor、HAProxy、Certbot、Fail2ban、ClamAV、Samba、Rsync、WordPress、Laravel、Drupal、phpMyAdmin、Adminer、Gitea 等常用服务。

部署中心的扩展应用清单允许社区维护额外应用，而无需修改面板核心代码。注册表写入前会校验应用 ID、命令长度和危险控制字符；自定义安装命令仍拥有服务器高权限，发布前必须人工审计来源和内容。

## 本地开发

需要 Go 1.22+ 和 Node.js 20+：

```bash
cd frontend
npm install
npm run build
cd ..
go test ./...
go run .
```

打开 `http://127.0.0.1:8088` 完成首次初始化。

## 生产部署

仓库提供 `deploy/tryallfun-panel.service`、Nginx 模板和构建说明。面板默认只监听 `127.0.0.1:8088`，生产环境应通过 HTTPS 反向代理访问，并限制管理入口来源。

远程备份需要先在服务器运行 `rclone config` 配置凭据。KunPanel 只保存 remote 名称和目标目录。

## 安全模型

除明确标注的 Web 终端和审核后的应用注册表命令外，高权限操作使用固定任务 ID、结构化参数、输入校验、二次确认、审计日志与配置备份。

Web 终端允许授权用户执行任意 root 命令，属于明确的高风险功能。不要把面板直接暴露到公网；请启用 HTTPS、限制访问 IP，并使用独立强密码。

SSH 离线重置管理员密码：

```bash
sh /home/wwwroot/Kunpanel.456.life/scripts/reset-password.sh
```

## 签名升级源

```bash
go run ./cmd/sign-update keygen
go run ./cmd/sign-update sign kunpanel-update-private.key v0.5.1 \
  https://updates.example.com/kunpanel-v0.5.2 \
  ./kunpanel-v0.5.2 "安全与稳定性更新" > manifest.json
```

只需把二进制和 `manifest.json` 放到 HTTPS 静态源，并在面板设置中填写 Manifest URL 与公钥。私钥不得上传服务器或提交到仓库。

## 参与贡献

提交补丁前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)、[SECURITY.md](SECURITY.md) 和 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。安全漏洞请按安全策略私下报告，不要直接公开利用细节。

## 许可证

Copyright 2026 TryAllFun contributors. Licensed under the Apache License, Version 2.0. 详见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。
