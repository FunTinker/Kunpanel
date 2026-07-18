# Kunpanel / 鲲面板

TryAllFun 旗下，面向 Debian 12 的自由、私有 VPS 管理面板。无需手机号、实名或云端账号。

## 当前 v0.3 能力

管理界面已覆盖总览、网站、应用、数据库、文件、防火墙、终端、安全中心和
面板设置，并通过 `frontend` 目录可以从源码重新构建嵌入资源。

- Go 单文件服务，内嵌管理前端
- 首次初始化与 16 位强密码策略
- HttpOnly 签名会话与安全响应头
- CPU、内存、磁盘、网络实时采样
- 1 小时到 30 天的分级聚合趋势数据
- systemd 服务启停与重启、后台安装任务及任务输出
- 静态网站与反向代理创建、Nginx 检查与失败保护
- MariaDB 数据库和用户创建、数据库删除确认
- 文件上传、目录浏览、在线编辑、重命名、权限和删除
- nftables 独立规则表、规则校验、允许/拒绝规则
- Root 命令工作台、SSH 设置、Root 密码修改、TLS 证书发现
- JSONL 操作审计、管理员密码修改与 SSH 离线重置
- 5 秒短期采样与 30 天分钟级持久化历史
- tmux PTY 交互终端与断线会话恢复
- PostgreSQL 角色、Redis 数据库和 MariaDB 管理
- 压缩、解压、文件下载和安全回收站
- Let's Encrypt 签发任务与 Certbot 自动续期
- WordPress 数据库、程序、管理员与 Nginx 一键编排
- nftables 默认拒绝策略与 SSH 防锁保护
- Cron 计划任务、配置备份恢复和 HTTPS Webhook 通知
- Ed25519 签名升级清单验证、SHA-256 校验与回滚二进制
- Debian 12 systemd 与 Nginx 部署模板

## 本地运行

```bash
go run .
```

打开 `http://127.0.0.1:8088`。

## 安全架构原则

除明确标注的 Web 终端外，高权限操作不接受任意 Shell 字符串，而是使用固定任务 ID、结构化参数、参数校验、二次确认、审计日志与配置备份。

Web 终端属于明确的高风险例外：它允许管理员执行任意 root 命令，每次执行均要求确认并写入审计日志。

## SSH 重置管理员密码

```bash
sh /home/wwwroot/Kunpanel.456.life/scripts/reset-password.sh
```

## 签名升级源

生成离线 Ed25519 密钥：

```bash
go run ./cmd/sign-update keygen
```

签署版本清单：

```bash
go run ./cmd/sign-update sign kunpanel-update-private.key v0.3.1 \
  https://updates.example.com/kunpanel-v0.3.1 \
  ./kunpanel-v0.3.1 "安全与稳定性更新" > manifest.json
```

只需把二进制和 `manifest.json` 放在 HTTPS 静态源，并在面板设置中填写
Manifest URL 与公钥。私钥不得上传服务器或提交到仓库。

## 路线

1. 持久化时序数据库与降采样任务
2. 白名单任务执行器、任务队列与 WebSocket 日志
3. LNMP、Docker、数据库和官方应用安装器
4. 网站、反向代理、Let's Encrypt 与 Cloudflare Origin CA
5. 文件上传、编辑、压缩、权限与回收站
6. nftables 规则事务、Fail2ban 与 SSH 策略
7. 备份、计划任务、面板自更新与签名升级源
