# KunPanel 安装与使用手册

本文适用于 KunPanel v0.6.x。当前版本建议以 **Beta** 方式公开使用：核心管理、权限、安全和回滚流程已有自动化测试与生产部署验证，但 KunPanel 会以 root 权限管理系统，不应在未备份、未配置 HTTPS 或没有服务商控制台救援能力的服务器上直接执行高风险操作。

## 1. 支持范围

### 1.1 推荐环境

- Debian 12 amd64 或 arm64
- systemd
- 至少 1 核 CPU、1 GB 内存、2 GB 可用磁盘
- 一个已解析到服务器的独立域名
- root 或等效的系统管理权限
- Go 1.22 或更高版本，用于从源码构建

面板默认监听 `127.0.0.1:8088`，不应直接监听公网地址。外部访问应经过 Nginx 和 HTTPS。

### 1.2 版本状态

- v0.6.x 属于 Beta 版本。
- Debian 12 是当前主要测试平台。
- Ubuntu、Rocky Linux、AlmaLinux 等系统尚未完成完整兼容矩阵。
- 节点 SSH 加固和端口迁移包含验证与回滚，但执行前仍必须准备云厂商控制台或串行控制台。
- KunPanel 不是容器隔离边界。获得管理员或操作员权限的用户可以执行高权限操作。

## 2. 安装前准备

### 2.1 DNS 和防火墙

将 `panel.example.com` 替换为自己的域名，并创建指向服务器公网 IP 的 A 或 AAAA 记录。

在云厂商安全组和服务器防火墙中仅放行：

- `22/tcp` 或实际 SSH 端口，只允许可信来源时更安全
- `80/tcp`，用于首次签发证书和 HTTP 跳转
- `443/tcp`，用于面板 HTTPS

不要放行 `8088/tcp` 到公网。

### 2.2 安装基础依赖

```bash
apt-get update
apt-get install -y \
  ca-certificates curl git nginx certbot python3-certbot-nginx \
  tmux nftables openssh-client sshpass zip unzip tar \
  sudo procps iproute2 openssl
```

说明：

- `tmux` 用于 Web 终端。
- `nftables` 用于防火墙管理。
- `openssh-client` 和 `sshpass` 用于多 VPS 节点密钥下发。
- 数据库、Docker、PHP、Redis、rclone 等按实际功能从应用商城安装。

### 2.3 安装 Go

Debian 12 默认仓库中的 Go 版本可能低于项目要求。请从 <https://go.dev/dl/> 安装 Go 1.22 或更高版本，然后验证：

```bash
go version
```

只使用仓库已构建的 `web/dist` 时不需要 Node.js。修改前端源码时需要 Node.js 20 或更高版本。

## 3. 从源码安装

### 3.1 创建目录并克隆源码

```bash
install -d -m 0755 /opt/kunpanel
git clone https://github.com/FunTinker/Kunpanel.git /opt/kunpanel/source
cd /opt/kunpanel/source
git checkout main
```

建议在正式环境记录准备安装的提交：

```bash
git rev-parse HEAD
```

### 3.2 测试并构建

```bash
cd /opt/kunpanel/source
go test ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" \
  -o /opt/kunpanel/kunpanel .
chmod 0755 /opt/kunpanel/kunpanel
```

如需重新构建前端：

```bash
cd /opt/kunpanel/source/frontend
npm ci
npm run build
cd ..
go test ./...
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" \
  -o /opt/kunpanel/kunpanel .
```

### 3.3 创建运行目录

```bash
install -d -m 0700 /var/lib/tryallfun-panel
install -d -m 0755 /home/wwwroot
install -d -m 0755 /etc/nginx/conf.d
install -d -m 0700 /etc/nginx/ssl
```

目录用途：

| 路径 | 用途 | 建议权限 |
| --- | --- | --- |
| `/opt/kunpanel/source` | Git 源码 | root 可写 |
| `/opt/kunpanel/kunpanel` | 生产二进制 | `0755` |
| `/var/lib/tryallfun-panel` | 配置、会话、审计、指标、备份、SSH 私钥 | `0700` |
| `/home/wwwroot` | 网站和部署项目 | 按站点需要设置 |
| `/etc/nginx/conf.d` | KunPanel 管理的 Nginx 站点配置 | root 可写 |
| `/etc/nginx/ssl` | 证书文件 | `0700` 或更严格 |

`/var/lib/tryallfun-panel` 含密码哈希、会话签名密钥和节点 SSH 私钥，禁止发布、上传到代码仓库或交给不可信用户。

### 3.4 安装 systemd 服务

```bash
install -m 0644 /opt/kunpanel/source/deploy/tryallfun-panel.service \
  /etc/systemd/system/kunpanel.service
systemctl daemon-reload
systemctl enable --now kunpanel
systemctl status kunpanel --no-pager
```

健康检查：

```bash
curl -fsS http://127.0.0.1:8088/api/status
```

首次安装应返回类似：

```json
{"configured":false,"twoFactor":false}
```

查看日志：

```bash
journalctl -u kunpanel -n 100 --no-pager
```

## 4. 配置 Nginx 和 HTTPS

### 4.1 安装反向代理配置

```bash
cp /opt/kunpanel/source/deploy/nginx.conf /etc/nginx/conf.d/kunpanel.conf
```

编辑 `/etc/nginx/conf.d/kunpanel.conf`，把 `panel.example.com` 改为实际域名。然后验证并重载：

```bash
nginx -t
systemctl reload nginx
```

### 4.2 签发 HTTPS 证书

```bash
certbot --nginx -d panel.example.com
```

完成后检查：

```bash
curl -I https://panel.example.com/
```

应看到 `200` 或登录页响应，并包含 `Content-Security-Policy`、`X-Content-Type-Options` 和 `X-Frame-Options` 等响应头。

### 4.3 限制管理入口

建议至少采用一种额外保护：

- 在云安全组中只允许办公 IP 或 VPN 网段访问 443。
- 在 Nginx `location /` 中使用 `allow` 和 `deny`。
- 将面板放在 WireGuard、Tailscale 或企业 VPN 后。
- 使用 Cloudflare Access 等零信任访问控制。

## 5. 首次初始化

1. 打开 `https://panel.example.com/`。
2. 创建主管理员账号，账号至少 3 个字符。
3. 密码至少 16 位，并同时包含大写字母、小写字母、数字和特殊字符。
4. 登录后进入“安全中心”，优先启用 TOTP 动态验证码。
5. 检查“面板设置”中的监听地址、数据目录和文件根目录。
6. 查看审计日志，确认首次初始化和登录来源正确。

主管理员是最高权限账号。不要在聊天工具、工单或公开问题中发送管理员密码、TOTP 密钥或节点私钥。

## 6. 角色和维护解锁

KunPanel 提供三种角色：

| 角色 | 适用对象 | 权限范围 |
| --- | --- | --- |
| 管理员 | 系统所有者 | 用户、设置、安装、删除和全部高风险操作 |
| 操作员 | 受信任运维人员 | 日常管理与经授权的维护操作 |
| 只读用户 | 审计或观察人员 | 查看状态，不执行变更 |

敏感操作会要求重新输入当前账号密码进行维护解锁。解锁有效期较短，完成维护后应退出账号或关闭浏览器会话。

## 7. 功能使用

### 7.1 服务器总览

“总览”显示 CPU、内存、磁盘、网络、系统信息、核心服务和最近任务。

- 趋势范围支持 1 小时、6 小时、24 小时、7 天和 30 天。
- 服务状态为“未知”通常表示对应程序未安装或 systemd 服务名不同。
- 长时间趋势数据保存在面板数据目录，备份时应包含整个数据目录。

### 7.2 应用商城

1. 打开“应用商城”。
2. 按分类或关键词查找应用。
3. 查看来源、许可证、依赖、检测命令和预计安装内容。
4. 点击安装后，在任务列表观察输出和最终状态。
5. 安装失败时先查看任务日志，不要重复快速点击安装。

应用安装命令以 root 权限执行。扩展应用清单中的每条命令都必须人工审核，不要导入来源不明的 JSON 注册表。

### 7.3 网站管理

创建网站前应确认：

- 域名已解析到服务器。
- Nginx 已安装且 `nginx -t` 通过。
- `TAF_NGINX_VHOST_DIR` 和 `TAF_FILE_ROOT` 配置正确。
- PHP 网站已安装对应 PHP-FPM。

常见流程：

1. 新建静态站、PHP 站、WordPress 站或反向代理。
2. 检查生成的站点根目录和 Nginx 配置。
3. 签发证书前确保 80/443 可达。
4. 修改配置后先执行语法检查，再重载 Nginx。
5. 删除站点前备份站点文件和数据库。

### 7.4 数据库

支持 MariaDB/MySQL、PostgreSQL 和 Redis 的检测与常用管理。

- 数据库账号使用独立强密码，不要复用面板密码。
- 删除数据库、清空 Redis 或执行 SQL 前先建立备份。
- 面板调用本机数据库客户端，缺少 `mariadb`、`mysql`、`psql` 或 `redis-cli` 时会显示未安装。
- 不建议允许数据库端口直接从公网访问。

### 7.5 文件管理

文件管理范围受 `TAF_FILE_ROOT` 限制，默认是 `/home/wwwroot`。

- 支持上传、编辑、下载、压缩、权限修改和安全回收站。
- 编辑配置文件前先下载或创建备份。
- 不要把 `.env`、数据库备份、私钥或令牌放在可公开访问的网站目录。
- 大文件上传同时受 Nginx `client_max_body_size` 和面板请求限制影响。

### 7.6 防火墙

KunPanel 使用 nftables 管理独立的 `inet tryallfun` 表。

添加规则前：

1. 在云厂商控制台确认有救援入口。
2. 保留当前 SSH 管理端口。
3. 区分入口和出口、TCP 和 UDP、来源 CIDR 和目标 CIDR。
4. 先添加允许规则，再添加拒绝规则。

面板规则不能替代云安全组，两者必须同时允许流量。

### 7.7 系统工具

系统工具包含进程、监听端口、磁盘、日志、系统更新和 Docker 管理。

- 终止进程前确认 PID 和服务归属。
- 安装系统更新前先备份并阅读待升级包列表。
- Docker Compose 项目应使用独立目录，敏感变量放在权限受限的环境文件中。
- 系统日志可能包含域名、路径和客户端 IP，分享前先脱敏。

### 7.8 Web 终端

Web 终端由 tmux 保持会话，可在浏览器断线后恢复。

- 输入内容会以面板服务用户权限执行，默认即 root。
- 不要在共享屏幕或录屏中输入密码、私钥和令牌。
- 完成后点击“关闭会话”，不要只关闭浏览器标签页。
- 审计日志会记录终端操作事件；仍应使用系统级审计和最小权限策略。

### 7.9 多 VPS 节点管理

推荐顺序：

1. 打开“节点管理”，初始化面板专用 Ed25519 密钥。
2. 备份显示的公钥；私钥只保存在面板数据目录。
3. 添加节点别名、地址、SSH 用户和当前端口。
4. 可填写一次性密码自动下发公钥，密码不会保存。
5. 执行单节点或批量探活。
6. 查看远程系统信息，确认主机、系统和端口无误。
7. 再使用远程命令或受管终端。

关闭密码登录前：

- 必须先确认密钥登录成功。
- 必须保留当前 SSH 会话。
- 必须准备云厂商控制台或串行控制台。
- 确认目标用户有 root 或免交互 sudo 权限。

修改 SSH 端口前：

1. 先在云安全组和本机防火墙放行新端口。
2. 输入界面要求的完整确认文本。
3. KunPanel 会让旧端口和新端口同时生效。
4. 面板从新端口完成实际密钥探测后才最终切换。
5. 新端口不可达时会尝试恢复原配置。
6. 即使界面显示回滚成功，也应立即从独立终端验证旧端口。

不要用生产面板本身作为第一个端口迁移测试节点。

### 7.10 部署中心与远程备份

- Git 部署只接受经过校验的仓库地址、分支和项目标识。
- Docker Compose 日志和操作在任务记录中查看。
- rclone 凭据必须先通过服务器终端运行 `rclone config` 创建。
- KunPanel 只保存 rclone remote 名称和目标路径，不保存云存储密码。
- 首次远程备份应先执行连接测试，再手工检查远端文件。

### 7.11 安全中心

上线后至少完成：

- 启用主管理员 TOTP。
- 创建日常操作员账号，减少主管理员日常使用。
- 检查 SSH 密钥认证和密码策略。
- 配置 Fail2ban。
- 查看最近登录失败和操作审计。
- 检查防火墙只开放必要端口。
- 定期导出离线备份并验证恢复。

## 8. 备份与恢复

### 8.1 必须备份的内容

```text
/var/lib/tryallfun-panel
/opt/kunpanel/source
/opt/kunpanel/kunpanel
/home/wwwroot
/etc/nginx
数据库逻辑备份
```

面板数据目录备份包含节点 SSH 私钥，应加密保存并限制访问。

### 8.2 面板数据备份示例

```bash
systemctl stop kunpanel
tar -czf /root/kunpanel-data-$(date +%F).tar.gz \
  -C /var/lib tryallfun-panel
systemctl start kunpanel
```

恢复前请阅读仓库根目录的 [RESTORE_NOTES.md](../RESTORE_NOTES.md)。

## 9. 升级与回滚

### 9.1 升级

```bash
cd /opt/kunpanel/source
git fetch --tags origin
git checkout main
git pull --ff-only
go test ./...
CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -o /opt/kunpanel/kunpanel.new .
```

校验候选程序：

```bash
file /opt/kunpanel/kunpanel.new
sha256sum /opt/kunpanel/kunpanel.new
```

替换前备份并执行短暂停机：

```bash
cp -a /opt/kunpanel/kunpanel /opt/kunpanel/kunpanel.rollback
systemctl stop kunpanel
install -m 0755 /opt/kunpanel/kunpanel.new /opt/kunpanel/kunpanel
systemctl start kunpanel
systemctl is-active kunpanel
curl -fsS http://127.0.0.1:8088/api/status
```

### 9.2 回滚

```bash
systemctl stop kunpanel
install -m 0755 /opt/kunpanel/kunpanel.rollback /opt/kunpanel/kunpanel
systemctl start kunpanel
systemctl is-active kunpanel
```

如果新版本修改了数据格式，回滚二进制前还必须恢复匹配版本的数据目录备份。

## 10. 重置管理员密码

```bash
cd /opt/kunpanel/source
sh scripts/reset-password.sh
systemctl restart kunpanel
```

自定义安装路径时：

```bash
PANEL_BIN=/custom/path/kunpanel \
TAF_DATA_DIR=/custom/data \
sh scripts/reset-password.sh
```

密码重置会使旧会话失效。

## 11. 配置变量

| 变量 | 默认值或推荐值 | 用途 |
| --- | --- | --- |
| `TAF_ADDR` | `127.0.0.1:8088` | HTTP 监听地址 |
| `TAF_DATA_DIR` | 服务模板为 `/var/lib/tryallfun-panel` | 面板运行数据 |
| `TAF_FILE_ROOT` | `/home/wwwroot` | 文件管理允许根目录 |
| `TAF_PROJECT_DIR` | `/opt/kunpanel` | 项目和升级工作目录 |
| `TAF_BINARY_PATH` | `/opt/kunpanel/kunpanel` | 当前生产二进制 |
| `TAF_NGINX_BIN` | 自动查找 `nginx` | 自定义 Nginx 可执行文件 |
| `TAF_NGINX_VHOST_DIR` | 模板为 `/etc/nginx/conf.d` | 站点配置目录 |
| `TAF_NGINX_SSL_DIR` | 模板为 `/etc/nginx/ssl` | 证书目录 |

修改 systemd 环境变量后执行：

```bash
systemctl daemon-reload
systemctl restart kunpanel
```

## 12. 常见故障

### 12.1 页面无法访问

```bash
systemctl status kunpanel --no-pager
journalctl -u kunpanel -n 100 --no-pager
curl -v http://127.0.0.1:8088/api/status
nginx -t
```

本地接口正常而公网失败时，重点检查 Nginx、DNS、证书、云安全组和 80/443 防火墙。

### 12.2 Nginx 操作失败

- 运行 `command -v nginx`。
- 运行 `nginx -t` 查看具体配置文件和行号。
- 核对 `TAF_NGINX_VHOST_DIR`。
- Debian 包安装的 Nginx 通常使用 `/usr/sbin/nginx` 和 `/etc/nginx/conf.d`。
- 自编译 Nginx 可通过 `TAF_NGINX_BIN` 指定路径。

### 12.3 Web 终端不可用

```bash
command -v tmux
tmux -V
```

安装 `tmux` 后重试。已有异常会话可在服务器终端运行 `tmux ls` 检查。

### 12.4 节点密码下发不可用

```bash
command -v ssh
command -v ssh-copy-id
command -v sshpass
```

缺少时安装：

```bash
apt-get install -y openssh-client sshpass
```

### 12.5 新 SSH 端口不可达

依次检查云安全组、本机 nftables/ufw/firewalld、`sshd -t`、`sshd -T`、监听端口和服务日志。不要关闭仍可用的旧 SSH 会话。

### 12.6 应用安装失败

- 查看任务输出中的第一条失败命令。
- 确认 Debian 软件源可访问。
- 检查磁盘空间、DNS 和代理环境。
- 不要把重复点击安装当作重试机制。
- 自定义注册表先在测试服务器审计和验证。

## 13. 卸载

卸载前先备份数据、网站和数据库。

```bash
systemctl disable --now kunpanel
rm -f /etc/systemd/system/kunpanel.service
systemctl daemon-reload
```

确认备份有效后，再由管理员决定是否删除以下目录：

```text
/opt/kunpanel
/var/lib/tryallfun-panel
```

KunPanel 不会自动删除 `/home/wwwroot`、数据库、Nginx 或已安装的应用。

## 14. 获取帮助和报告问题

- 普通问题：<https://github.com/FunTinker/Kunpanel/issues>
- 安全问题：阅读 [SECURITY.md](../SECURITY.md)，不要在公开 Issue 中发布漏洞利用、密码、私钥或生产数据。
- 提交补丁：阅读 [CONTRIBUTING.md](../CONTRIBUTING.md)。

报告问题时提供 KunPanel 版本、操作系统、复现步骤和已脱敏日志。不要提交 `/var/lib/tryallfun-panel` 原始内容。
