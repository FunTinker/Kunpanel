# KunPanel 构建与发布

本文面向维护者。普通用户请阅读 [安装与使用手册](docs/INSTALLATION_AND_USAGE.md)。

## 构建环境

- Go 1.22+
- Node.js 20+，仅重新构建前端时需要
- npm
- Git

确认工作树干净：

```bash
git status --short
```

## 后端验证

```bash
gofmt -w *.go cmd/sign-update/*.go
go test ./...
go vet ./...
```

## 前端构建

生产前端源码位于 `frontend/src`，构建结果写入 `web/dist` 并由 Go 二进制嵌入。

```bash
cd frontend
npm ci
npm run build
cd ..
git diff --check
```

前端源码和 `web/dist` 必须在同一提交中更新。

## Linux 二进制

amd64：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -buildvcs=false -ldflags="-s -w" \
  -o releases/kunpanel-linux-amd64 .
```

arm64：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -buildvcs=false -ldflags="-s -w" \
  -o releases/kunpanel-linux-arm64 .
```

生成校验文件：

```bash
sha256sum releases/kunpanel-linux-* > releases/SHA256SUMS
```

## 候选版本验收

至少完成：

1. `go test ./...` 和 `go vet ./...` 通过。
2. 前端 `npm run build` 通过。
3. Linux 二进制文件头和 SHA-256 正确。
4. 在隔离数据目录完成首次初始化、登录和核心页面检查。
5. 检查桌面与移动端布局没有横向页面溢出。
6. 检查未登录 API 返回 `401`。
7. 在 Debian 12 测试机通过 systemd、Nginx 和 HTTPS 冒烟测试。
8. 检查仓库不含私钥、密码、令牌、生产数据和构建缓存。
9. 更新版本号、README、安装手册、NOTICE 和变更记录。

SSH 密码关闭和端口迁移属于破坏性测试，必须在可重装的专用节点执行，并保留服务商控制台。

## 发布内容

公开发布应包含：

- Git 标签，例如 `v0.6.0`；
- amd64 和 arm64 Linux 二进制；
- `SHA256SUMS`；
- 完整源码归档；
- 变更说明、升级步骤、回滚步骤和已知限制；
- `LICENSE` 与 `NOTICE`。

发布前再次确认：

```bash
git status --short
git diff --check HEAD~1
```

## 签名更新清单

生成离线签名密钥：

```bash
go run ./cmd/sign-update keygen
```

签名发布清单：

```bash
go run ./cmd/sign-update sign kunpanel-update-private.key v0.6.1 \
  https://downloads.example.com/kunpanel-v0.6.1-linux-amd64 \
  releases/kunpanel-linux-amd64 "安全与稳定性更新" > manifest.json
```

私钥只能离线保存，不得上传服务器、CI 日志、Issue、Release 或源码仓库。

## 生产部署原则

不要在运行中的二进制路径上直接构建。应构建到候选文件，校验后再执行：

1. 备份当前二进制和数据目录。
2. 停止服务。
3. 使用 `install -m 0755` 替换二进制。
4. 启动服务。
5. 检查 `systemctl is-active`、`/api/status`、二进制哈希和限定时间日志。
6. 失败时立即恢复旧二进制；涉及数据格式变化时同时恢复数据备份。
