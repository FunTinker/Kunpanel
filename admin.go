package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type auditEntry struct {
	Time    time.Time `json:"time"`
	Action  string    `json:"action"`
	Target  string    `json:"target"`
	Success bool      `json:"success"`
	Detail  string    `json:"detail"`
	IP      string    `json:"ip"`
}

type job struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Status   string    `json:"status"`
	Output   string    `json:"output"`
	Error    string    `json:"error,omitempty"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitempty"`
}

type appSpec struct {
	ID          string
	Name        string
	Desc        string
	Category    string
	Version     string
	Icon        string
	Homepage    string
	License     string
	Tags        []string
	Source      string
	InstallSize string
	Commands    []string
	Remove      []string
	Update      []string
	Checks      []string
}

type firewallRule struct {
	ID          string `json:"id"`
	Direction   string `json:"direction,omitempty"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Source      string `json:"source"`
	Destination string `json:"destination,omitempty"`
	Action      string `json:"action"`
	Note        string `json:"note"`
}

var (
	safeNameRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	domainRE     = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$`)
	databaseRE   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,62}$`)
	sqlIdentRE   = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)
	serviceSpecs = []struct {
		Name, Label, Port string
	}{
		{"nginx", "Nginx", "80 / 443"},
		{"php8.2-fpm", "PHP-FPM 8.2", "9000"},
		{"mariadb", "MariaDB", "3306"},
		{"docker", "Docker", "—"},
		{"redis-server", "Redis", "6379"},
		{"postgresql", "PostgreSQL", "5432"},
		{"fail2ban", "Fail2ban", "—"},
		{"supervisor", "Supervisor", "—"},
		{"memcached", "Memcached", "11211"},
		{"rabbitmq-server", "RabbitMQ", "5672 / 15672"},
		{"haproxy", "HAProxy", "80 / 443"},
		{"postfix", "Postfix", "25 / 587"},
		{"smbd", "Samba", "445"},
		{"clamav-daemon", "ClamAV", "—"},
	}
)

func managedServices() []map[string]any {
	out := make([]map[string]any, 0, len(serviceSpecs))
	for _, s := range serviceSpecs {
		out = append(out, map[string]any{
			"name": s.Name, "label": s.Label, "port": s.Port,
			"status": serviceStatus(s.Name), "installed": serviceInstalled(s.Name),
		})
	}
	return out
}

func serviceInstalled(name string) bool {
	if runtime.GOOS == "windows" {
		return false
	}
	return exec.Command("systemctl", "cat", name).Run() == nil
}

func catalog() []appSpec {
	apps := []appSpec{
		{"lnmp", "LNMP 环境", "Nginx + MariaDB + PHP 8.2 常用扩展", "运行环境", "1.0", "L", "https://www.nginx.com/", "BSD/GPL", []string{"nginx", "php", "mariadb", "建站"}, "Debian", "350 MB", []string{"apt-get update", "DEBIAN_FRONTEND=noninteractive apt-get install -y nginx mariadb-server php8.2-fpm php8.2-cli php8.2-mysql php8.2-curl php8.2-gd php8.2-mbstring php8.2-xml php8.2-zip", "systemctl enable --now nginx mariadb php8.2-fpm"}, []string{"DEBIAN_FRONTEND=noninteractive apt-get purge -y nginx mariadb-server php8.2-fpm php8.2-cli php8.2-mysql php8.2-curl php8.2-gd php8.2-mbstring php8.2-xml php8.2-zip", "apt-get autoremove -y"}, []string{"apt-get update", "DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y nginx mariadb-server php8.2-fpm php8.2-cli"}, []string{"nginx", "mysql", "php"}},
		{"docker", "Docker Engine", "Debian 官方 Docker Engine 与 Compose 插件", "容器", "24.x", "D", "https://docs.docker.com/", "Apache-2.0", []string{"容器", "Compose", "部署"}, "Debian", "220 MB", []string{"apt-get update", "DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-plugin", "systemctl enable --now docker"}, []string{"DEBIAN_FRONTEND=noninteractive apt-get purge -y docker.io docker-compose-plugin", "apt-get autoremove -y"}, []string{"apt-get update", "DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y docker.io docker-compose-plugin"}, []string{"docker"}},
		{"redis", "Redis", "高性能内存数据库，支持持久化与缓存", "数据库", "7.x", "R", "https://redis.io/", "BSD", []string{"缓存", "队列", "数据库"}, "Debian", "45 MB", []string{"apt-get update", "DEBIAN_FRONTEND=noninteractive apt-get install -y redis-server", "systemctl enable --now redis-server"}, []string{"DEBIAN_FRONTEND=noninteractive apt-get purge -y redis-server", "apt-get autoremove -y"}, []string{"apt-get update", "DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y redis-server"}, []string{"redis-server"}},
		{"postgres", "PostgreSQL", "可靠的开源关系型数据库与扩展生态", "数据库", "15.x", "P", "https://www.postgresql.org/", "PostgreSQL", []string{"数据库", "SQL", "GIS"}, "Debian", "180 MB", []string{"apt-get update", "DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql postgresql-contrib", "systemctl enable --now postgresql"}, []string{"DEBIAN_FRONTEND=noninteractive apt-get purge -y postgresql postgresql-contrib", "apt-get autoremove -y"}, []string{"apt-get update", "DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y postgresql postgresql-contrib"}, []string{"psql"}},
		{"fail2ban", "Fail2ban", "自动封禁恶意登录来源，保护 SSH 与 Web 服务", "安全", "1.0", "F", "https://www.fail2ban.org/", "GPL-2.0", []string{"安全", "SSH", "防爆破"}, "Debian", "20 MB", []string{"apt-get update", "DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban", "systemctl enable --now fail2ban"}, []string{"DEBIAN_FRONTEND=noninteractive apt-get purge -y fail2ban", "apt-get autoremove -y"}, []string{"apt-get update", "DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y fail2ban"}, []string{"fail2ban-client"}},
		{"nftables", "nftables", "Debian 原生防火墙管理框架，默认拒绝并保护 SSH", "安全", "1.0", "N", "https://wiki.nftables.org/", "GPL-2.0", []string{"安全", "防火墙", "网络"}, "Debian", "12 MB", []string{"apt-get update", "DEBIAN_FRONTEND=noninteractive apt-get install -y nftables", "systemctl enable --now nftables"}, []string{"DEBIAN_FRONTEND=noninteractive apt-get purge -y nftables", "apt-get autoremove -y"}, []string{"apt-get update", "DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y nftables"}, []string{"nft"}},
	}
	apps = append(apps,
		packageApp("php", "PHP 8.2", "PHP-FPM 与常用扩展，适用于 Laravel、WordPress 和传统 PHP 站点", "运行环境", "8.2", "P", "https://www.php.net/", "PHP-3.01", []string{"php", "php-fpm", "Laravel", "WordPress"}, []string{"php8.2", "php8.2-fpm", "php8.2-cli", "php8.2-mysql", "php8.2-curl", "php8.2-gd", "php8.2-mbstring", "php8.2-xml", "php8.2-zip"}, []string{"php"}),
		packageApp("nodejs", "Node.js", "JavaScript 服务端运行时，包含 npm 包管理器", "运行环境", "18 LTS", "J", "https://nodejs.org/", "MIT", []string{"Node.js", "npm", "前端"}, []string{"nodejs", "npm"}, []string{"node"}),
		packageApp("python", "Python 3", "Python 3、虚拟环境与 pip，适合 API 和自动化服务", "运行环境", "3.11", "Py", "https://www.python.org/", "PSF", []string{"Python", "API", "自动化"}, []string{"python3", "python3-venv", "python3-pip", "pipx"}, []string{"python3"}),
		packageApp("golang", "Go", "Go 编译器与标准工具链，用于构建高性能服务", "运行环境", "1.20", "Go", "https://go.dev/", "BSD", []string{"Go", "编译器", "API"}, []string{"golang", "git"}, []string{"go"}),
		packageApp("java", "OpenJDK", "OpenJDK 17 运行时，支持 Spring Boot 与 Java 应用", "运行环境", "17", "J", "https://openjdk.org/", "GPL-2.0", []string{"Java", "Spring", "运行时"}, []string{"openjdk-17-jre-headless"}, []string{"java"}),
		packageApp("git", "Git", "版本控制工具，支持部署钩子与代码拉取", "开发工具", "2.x", "G", "https://git-scm.com/", "GPL-2.0", []string{"Git", "部署", "开发"}, []string{"git"}, []string{"git"}),
		packageApp("ssh-tools", "SSH 节点工具", "多 VPS 密钥下发、探活和安全加固所需客户端", "运维工具", "1.x", "S", "https://www.openssh.com/", "BSD/GPL-2.0", []string{"SSH", "节点", "密钥", "VPS"}, []string{"openssh-client", "sshpass"}, []string{"ssh", "sshpass"}),
		packageApp("composer", "Composer", "PHP 官方依赖管理器", "开发工具", "2.x", "C", "https://getcomposer.org/", "MIT", []string{"PHP", "依赖", "Laravel"}, []string{"composer"}, []string{"composer"}),
		packageApp("supervisor", "Supervisor", "Python 进程守护与多应用进程管理", "运维工具", "4.x", "S", "http://supervisord.org/", "BSD", []string{"进程守护", "队列", "运维"}, []string{"supervisor"}, []string{"supervisord"}),
		packageApp("memcached", "Memcached", "轻量级内存对象缓存服务", "数据库", "1.6", "M", "https://memcached.org/", "BSD", []string{"缓存", "性能"}, []string{"memcached"}, []string{"memcached"}),
		packageApp("rabbitmq", "RabbitMQ", "可靠消息队列，支持 AMQP 与任务异步化", "数据库", "3.x", "Q", "https://www.rabbitmq.com/", "MPL-2.0", []string{"队列", "消息", "异步"}, []string{"rabbitmq-server"}, []string{"rabbitmqctl"}),
		packageApp("haproxy", "HAProxy", "高性能 TCP/HTTP 负载均衡与健康检查", "网络服务", "2.x", "H", "https://www.haproxy.org/", "GPL-2.0", []string{"负载均衡", "代理", "高可用"}, []string{"haproxy"}, []string{"haproxy"}),
		packageApp("certbot", "Certbot", "Let's Encrypt 自动签发与续期工具", "安全", "2.x", "C", "https://certbot.eff.org/", "Apache-2.0", []string{"TLS", "HTTPS", "证书"}, []string{"certbot", "python3-certbot-nginx"}, []string{"certbot"}),
		packageApp("clamav", "ClamAV", "开源病毒扫描器，可配合上传和备份任务", "安全", "1.x", "C", "https://www.clamav.net/", "GPL-2.0", []string{"安全", "杀毒", "扫描"}, []string{"clamav", "clamav-daemon"}, []string{"clamscan"}),
		packageApp("samba", "Samba", "SMB/CIFS 文件共享服务", "文件服务", "4.x", "S", "https://www.samba.org/", "GPL-3.0", []string{"文件共享", "SMB", "局域网"}, []string{"samba"}, []string{"smbd"}),
		packageApp("rsync", "Rsync", "增量同步与远程备份工具", "备份工具", "3.x", "R", "https://rsync.samba.org/", "GPL-3.0", []string{"备份", "同步", "增量"}, []string{"rsync"}, []string{"rsync"}),
		packageApp("imagemagick", "ImageMagick", "服务器端图片转换、缩略图与格式处理", "媒体工具", "6/7", "I", "https://imagemagick.org/", "ImageMagick", []string{"图片", "缩略图", "媒体"}, []string{"imagemagick"}, []string{"convert"}),
		packageApp("ffmpeg", "FFmpeg", "音视频转码、截图与媒体处理工具链", "媒体工具", "5.x", "F", "https://ffmpeg.org/", "LGPL/GPL", []string{"视频", "音频", "转码"}, []string{"ffmpeg"}, []string{"ffmpeg"}),
		packageApp("phpmyadmin", "phpMyAdmin", "MariaDB/MySQL 可视化管理工具", "建站", "5.x", "P", "https://www.phpmyadmin.net/", "GPL-2.0", []string{"MySQL", "MariaDB", "Web 管理"}, []string{"phpmyadmin"}, []string{"phpmyadmin"}),
		packageApp("drupal", "Drupal 依赖", "为 Drupal 站点准备 PHP、Composer 与扩展", "建站", "10.x", "D", "https://www.drupal.org/", "GPL-2.0", []string{"CMS", "PHP", "建站"}, []string{"php8.2-cli", "php8.2-xml", "php8.2-gd", "php8.2-mbstring", "composer"}, []string{"php"}),
		packageApp("laravel", "Laravel 运行环境", "Laravel 所需 PHP 扩展、Composer 与进程守护", "建站", "10/11", "L", "https://laravel.com/", "MIT", []string{"Laravel", "PHP", "队列"}, []string{"php8.2-cli", "php8.2-mbstring", "php8.2-xml", "php8.2-curl", "php8.2-zip", "composer", "supervisor"}, []string{"php", "composer"}),
		packageApp("postfix", "Postfix", "SMTP 邮件发送服务，适合站点通知和系统邮件", "网络服务", "3.x", "M", "http://www.postfix.org/", "EPL-2.0", []string{"邮件", "SMTP", "通知"}, []string{"postfix"}, []string{"postfix"}),
	)
	return apps
}

func packageApp(id, name, desc, category, version, icon, homepage, license string, tags, packages, checks []string) appSpec {
	install := []string{"apt-get update", fmt.Sprintf("DEBIAN_FRONTEND=noninteractive apt-get install -y %s", strings.Join(packages, " "))}
	remove := []string{fmt.Sprintf("DEBIAN_FRONTEND=noninteractive apt-get purge -y %s", strings.Join(packages, " ")), "apt-get autoremove -y"}
	update := []string{"apt-get update", fmt.Sprintf("DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y %s", strings.Join(packages, " "))}
	return appSpec{ID: id, Name: name, Desc: desc, Category: category, Version: version, Icon: icon, Homepage: homepage, License: license, Tags: tags, Source: "Debian 官方仓库", InstallSize: "按依赖变化", Commands: install, Remove: remove, Update: update, Checks: checks}
}

func appCatalog() []map[string]any {
	specs := catalog()
	out := make([]map[string]any, 0, len(specs))
	for _, s := range specs {
		installed := appInstalled(s)
		out = append(out, map[string]any{
			"id": s.ID, "name": s.Name, "desc": s.Desc, "category": s.Category,
			"version": s.Version, "icon": s.Icon, "homepage": s.Homepage, "license": s.License,
			"tags": s.Tags, "source": s.Source, "installSize": s.InstallSize,
			"verified": true, "installed": installed,
			"actions": appActions(s, installed),
		})
	}
	out = append(out, map[string]any{
		"id": "wordpress", "name": "WordPress 一键建站", "desc": "创建数据库、下载程序并生成安全配置", "category": "建站",
		"version": "6.x", "icon": "W", "homepage": "https://wordpress.org/", "license": "GPL-2.0",
		"tags": []string{"CMS", "PHP", "建站", "一键部署"}, "source": "WordPress 官方下载源", "installSize": "约 120 MB",
		"verified": true, "installed": false, "orchestrated": true, "actions": []string{"install"},
	})
	return out
}

func (a *app) handleAppDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("id")
	if id == "wordpress" {
		writeJSON(w, 200, map[string]any{
			"id": "wordpress", "name": "WordPress 一键建站", "desc": "创建数据库、下载 WordPress、生成 Nginx 站点并初始化管理员。",
			"category": "建站", "version": "6.x", "icon": "W", "homepage": "https://wordpress.org/", "license": "GPL-2.0",
			"tags": []string{"CMS", "PHP", "建站", "一键部署"}, "source": "WordPress 官方下载源", "installSize": "约 120 MB",
			"verified": true, "installed": false, "orchestrated": true, "actions": []string{"install"},
			"services": appServiceStates("wordpress"),
			"checks":   []string{"nginx", "mysql", "php", "curl"},
			"config": []map[string]string{
				{"name": "domain", "label": "域名", "description": "域名需要解析到本机或由 Cloudflare 代理到本机。"},
				{"name": "email", "label": "管理员邮箱", "description": "用于 WordPress 初始管理员账号。"},
				{"name": "title", "label": "站点标题", "description": "安装完成后仍可在 WordPress 后台修改。"},
			},
		})
		return
	}
	for _, spec := range a.allCatalog() {
		if spec.ID != id {
			continue
		}
		installed := appInstalled(spec)
		services, config := appServiceStates(spec.ID), appConfigHints(spec.ID)
		if manifest, ok := a.registryManifestByID(spec.ID); ok {
			services, config = appServiceStatesByName(manifest.Services), manifest.Config
		}
		writeJSON(w, 200, map[string]any{
			"id": spec.ID, "name": spec.Name, "desc": spec.Desc, "category": spec.Category,
			"version": spec.Version, "icon": spec.Icon, "homepage": spec.Homepage, "license": spec.License,
			"tags": spec.Tags, "source": spec.Source, "installSize": spec.InstallSize,
			"verified": true, "installed": installed, "checks": spec.Checks, "commands": spec.Commands,
			"services": services, "config": config,
			"actions": appActions(spec, installed),
		})
		return
	}
	writeJSON(w, 404, map[string]string{"error": "应用不存在"})
}

func appServiceStatesByName(names []string) []map[string]any {
	var out []map[string]any
	for _, service := range managedServices() {
		for _, name := range names {
			if service["name"] == name {
				out = append(out, service)
			}
		}
	}
	return out
}

func appActions(spec appSpec, installed bool) []string {
	if installed {
		actions := []string{"update", "uninstall"}
		if len(spec.Update) == 0 {
			actions = actions[1:]
		}
		if len(spec.Remove) == 0 {
			actions = actions[:1]
		}
		return actions
	}
	return []string{"install"}
}

func appServiceStates(id string) []map[string]any {
	names := map[string][]string{
		"lnmp":       {"nginx", "mariadb", "php8.2-fpm"},
		"php":        {"php8.2-fpm"},
		"docker":     {"docker"},
		"redis":      {"redis-server"},
		"postgres":   {"postgresql"},
		"fail2ban":   {"fail2ban"},
		"nftables":   {"nftables"},
		"supervisor": {"supervisor"},
		"memcached":  {"memcached"},
		"rabbitmq":   {"rabbitmq-server"},
		"haproxy":    {"haproxy"},
		"postfix":    {"postfix"},
		"samba":      {"smbd"},
		"clamav":     {"clamav-daemon"},
		"wordpress":  {"nginx", "mariadb", "php8.2-fpm"},
	}[id]
	var out []map[string]any
	for _, service := range managedServices() {
		for _, name := range names {
			if service["name"] == name {
				out = append(out, service)
			}
		}
	}
	return out
}

func appConfigHints(id string) []map[string]string {
	switch id {
	case "lnmp":
		return []map[string]string{
			{"label": "Nginx vhost", "value": env("TAF_NGINX_VHOST_DIR", "/usr/local/nginx/conf/vhost")},
			{"label": "SSL 目录", "value": env("TAF_NGINX_SSL_DIR", "/usr/local/nginx/conf/ssl")},
			{"label": "网站根目录", "value": fileRoot()},
		}
	case "docker":
		return []map[string]string{{"label": "Compose", "value": "docker compose"}}
	case "redis":
		return []map[string]string{{"label": "服务名", "value": "redis-server"}, {"label": "默认端口", "value": "6379"}}
	case "postgres":
		return []map[string]string{{"label": "服务名", "value": "postgresql"}, {"label": "默认端口", "value": "5432"}}
	case "fail2ban":
		return []map[string]string{{"label": "配置目录", "value": "/etc/fail2ban"}}
	case "nftables":
		return []map[string]string{{"label": "面板规则文件", "value": "tryallfun-panel.nft"}, {"label": "表名", "value": "inet tryallfun"}}
	default:
		return nil
	}
}

func (a *app) handleServiceAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	var in struct{ Service, Action string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if !knownService(in.Service) || !oneOf(in.Action, "start", "stop", "restart", "enable", "disable") {
		writeJSON(w, 400, map[string]string{"error": "不支持的服务或操作"})
		return
	}
	out, err := runCommand(30*time.Second, "systemctl", in.Action, in.Service)
	a.audit(r, "service."+in.Action, in.Service, err == nil, outOrErr(out, err))
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": outOrErr(out, err)})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "status": serviceStatus(in.Service)})
}

func knownService(name string) bool {
	for _, s := range serviceSpecs {
		if s.Name == name {
			return true
		}
	}
	return false
}

func (a *app) handleAppAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	var in struct{ ID, Action string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if !oneOf(in.Action, "install", "update", "uninstall") {
		writeJSON(w, 400, map[string]string{"error": "不支持的应用操作"})
		return
	}
	var selected *appSpec
	for _, spec := range a.allCatalog() {
		if spec.ID == in.ID {
			copy := spec
			selected = &copy
			break
		}
	}
	if selected == nil {
		writeJSON(w, 404, map[string]string{"error": "应用不存在"})
		return
	}
	installed := appInstalled(*selected)
	if in.Action == "install" && installed {
		writeJSON(w, 409, map[string]string{"error": "应用已经安装"})
		return
	}
	if in.Action != "install" && !installed {
		writeJSON(w, 409, map[string]string{"error": "应用尚未安装"})
		return
	}
	commands := selected.Commands
	verb := "安装"
	if in.Action == "update" {
		commands, verb = selected.Update, "更新"
	} else if in.Action == "uninstall" {
		commands, verb = selected.Remove, "卸载"
	}
	if len(commands) == 0 {
		writeJSON(w, 400, map[string]string{"error": "此应用暂不支持该操作"})
		return
	}
	j := a.startJob(verb+" "+selected.Name, commands, r)
	writeJSON(w, 202, j)
}

func appInstalled(spec appSpec) bool {
	if len(spec.Checks) == 0 {
		return false
	}
	for _, check := range spec.Checks {
		if !commandExists(check) {
			return false
		}
	}
	return true
}

func (a *app) startJob(name string, commands []string, r *http.Request) *job {
	return a.startJobWithSecrets(name, commands, nil, r)
}

func (a *app) startSensitiveJob(name string, commands, secrets []string, r *http.Request) *job {
	return a.startJobWithSecrets(name, commands, secrets, r)
}

func (a *app) startJobWithSecrets(name string, commands, secrets []string, r *http.Request) *job {
	j := &job{ID: fmt.Sprintf("%d-%s", time.Now().UnixNano(), randomToken(4)), Name: name, Status: "running", Started: time.Now()}
	a.mu.Lock()
	a.jobs[j.ID] = j
	a.mu.Unlock()
	go func() {
		var output strings.Builder
		var finalErr error
		for _, command := range commands {
			if len(secrets) > 0 {
				output.WriteString("$ [敏感命令已隐藏]\n")
			} else {
				output.WriteString("$ " + command + "\n")
			}
			out, err := runShell(20*time.Minute, command)
			output.WriteString(redactSecrets(out, secrets) + "\n")
			if output.Len() > 512*1024 {
				s := output.String()
				output.Reset()
				output.WriteString(s[len(s)-512*1024:])
			}
			if err != nil {
				finalErr = err
				break
			}
		}
		a.mu.Lock()
		j.Output = output.String()
		j.Finished = time.Now()
		if finalErr != nil {
			j.Status = "failed"
			j.Error = finalErr.Error()
		} else {
			j.Status = "success"
		}
		a.mu.Unlock()
		a.audit(r, "job.run", name, finalErr == nil, outOrErr(j.Output, finalErr))
		a.sendNotification("job", name, j.Status)
	}()
	return j
}

func (a *app) handleJobs(w http.ResponseWriter, r *http.Request) {
	if !a.requireRole(w, r, "admin", "operator") {
		return
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if id := r.URL.Query().Get("id"); id != "" {
		j, ok := a.jobs[id]
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "任务不存在"})
			return
		}
		writeJSON(w, 200, j)
		return
	}
	items := make([]*job, 0, len(a.jobs))
	for _, j := range a.jobs {
		items = append(items, j)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Started.After(items[j].Started) })
	if len(items) > 30 {
		items = items[:30]
	}
	writeJSON(w, 200, items)
}

func (a *app) handleSites(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dir := env("TAF_NGINX_VHOST_DIR", "/usr/local/nginx/conf/vhost")
	files, _ := filepath.Glob(filepath.Join(dir, "*.conf"))
	disabled, _ := filepath.Glob(filepath.Join(dir, "*.conf.disabled"))
	files = append(files, disabled...)
	sites := make([]map[string]any, 0, len(files))
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		text := string(b)
		names := parseServerNames(text)
		sites = append(sites, map[string]any{
			"file": filepath.Base(file), "domains": names, "enabled": !strings.HasSuffix(file, ".disabled"),
			"managed":  strings.Contains(text, "managed-by: tryallfun-panel"),
			"tls":      strings.Contains(text, "listen 443") || strings.Contains(text, "listen 443 ssl"),
			"type":     siteType(text),
			"root":     parseRoot(text),
			"upstream": parseProxyPass(text),
		})
	}
	writeJSON(w, 200, sites)
}

func (a *app) handleSiteDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	file := r.URL.Query().Get("file")
	if !safeNameRE.MatchString(file) {
		writeJSON(w, 400, map[string]string{"error": "配置文件名无效"})
		return
	}
	target := filepath.Join(env("TAF_NGINX_VHOST_DIR", "/usr/local/nginx/conf/vhost"), filepath.Base(file))
	b, err := os.ReadFile(target)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": "配置不存在"})
		return
	}
	text := string(b)
	writeJSON(w, 200, map[string]any{
		"file": filepath.Base(target), "domains": parseServerNames(text), "enabled": !strings.HasSuffix(target, ".disabled"),
		"managed": strings.Contains(text, "managed-by: tryallfun-panel"), "tls": strings.Contains(text, "listen 443") || strings.Contains(text, "listen 443 ssl"),
		"type": siteType(text), "root": parseRoot(text), "upstream": parseProxyPass(text), "content": text,
	})
}

func (a *app) handleSiteAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	var in struct {
		Action   string `json:"action"`
		Domain   string `json:"domain"`
		Type     string `json:"type"`
		Root     string `json:"root"`
		Upstream string `json:"upstream"`
		TLS      bool   `json:"tls"`
		File     string `json:"file"`
		Content  string `json:"content"`
		OriginIP string `json:"originIP"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	dir := env("TAF_NGINX_VHOST_DIR", "/usr/local/nginx/conf/vhost")
	switch in.Action {
	case "create":
		if !domainRE.MatchString(in.Domain) || !oneOf(in.Type, "static", "php", "proxy") {
			writeJSON(w, 400, map[string]string{"error": "域名或网站类型无效"})
			return
		}
		if in.Type == "static" || in.Type == "php" {
			if in.Root == "" {
				in.Root = filepath.Join(env("TAF_FILE_ROOT", "/home/wwwroot"), in.Domain, "public")
			}
			if _, err := safePath(env("TAF_FILE_ROOT", "/home/wwwroot"), in.Root); err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			if err := os.MkdirAll(in.Root, 0755); err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
		} else if !validUpstream(in.Upstream) {
			writeJSON(w, 400, map[string]string{"error": "反向代理地址必须是 http:// 或 https:// 地址"})
			return
		}
		target := filepath.Join(dir, in.Domain+".conf")
		if _, err := os.Stat(target); err == nil {
			writeJSON(w, 409, map[string]string{"error": "该站点配置已存在"})
			return
		}
		conf, err := buildSiteConfig(in.Domain, in.Type, in.Root, in.Upstream, in.TLS)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if err := writeAndReloadNginx(target, []byte(conf)); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if in.Type == "proxy" && strings.TrimSpace(in.OriginIP) != "" {
			if err := updateHostsOverride(in.Domain, strings.TrimSpace(in.OriginIP)); err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
		}
		a.audit(r, "site.create", in.Domain, true, in.Type)
	case "edit":
		if !safeNameRE.MatchString(in.File) || len(in.Content) == 0 || len(in.Content) > 128*1024 || strings.ContainsRune(in.Content, 0) {
			writeJSON(w, 400, map[string]string{"error": "配置文件名或内容无效"})
			return
		}
		target := filepath.Join(dir, filepath.Base(in.File))
		if err := writeSiteConfigWithRollback(target, []byte(in.Content)); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		a.audit(r, "site.edit", in.File, true, "nginx 配置已通过检查并重载")
	case "disable":
		if !safeNameRE.MatchString(in.File) || strings.HasSuffix(in.File, ".disabled") {
			writeJSON(w, 400, map[string]string{"error": "配置文件名无效"})
			return
		}
		target := filepath.Join(dir, filepath.Base(in.File))
		disabled := target + ".disabled"
		if err := renameSiteConfigAndReload(target, disabled); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		a.audit(r, "site.disable", in.File, true, "站点已暂停")
	case "enable":
		if !safeNameRE.MatchString(in.File) || !strings.HasSuffix(in.File, ".disabled") {
			writeJSON(w, 400, map[string]string{"error": "配置文件名无效"})
			return
		}
		target := filepath.Join(dir, filepath.Base(in.File))
		enabled := strings.TrimSuffix(target, ".disabled")
		if err := renameSiteConfigAndReload(target, enabled); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		a.audit(r, "site.enable", in.File, true, "站点已启用")
	case "delete":
		if !safeNameRE.MatchString(in.File) {
			writeJSON(w, 400, map[string]string{"error": "配置文件名无效"})
			return
		}
		target := filepath.Join(dir, filepath.Base(in.File))
		b, err := os.ReadFile(target)
		if err != nil || !bytes.Contains(b, []byte("managed-by: tryallfun-panel")) {
			writeJSON(w, 403, map[string]string{"error": "只能删除由面板创建的网站"})
			return
		}
		backup := target + ".bak." + time.Now().Format("20060102150405")
		if err := os.Rename(target, backup); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if out, err := runCommand(15*time.Second, nginxBin(), "-t"); err != nil {
			_ = os.Rename(backup, target)
			writeJSON(w, 500, map[string]string{"error": outOrErr(out, err)})
			return
		}
		_, _ = runCommand(15*time.Second, nginxBin(), "-s", "reload")
		a.audit(r, "site.delete", in.File, true, "配置已备份为 "+filepath.Base(backup))
	default:
		writeJSON(w, 400, map[string]string{"error": "不支持的网站操作"})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func parseServerNames(text string) []string {
	re := regexp.MustCompile(`(?m)^\s*server_name\s+([^;]+);`)
	matches := re.FindAllStringSubmatch(text, -1)
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		for _, name := range strings.Fields(m[1]) {
			if name != "_" && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}

func siteType(text string) string {
	if strings.Contains(text, "proxy_pass") {
		return "反向代理"
	}
	if strings.Contains(text, "fastcgi_pass") {
		return "PHP / 动态站点"
	}
	return "静态网站"
}

func parseRoot(text string) string {
	re := regexp.MustCompile(`(?m)^\s*root\s+([^;]+);`)
	if m := re.FindStringSubmatch(text); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func parseProxyPass(text string) string {
	re := regexp.MustCompile(`(?m)^\s*proxy_pass\s+([^;]+);`)
	if m := re.FindStringSubmatch(text); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func validUpstream(v string) bool {
	return (strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://")) &&
		!strings.ContainsAny(v, "\r\n;{}")
}

func buildSiteConfig(domain, kind, root, upstream string, tls bool) (string, error) {
	if strings.ContainsAny(domain+root+upstream, "\r\n{};") {
		return "", errors.New("配置参数包含非法字符")
	}
	body := fmt.Sprintf(`root %s;
    index index.html index.htm;
    location / {
        try_files $uri $uri/ /index.html;
    }`, root)
	if kind == "php" {
		body = fmt.Sprintf(`root %s;
    index index.php index.html index.htm;
    location / {
        try_files $uri $uri/ /index.php?$args;
    }
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
    }
    location ~ /\. {
        deny all;
    }`, root)
	}
	if kind == "proxy" {
		body = fmt.Sprintf(`location / {
        proxy_pass %s;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
    }`, strings.TrimRight(upstream, "/"))
	}
	var b strings.Builder
	b.WriteString("# managed-by: tryallfun-panel\n")
	if tls {
		cert, key := findCertificate(domain)
		if cert == "" {
			return "", errors.New("未找到覆盖该域名的证书，请先在安全中心配置证书")
		}
		fmt.Fprintf(&b, `server {
    listen 80;
    server_name %s;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl;
    http2 on;
    server_name %s;
    ssl_certificate %s;
    ssl_certificate_key %s;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 2g;
    %s
}
`, domain, domain, cert, key, body)
	} else {
		fmt.Fprintf(&b, `server {
    listen 80;
    server_name %s;
    client_max_body_size 2g;
    %s
}
`, domain, body)
	}
	return b.String(), nil
}

func findCertificate(domain string) (string, string) {
	sslRoot := env("TAF_NGINX_SSL_DIR", "/usr/local/nginx/conf/ssl")
	candidates := []string{domain}
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		candidates = append(candidates, "www."+strings.Join(parts[len(parts)-2:], "."))
	}
	for _, name := range candidates {
		cert := filepath.Join(sslRoot, name, "fullchain.cer")
		key := filepath.Join(sslRoot, name, name+".key")
		if fileExists(cert) && fileExists(key) {
			return cert, key
		}
	}
	return "", ""
}

func writeAndReloadNginx(target string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	if err := atomicWrite(target, data, 0644); err != nil {
		return err
	}
	if out, err := runCommand(15*time.Second, nginxBin(), "-t"); err != nil {
		_ = os.Remove(target)
		return errors.New(outOrErr(out, err))
	}
	if out, err := runCommand(15*time.Second, nginxBin(), "-s", "reload"); err != nil {
		return errors.New(outOrErr(out, err))
	}
	return nil
}

func writeSiteConfigWithRollback(target string, data []byte) error {
	old, err := os.ReadFile(target)
	if err != nil {
		return err
	}
	mode := os.FileMode(0644)
	if info, statErr := os.Stat(target); statErr == nil {
		mode = info.Mode().Perm()
	}
	backup := target + ".bak." + time.Now().Format("20060102150405")
	_ = os.WriteFile(backup, old, mode)
	if err := atomicWrite(target, data, mode); err != nil {
		return err
	}
	if out, err := runCommand(15*time.Second, nginxBin(), "-t"); err != nil {
		_ = atomicWrite(target, old, mode)
		return errors.New(outOrErr(out, err))
	}
	if out, err := runCommand(15*time.Second, nginxBin(), "-s", "reload"); err != nil {
		_ = atomicWrite(target, old, mode)
		return errors.New(outOrErr(out, err))
	}
	return nil
}

func renameSiteConfigAndReload(from, to string) error {
	if _, err := os.Stat(from); err != nil {
		return err
	}
	if fileExists(to) {
		return fmt.Errorf("目标配置已存在: %s", filepath.Base(to))
	}
	if err := os.Rename(from, to); err != nil {
		return err
	}
	if out, err := runCommand(15*time.Second, nginxBin(), "-t"); err != nil {
		_ = os.Rename(to, from)
		return errors.New(outOrErr(out, err))
	}
	if out, err := runCommand(15*time.Second, nginxBin(), "-s", "reload"); err != nil {
		_ = os.Rename(to, from)
		return errors.New(outOrErr(out, err))
	}
	return nil
}

func updateHostsOverride(domain, ip string) error {
	if !domainRE.MatchString(domain) || net.ParseIP(ip) == nil {
		return errors.New("本地 DNS 覆盖的域名或源站 IP 无效")
	}
	path := "/etc/hosts"
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	marker := "# tryallfun-panel " + domain
	var lines []string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, marker) {
			continue
		}
		lines = append(lines, line)
	}
	lines = append(lines, fmt.Sprintf("%s %s %s", ip, domain, marker))
	return atomicWrite(path, []byte(strings.TrimRight(strings.Join(lines, "\n"), "\n")+"\n"), 0644)
}

func (a *app) handleDatabases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	result := map[string]any{"engines": []map[string]any{
		{"id": "mariadb", "name": "MariaDB", "installed": databaseCLI() != "", "status": serviceStatus("mariadb")},
		{"id": "postgres", "name": "PostgreSQL", "installed": commandExists("psql"), "status": serviceStatus("postgresql")},
		{"id": "redis", "name": "Redis", "installed": commandExists("redis-cli"), "status": serviceStatus("redis-server")},
	}}
	if cli := databaseCLI(); cli != "" {
		out, err := runCommand(15*time.Second, cli, "-NBe", "SHOW DATABASES")
		if err == nil {
			var dbs []string
			for _, name := range strings.Fields(out) {
				if !oneOf(name, "information_schema", "performance_schema", "mysql", "sys") {
					dbs = append(dbs, name)
				}
			}
			result["databases"] = dbs
		}
	}
	writeJSON(w, 200, result)
}

func (a *app) handleDatabaseDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := r.URL.Query().Get("name")
	if !databaseRE.MatchString(name) {
		writeJSON(w, 400, map[string]string{"error": "数据库名无效"})
		return
	}
	cli := databaseCLI()
	if cli == "" {
		writeJSON(w, 409, map[string]string{"error": "未找到 MariaDB/MySQL 客户端"})
		return
	}
	tables, err := databaseTables(cli, name)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	result := map[string]any{"engine": "mariadb", "name": name, "tables": tables}
	if table := r.URL.Query().Get("table"); table != "" {
		if !sqlIdentRE.MatchString(table) {
			writeJSON(w, 400, map[string]string{"error": "表名无效"})
			return
		}
		columns, err := databaseColumns(cli, name, table)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		result["selectedTable"] = table
		result["columns"] = columns
	}
	writeJSON(w, 200, result)
}

func (a *app) handleDatabaseRows(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name, table := r.URL.Query().Get("name"), r.URL.Query().Get("table")
	if !databaseRE.MatchString(name) || !sqlIdentRE.MatchString(table) {
		writeJSON(w, 400, map[string]string{"error": "数据库名或表名无效"})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	result, err := runMySQLQuery(name, fmt.Sprintf("SELECT * FROM %s LIMIT %d", quoteIdent(table), limit), 20*time.Second)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, result)
}

func (a *app) handleDatabaseQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	var in struct {
		Name string `json:"name"`
		SQL  string `json:"sql"`
	}
	if !decodeJSONLimit(w, r, &in, 128<<10) {
		return
	}
	in.SQL = strings.TrimSpace(in.SQL)
	if !databaseRE.MatchString(in.Name) || in.SQL == "" || len(in.SQL) > 64*1024 {
		writeJSON(w, 400, map[string]string{"error": "数据库名或 SQL 无效"})
		return
	}
	if strings.Contains(strings.ToLower(in.SQL), "load data local infile") {
		writeJSON(w, 400, map[string]string{"error": "不允许执行 LOAD DATA LOCAL INFILE"})
		return
	}
	result, err := runMySQLQuery(in.Name, in.SQL, 45*time.Second)
	a.audit(r, "database.query", in.Name, err == nil, truncate(in.SQL, 300))
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, result)
}

func databaseTables(cli, database string) ([]map[string]any, error) {
	sql := fmt.Sprintf(`SELECT TABLE_NAME, TABLE_TYPE, COALESCE(TABLE_ROWS,0), COALESCE(DATA_LENGTH + INDEX_LENGTH,0)
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = '%s'
ORDER BY TABLE_NAME`, sqlString(database))
	out, err := runCommand(20*time.Second, cli, "--batch", "--raw", "--skip-column-names", "-e", sql)
	if err != nil {
		return nil, errors.New(outOrErr(out, err))
	}
	var tables []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		for len(parts) < 4 {
			parts = append(parts, "")
		}
		tables = append(tables, map[string]any{
			"name": parts[0], "type": parts[1], "rows": parts[2], "size": parts[3],
		})
	}
	return tables, nil
}

func databaseColumns(cli, database, table string) ([]map[string]any, error) {
	sql := fmt.Sprintf(`SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY, COALESCE(COLUMN_DEFAULT,''), EXTRA, COALESCE(COLUMN_COMMENT,'')
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = '%s' AND TABLE_NAME = '%s'
ORDER BY ORDINAL_POSITION`, sqlString(database), sqlString(table))
	out, err := runCommand(20*time.Second, cli, "--batch", "--raw", "--skip-column-names", "-e", sql)
	if err != nil {
		return nil, errors.New(outOrErr(out, err))
	}
	var columns []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		for len(parts) < 7 {
			parts = append(parts, "")
		}
		columns = append(columns, map[string]any{
			"name": parts[0], "type": parts[1], "nullable": parts[2], "key": parts[3],
			"default": parts[4], "extra": parts[5], "comment": parts[6],
		})
	}
	return columns, nil
}

func runMySQLQuery(database, query string, timeout time.Duration) (map[string]any, error) {
	cli := databaseCLI()
	if cli == "" {
		return nil, errors.New("未找到 MariaDB/MySQL 客户端")
	}
	args := []string{"--batch", "--raw", "-D", database, "-e", query}
	out, err := runCommand(timeout, cli, args...)
	if err != nil {
		return nil, errors.New(outOrErr(out, err))
	}
	columns, rows := parseTSV(out)
	return map[string]any{"columns": columns, "rows": rows, "output": out}, nil
}

func parseTSV(out string) ([]string, []map[string]string) {
	out = strings.TrimRight(out, "\r\n")
	if out == "" {
		return nil, nil
	}
	lines := strings.Split(out, "\n")
	columns := strings.Split(lines[0], "\t")
	var rows []map[string]string
	for _, line := range lines[1:] {
		values := strings.Split(line, "\t")
		row := map[string]string{}
		for i, col := range columns {
			key := col
			if key == "" {
				key = fmt.Sprintf("column_%d", i+1)
			}
			if i < len(values) {
				row[key] = values[i]
			} else {
				row[key] = ""
			}
		}
		rows = append(rows, row)
	}
	return columns, rows
}

func sqlString(s string) string  { return strings.ReplaceAll(s, "'", "''") }
func quoteIdent(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }

func (a *app) handleDatabaseAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	var in struct{ Action, Engine, Name, User, Password, Confirm string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Engine != "mariadb" || !databaseRE.MatchString(in.Name) {
		writeJSON(w, 400, map[string]string{"error": "当前仅支持 MariaDB，且数据库名必须是字母数字下划线"})
		return
	}
	var sql string
	switch in.Action {
	case "create":
		if in.User == "" {
			in.User = in.Name
		}
		if !databaseRE.MatchString(in.User) || len(in.Password) < 12 || strings.ContainsAny(in.Password, "'\r\n\\") {
			writeJSON(w, 400, map[string]string{"error": "数据库用户无效，密码至少 12 位且不能包含引号、反斜线或换行"})
			return
		}
		sql = fmt.Sprintf("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER '%s'@'localhost' IDENTIFIED BY '%s'; GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'localhost'; FLUSH PRIVILEGES;", in.Name, in.User, in.Password, in.Name, in.User)
	case "drop":
		if in.Confirm != in.Name {
			writeJSON(w, 400, map[string]string{"error": "删除确认文本必须与数据库名一致"})
			return
		}
		sql = fmt.Sprintf("DROP DATABASE `%s`;", in.Name)
	default:
		writeJSON(w, 400, map[string]string{"error": "不支持的数据库操作"})
		return
	}
	cli := databaseCLI()
	if cli == "" {
		writeJSON(w, 409, map[string]string{"error": "未找到 MariaDB/MySQL 客户端"})
		return
	}
	out, err := runCommandInput(30*time.Second, sql, cli)
	a.audit(r, "database."+in.Action, in.Name, err == nil, outOrErr(out, err))
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": outOrErr(out, err)})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *app) handleFiles(w http.ResponseWriter, r *http.Request) {
	root := fileRoot()
	if r.Method == http.MethodPost {
		if !a.requireMaintenance(w, r) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 128<<20)
		if err := r.ParseMultipartForm(128 << 20); err != nil {
			writeJSON(w, 400, map[string]string{"error": "上传内容无效或超过 128MB"})
			return
		}
		dir, err := safePath(root, r.FormValue("path"))
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "缺少上传文件"})
			return
		}
		defer file.Close()
		name := filepath.Base(header.Filename)
		if !safeNameRE.MatchString(name) {
			writeJSON(w, 400, map[string]string{"error": "文件名无效"})
			return
		}
		target := filepath.Join(dir, name)
		dst, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			writeJSON(w, 409, map[string]string{"error": err.Error()})
			return
		}
		_, copyErr := io.Copy(dst, file)
		closeErr := dst.Close()
		if copyErr != nil || closeErr != nil {
			_ = os.Remove(target)
			writeJSON(w, 500, map[string]string{"error": "上传写入失败"})
			return
		}
		a.audit(r, "file.upload", target, true, fmt.Sprintf("%d bytes", header.Size))
		writeJSON(w, 201, map[string]bool{"ok": true})
		return
	}
	pathValue := r.URL.Query().Get("path")
	if pathValue == "" {
		pathValue = root
	}
	clean, err := safePath(root, pathValue)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	entries, err := os.ReadDir(clean)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	items := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		items = append(items, map[string]any{
			"name": entry.Name(), "dir": entry.IsDir(), "size": info.Size(),
			"modified": info.ModTime(), "mode": info.Mode().Perm().String(),
			"path": filepath.Join(clean, entry.Name()),
		})
	}
	sort.Slice(items, func(i, j int) bool {
		di, dj := items[i]["dir"].(bool), items[j]["dir"].(bool)
		if di != dj {
			return di
		}
		return strings.ToLower(items[i]["name"].(string)) < strings.ToLower(items[j]["name"].(string))
	})
	writeJSON(w, 200, map[string]any{"path": clean, "root": root, "items": items})
}

func fileRoot() string {
	root := env("TAF_FILE_ROOT", "/home/wwwroot")
	if runtime.GOOS == "windows" {
		root = "."
	}
	return root
}

func (a *app) handleFileContent(w http.ResponseWriter, r *http.Request) {
	clean, err := safePath(fileRoot(), r.URL.Query().Get("path"))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if r.Method == http.MethodGet {
		info, err := os.Stat(clean)
		if err != nil || info.IsDir() || info.Size() > 2<<20 {
			writeJSON(w, 400, map[string]string{"error": "只能编辑 2MB 以内的普通文件"})
			return
		}
		b, err := os.ReadFile(clean)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"path": clean, "content": string(b), "mode": info.Mode().Perm().String()})
		return
	}
	if r.Method == http.MethodPut {
		if !a.requireMaintenance(w, r) {
			return
		}
		var in struct{ Content string }
		if !decodeJSONLimit(w, r, &in, 3<<20) {
			return
		}
		if len(in.Content) > 2<<20 {
			writeJSON(w, 400, map[string]string{"error": "文件内容不能超过 2MB"})
			return
		}
		info, err := os.Stat(clean)
		if err != nil || info.IsDir() {
			writeJSON(w, 400, map[string]string{"error": "目标不是可编辑文件"})
			return
		}
		_ = backupFile(clean)
		if err := atomicWrite(clean, []byte(in.Content), info.Mode().Perm()); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		a.audit(r, "file.write", clean, true, fmt.Sprintf("%d bytes", len(in.Content)))
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (a *app) handleFileAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	var in struct{ Action, Path, Name, Mode, Format, Confirm string }
	if !decodeJSON(w, r, &in) {
		return
	}
	clean, err := safePath(fileRoot(), in.Path)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	switch in.Action {
	case "mkdir":
		if !safeNameRE.MatchString(in.Name) {
			err = errors.New("目录名无效")
		} else {
			err = os.Mkdir(filepath.Join(clean, in.Name), 0755)
		}
	case "rename":
		if !safeNameRE.MatchString(in.Name) {
			err = errors.New("新名称无效")
		} else {
			err = os.Rename(clean, filepath.Join(filepath.Dir(clean), in.Name))
		}
	case "chmod":
		var n uint64
		n, err = strconv.ParseUint(in.Mode, 8, 32)
		if err == nil {
			err = os.Chmod(clean, os.FileMode(n))
		}
	case "delete":
		if in.Confirm != filepath.Base(clean) {
			err = errors.New("删除确认文本与文件名不一致")
		} else {
			info, statErr := os.Stat(clean)
			if statErr != nil {
				err = statErr
			} else if info.IsDir() {
				err = os.Remove(clean)
			} else {
				err = os.Remove(clean)
			}
		}
	case "archive", "extract", "trash":
		err = a.handleFileAdvancedAction(w, r, struct{ Action, Path, Name, Format, Confirm string }{
			in.Action, in.Path, in.Name, in.Format, in.Confirm,
		})
	default:
		err = errors.New("不支持的文件操作")
	}
	a.audit(r, "file."+in.Action, clean, err == nil, outOrErr("", err))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *app) handleFirewall(w http.ResponseWriter, r *http.Request) {
	rules := a.loadFirewallRules()
	writeJSON(w, 200, map[string]any{
		"installed": commandExists("nft"), "enabled": nftTableExists(), "backend": "nftables",
		"rules": rules,
	})
}

func (a *app) handleFirewallAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	var in struct {
		Action, ID, Direction, Protocol, Source, Destination, RuleAction, Note string
		Port                                                                   int
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if !commandExists("nft") {
		writeJSON(w, 409, map[string]string{"error": "请先在应用商店安装 nftables"})
		return
	}
	rules := a.loadFirewallRules()
	switch in.Action {
	case "enable":
	case "add":
		direction := strings.ToLower(strings.TrimSpace(in.Direction))
		if direction == "" {
			direction = "in"
		}
		source := strings.TrimSpace(in.Source)
		destination := strings.TrimSpace(in.Destination)
		if source == "" {
			source = "0.0.0.0/0"
		}
		if destination == "" {
			destination = "0.0.0.0/0"
		}
		if in.Port < 0 || in.Port > 65535 || !oneOf(direction, "in", "out") || !oneOf(strings.ToLower(in.Protocol), "tcp", "udp") ||
			!oneOf(in.RuleAction, "allow", "deny") || !validSource(source) || !validSource(destination) || !sameAddressFamily(source, destination) {
			writeJSON(w, 400, map[string]string{"error": "防火墙规则参数无效"})
			return
		}
		rules = append(rules, firewallRule{ID: randomToken(8), Direction: direction, Port: in.Port, Protocol: strings.ToLower(in.Protocol), Source: source, Destination: destination, Action: in.RuleAction, Note: cleanNote(in.Note)})
	case "delete":
		for _, rule := range rules {
			if rule.ID == in.ID && (rule.Direction == "" || rule.Direction == "in") && rule.Action == "allow" && rule.Protocol == "tcp" && rule.Port == sshPort() {
				writeJSON(w, 400, map[string]string{"error": "不能删除当前 SSH 端口的保护规则，请先添加新的 SSH 放行规则"})
				return
			}
		}
		filtered := rules[:0]
		for _, rule := range rules {
			if rule.ID != in.ID {
				filtered = append(filtered, rule)
			}
		}
		rules = filtered
	default:
		writeJSON(w, 400, map[string]string{"error": "不支持的防火墙操作"})
		return
	}
	if err := a.applyFirewallRules(rules); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	a.audit(r, "firewall."+in.Action, in.ID, true, fmt.Sprintf("%d rules", len(rules)))
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *app) loadFirewallRules() []firewallRule {
	path := filepath.Join(a.dataDir, "firewall.json")
	var rules []firewallRule
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &rules)
	}
	if len(rules) == 0 {
		rules = []firewallRule{
			{ID: randomToken(8), Direction: "in", Port: sshPort(), Protocol: "tcp", Source: "0.0.0.0/0", Destination: "0.0.0.0/0", Action: "allow", Note: "SSH"},
			{ID: randomToken(8), Direction: "in", Port: 80, Protocol: "tcp", Source: "0.0.0.0/0", Destination: "0.0.0.0/0", Action: "allow", Note: "HTTP"},
			{ID: randomToken(8), Direction: "in", Port: 443, Protocol: "tcp", Source: "0.0.0.0/0", Destination: "0.0.0.0/0", Action: "allow", Note: "HTTPS"},
		}
	}
	for i := range rules {
		if rules[i].Direction == "" {
			rules[i].Direction = "in"
		}
		if rules[i].Source == "" {
			rules[i].Source = "0.0.0.0/0"
		}
		if rules[i].Destination == "" {
			rules[i].Destination = "0.0.0.0/0"
		}
	}
	return rules
}

func (a *app) applyFirewallRules(rules []firewallRule) error {
	var b strings.Builder
	b.WriteString("table inet tryallfun {\n chain input {\n  type filter hook input priority -10; policy drop;\n  ct state established,related accept\n  iifname \"lo\" accept\n  ip protocol icmp accept\n  ip6 nexthdr ipv6-icmp accept\n")
	for _, rule := range rules {
		if rule.Direction == "" || rule.Direction == "in" {
			appendFirewallRule(&b, rule)
		}
	}
	b.WriteString(" }\n chain output {\n  type filter hook output priority -10; policy accept;\n  ct state established,related accept\n  oifname \"lo\" accept\n")
	for _, rule := range rules {
		if rule.Direction == "out" {
			appendFirewallRule(&b, rule)
		}
	}
	b.WriteString(" }\n}\n")
	conf := filepath.Join(a.dataDir, "tryallfun-panel.nft")
	if err := atomicWrite(conf, []byte(b.String()), 0600); err != nil {
		return err
	}
	if out, err := runCommand(15*time.Second, "nft", "-c", "-f", conf); err != nil {
		return errors.New(outOrErr(out, err))
	}
	_, _ = runCommand(10*time.Second, "nft", "delete", "table", "inet", "tryallfun")
	if out, err := runCommand(15*time.Second, "nft", "-f", conf); err != nil {
		return errors.New(outOrErr(out, err))
	}
	data, _ := json.MarshalIndent(rules, "", "  ")
	return atomicWrite(filepath.Join(a.dataDir, "firewall.json"), data, 0600)
}

func nftTableExists() bool {
	if !commandExists("nft") {
		return false
	}
	return exec.Command("nft", "list", "table", "inet", "tryallfun").Run() == nil
}

func appendFirewallRule(b *strings.Builder, rule firewallRule) {
	action := "accept"
	if rule.Action == "deny" {
		action = "drop"
	}
	var parts []string
	if expr := nftAddressExpr("saddr", rule.Source); expr != "" {
		parts = append(parts, expr)
	}
	if expr := nftAddressExpr("daddr", rule.Destination); expr != "" {
		parts = append(parts, expr)
	}
	if rule.Port > 0 {
		parts = append(parts, fmt.Sprintf("%s dport %d", rule.Protocol, rule.Port))
	} else {
		parts = append(parts, fmt.Sprintf("meta l4proto %s", rule.Protocol))
	}
	parts = append(parts, action, "comment "+strconv.Quote(rule.Note))
	fmt.Fprintf(b, "  %s\n", strings.Join(parts, " "))
}

func nftAddressExpr(kind, value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "0.0.0.0/0" || value == "::/0" {
		return ""
	}
	family := "ip"
	if strings.Contains(value, ":") {
		family = "ip6"
	}
	return fmt.Sprintf("%s %s %s", family, kind, value)
}

func validSource(s string) bool {
	if s == "" {
		return false
	}
	if strings.ContainsAny(s, " \t\r\n;{}") {
		return false
	}
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

func sameAddressFamily(a, b string) bool {
	return addressFamily(a) == addressFamily(b)
}

func addressFamily(s string) string {
	if strings.Contains(s, ":") {
		return "ip6"
	}
	return "ip"
}

func cleanNote(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == '"' || r == '\\' {
			return -1
		}
		return r
	}, s)
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

func (a *app) handleTerminal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	var in struct{ Command, Confirm string }
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Command = strings.TrimSpace(in.Command)
	if in.Command == "" || len(in.Command) > 4096 {
		writeJSON(w, 400, map[string]string{"error": "命令不能为空且不能超过 4096 字符"})
		return
	}
	if in.Confirm != "EXECUTE" {
		writeJSON(w, 400, map[string]string{"error": "请确认执行高风险命令"})
		return
	}
	out, err := runShell(45*time.Second, in.Command)
	a.audit(r, "terminal.execute", truncate(in.Command, 160), err == nil, truncate(outOrErr(out, err), 2000))
	code := 200
	if err != nil {
		code = 500
	}
	writeJSON(w, code, map[string]any{"output": out, "error": errorString(err)})
}

func (a *app) handleSecurity(w http.ResponseWriter, _ *http.Request) {
	tls := scanCertificates()
	a.mu.RLock()
	twoFactor := a.cfg.TOTPEnabled
	a.mu.RUnlock()
	writeJSON(w, 200, map[string]any{
		"sshPort": sshPort(), "ssh": sshSettings(), "tls": tls,
		"twoFactor": twoFactor, "audit": true, "score": securityScore(tls),
	})
}

func (a *app) handleSecurityAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	var in struct {
		Action, Confirm, RootPassword string
		Port                          int
		PasswordAuth, RootLogin       bool
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	switch in.Action {
	case "ssh":
		if in.Confirm != "APPLY SSH" || in.Port < 1 || in.Port > 65535 {
			writeJSON(w, 400, map[string]string{"error": "SSH 参数或确认文本无效"})
			return
		}
		content := fmt.Sprintf("# managed-by: tryallfun-panel\nPort %d\nPasswordAuthentication %s\nPermitRootLogin %s\nPubkeyAuthentication yes\n",
			in.Port, yesNo(in.PasswordAuth), rootLoginValue(in.RootLogin))
		target := "/etc/ssh/sshd_config.d/99-tryallfun-panel.conf"
		if old, err := os.ReadFile(target); err == nil {
			_ = os.WriteFile(target+".bak."+time.Now().Format("20060102150405"), old, 0600)
		}
		if err := atomicWrite(target, []byte(content), 0600); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if out, err := runCommand(15*time.Second, "sshd", "-t"); err != nil {
			_ = os.Remove(target)
			writeJSON(w, 500, map[string]string{"error": outOrErr(out, err)})
			return
		}
		out, err := runCommand(20*time.Second, "systemctl", "reload", "ssh")
		a.audit(r, "security.ssh", fmt.Sprintf("port=%d", in.Port), err == nil, outOrErr(out, err))
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": outOrErr(out, err)})
			return
		}
	case "root-password":
		if in.Confirm != "CHANGE ROOT PASSWORD" {
			writeJSON(w, 400, map[string]string{"error": "确认文本无效"})
			return
		}
		if err := validateStrongPassword(in.RootPassword); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		out, err := runCommandInput(20*time.Second, "root:"+in.RootPassword+"\n", "chpasswd")
		a.audit(r, "security.root-password", "root", err == nil, outOrErr(out, err))
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": outOrErr(out, err)})
			return
		}
	default:
		writeJSON(w, 400, map[string]string{"error": "不支持的安全操作"})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func sshSettings() map[string]any {
	out, _ := runCommand(10*time.Second, "sshd", "-T")
	result := map[string]any{"passwordAuth": false, "rootLogin": false, "pubkeyAuth": true}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[0] {
		case "passwordauthentication":
			result["passwordAuth"] = fields[1] == "yes"
		case "permitrootlogin":
			result["rootLogin"] = fields[1] == "yes"
		case "pubkeyauthentication":
			result["pubkeyAuth"] = fields[1] == "yes"
		}
	}
	return result
}

func scanCertificates() []map[string]any {
	root := env("TAF_NGINX_SSL_DIR", "/usr/local/nginx/conf/ssl")
	var out []map[string]any
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || (!strings.HasSuffix(d.Name(), ".cer") && !strings.HasSuffix(d.Name(), ".pem")) {
			return nil
		}
		text, cmdErr := runCommand(10*time.Second, "openssl", "x509", "-in", path, "-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName")
		if cmdErr == nil {
			out = append(out, map[string]any{"path": path, "detail": text})
		}
		return nil
	})
	if len(out) > 30 {
		out = out[:30]
	}
	return out
}

func securityScore(certs []map[string]any) int {
	score := 55
	ssh := sshSettings()
	if ssh["pubkeyAuth"] == true {
		score += 15
	}
	if ssh["passwordAuth"] == false {
		score += 10
	}
	if ssh["rootLogin"] == false {
		score += 10
	}
	if len(certs) > 0 {
		score += 10
	}
	return score
}

func (a *app) handleAudit(w http.ResponseWriter, r *http.Request) {
	if !a.requireRole(w, r, "admin", "operator") {
		return
	}
	path := filepath.Join(a.dataDir, "audit.jsonl")
	f, err := os.Open(path)
	if err != nil {
		writeJSON(w, 200, []auditEntry{})
		return
	}
	defer f.Close()
	var entries []auditEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 2<<20)
	for scanner.Scan() {
		var entry auditEntry
		if json.Unmarshal(scanner.Bytes(), &entry) == nil {
			entries = append(entries, entry)
		}
	}
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	if len(entries) > 200 {
		entries = entries[:200]
	}
	writeJSON(w, 200, entries)
}

func (a *app) audit(r *http.Request, action, target string, success bool, detail string) {
	entry := auditEntry{time.Now(), action, target, success, truncate(detail, 4000), clientIP(r)}
	b, _ := json.Marshal(entry)
	path := filepath.Join(a.dataDir, "audit.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		_, _ = f.Write(append(b, '\n'))
		_ = f.Close()
	}
}

func (a *app) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.mu.RLock()
		name, admin := a.cfg.PanelName, a.cfg.Admin
		a.mu.RUnlock()
		if name == "" {
			name = "TryAllFun Panel"
		}
		writeJSON(w, 200, map[string]any{
			"panelName": name, "admin": admin, "version": panelVersion,
			"listen": env("TAF_ADDR", addr), "dataDir": a.dataDir, "fileRoot": fileRoot(),
		})
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.requireRole(w, r, "admin") || !a.requireMaintenance(w, r) {
		return
	}
	var in struct{ PanelName, CurrentPassword, NewPassword string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.NewPassword != "" {
		if _, ok := a.authenticateUser(a.sessionUser(r), in.CurrentPassword); !ok {
			writeJSON(w, 403, map[string]string{"error": "当前密码错误"})
			return
		}
		if err := validateStrongPassword(in.NewPassword); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if in.PanelName != "" {
		if len(in.PanelName) > 40 {
			writeJSON(w, 400, map[string]string{"error": "面板名称不能超过 40 字符"})
			return
		}
		a.cfg.PanelName = strings.TrimSpace(in.PanelName)
	}
	if in.NewPassword != "" {
		setAdminPassword(&a.cfg, in.NewPassword)
		a.cfg.SessionKey = base64.RawStdEncoding.EncodeToString(randomBytes(32))
	}
	if err := a.saveConfigUnlocked(); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	a.audit(r, "settings.update", "panel", true, "面板设置已更新")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *app) handleCloudflare(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.mu.RLock()
		cfg := a.cfg
		a.mu.RUnlock()
		writeJSON(w, 200, map[string]any{
			"email": cfg.CloudflareEmail, "zoneID": cfg.CloudflareZoneID,
			"apiKeyMasked": maskSecret(cfg.CloudflareAPIKey), "apiTokenMasked": maskSecret(cfg.CloudflareAPIToken),
			"configured":      (cfg.CloudflareAPIToken != "" || cfg.CloudflareAPIKey != "") && cfg.CloudflareZoneID != "",
			"autoOrangeCloud": cfg.CloudflareAutoOrangeCloud,
			"trafficGB":       cfg.CloudflareTrafficGB, "cpuPercent": cfg.CloudflareCPUPercent, "sustainMinutes": cfg.CloudflareSustainMinutes,
			"lastSwitch": cfg.CloudflareLastSwitch, "lastError": cfg.CloudflareLastError,
		})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	var in struct {
		Email, APIKey, APIToken, ZoneID string
		AutoOrangeCloud                 bool
		TrafficGB, CPUPercent           float64
		SustainMinutes                  int
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Email = strings.TrimSpace(in.Email)
	in.APIKey = strings.TrimSpace(in.APIKey)
	in.APIToken = strings.TrimSpace(in.APIToken)
	in.ZoneID = strings.TrimSpace(in.ZoneID)
	if in.Email != "" && !strings.Contains(in.Email, "@") {
		writeJSON(w, 400, map[string]string{"error": "Cloudflare 邮箱无效"})
		return
	}
	if in.ZoneID != "" && !regexp.MustCompile(`^[A-Za-z0-9_-]{16,80}$`).MatchString(in.ZoneID) {
		writeJSON(w, 400, map[string]string{"error": "Cloudflare Zone ID 格式无效"})
		return
	}
	if in.CPUPercent < 0 || in.CPUPercent > 100 || in.TrafficGB < 0 || in.SustainMinutes < 0 || in.SustainMinutes > 1440 {
		writeJSON(w, 400, map[string]string{"error": "Cloudflare 自动切换阈值无效"})
		return
	}
	a.mu.RLock()
	existingToken, existingKey := a.cfg.CloudflareAPIToken, a.cfg.CloudflareAPIKey
	a.mu.RUnlock()
	if in.AutoOrangeCloud && (in.ZoneID == "" || (in.APIToken == "" && in.APIKey == "" && existingToken == "" && existingKey == "") || (in.CPUPercent == 0 && in.TrafficGB == 0)) {
		writeJSON(w, 400, map[string]string{"error": "启用自动橙云需要凭据、Zone ID 和至少一个有效阈值"})
		return
	}
	a.mu.Lock()
	a.cfg.CloudflareEmail = in.Email
	a.cfg.CloudflareZoneID = in.ZoneID
	if in.APIKey != "" && !strings.Contains(in.APIKey, "********") {
		a.cfg.CloudflareAPIKey = in.APIKey
	}
	if in.APIToken != "" && !strings.Contains(in.APIToken, "********") {
		a.cfg.CloudflareAPIToken = in.APIToken
	}
	a.cfg.CloudflareAutoOrangeCloud = in.AutoOrangeCloud
	a.cfg.CloudflareTrafficGB = in.TrafficGB
	a.cfg.CloudflareCPUPercent = in.CPUPercent
	a.cfg.CloudflareSustainMinutes = in.SustainMinutes
	err := a.saveConfigUnlocked()
	a.mu.Unlock()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	a.audit(r, "cloudflare.configure", "zone="+in.ZoneID, true, "自动橙云阈值已保存")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *app) saveConfigUnlocked() error {
	b, err := json.MarshalIndent(a.cfg, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(a.cfgPath, b, 0600)
}

func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 8 {
		return "********"
	}
	return s[:4] + "********" + s[len(s)-4:]
}

func runCommand(timeout time.Duration, name string, args ...string) (string, error) {
	return runCommandInput(timeout, "", name, args...)
}

func runCommandInput(timeout time.Duration, input, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	var output limitedBuffer
	cmd.Stdout, cmd.Stderr = &output, &output
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return output.String(), errors.New("命令执行超时")
	}
	return output.String(), err
}

func runShell(timeout time.Duration, command string) (string, error) {
	if runtime.GOOS == "windows" {
		return runCommand(timeout, "cmd.exe", "/d", "/s", "/c", command)
	}
	return runCommand(timeout, "/bin/bash", "-c", "set -o pipefail; "+command)
}

type limitedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.b.Len() < 1<<20 {
		remaining := 1<<20 - b.b.Len()
		if len(p) > remaining {
			_, _ = b.b.Write(p[:remaining])
		} else {
			_, _ = b.b.Write(p)
		}
	}
	return len(p), nil
}
func (b *limitedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp." + randomToken(4)
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func backupFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path+".bak."+time.Now().Format("20060102150405"), b, 0600)
}

func decodeJSONLimit(w http.ResponseWriter, r *http.Request, out any, limit int64) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(io.LimitReader(r.Body, limit)).Decode(out); err != nil {
		writeJSON(w, 400, map[string]string{"error": "无效的请求"})
		return false
	}
	return true
}

func validateStrongPassword(password string) error {
	return validateCredentials("admin", password)
}

func oneOf(v string, values ...string) bool {
	for _, item := range values {
		if v == item {
			return true
		}
	}
	return false
}

func outOrErr(out string, err error) string {
	out = strings.TrimSpace(out)
	if out != "" {
		return out
	}
	if err != nil {
		return err.Error()
	}
	return "ok"
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func randomToken(n int) string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(n))
}

func clientIP(r *http.Request) string {
	if r == nil {
		return "system"
	}
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return v
	}
	if v := r.Header.Get("CF-Connecting-IP"); v != "" {
		return v
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func redactSecrets(value string, secrets []string) string {
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[REDACTED]")
		}
	}
	return value
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func rootLoginValue(v bool) string {
	if v {
		return "yes"
	}
	return "prohibit-password"
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func databaseCLI() string {
	if fileExists("/usr/local/mariadb/bin/mariadb") {
		return "/usr/local/mariadb/bin/mariadb"
	}
	if commandExists("mariadb") {
		return "mariadb"
	}
	if commandExists("mysql") {
		return "mysql"
	}
	return ""
}
