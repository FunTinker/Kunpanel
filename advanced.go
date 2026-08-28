package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type scheduleEntry struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Cron    string `json:"cron"`
	Command string `json:"command"`
	Enabled bool   `json:"enabled"`
}

type upgradeManifest struct {
	Version   string `json:"version"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
	Notes     string `json:"notes"`
}

func (a *app) handlePTY(w http.ResponseWriter, r *http.Request) {
	if !a.requireMaintenance(w, r) {
		return
	}
	if !commandExists("tmux") {
		writeJSON(w, 409, map[string]string{"error": "服务器未安装 tmux"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		id := r.URL.Query().Get("id")
		if !safeNameRE.MatchString(id) {
			writeJSON(w, 400, map[string]string{"error": "会话 ID 无效"})
			return
		}
		out, err := runCommand(10*time.Second, "tmux", "capture-pane", "-p", "-J", "-t", "kun-"+id, "-S", "-1000")
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "终端会话不存在"})
			return
		}
		writeJSON(w, 200, map[string]any{"id": id, "output": out})
	case http.MethodPost:
		var in struct{ Action, ID, Data, Node string }
		if !decodeJSON(w, r, &in) {
			return
		}
		if in.ID == "" {
			in.ID = randomToken(6)
		}
		if !safeNameRE.MatchString(in.ID) {
			writeJSON(w, 400, map[string]string{"error": "会话 ID 无效"})
			return
		}
		session := "kun-" + in.ID
		switch in.Action {
		case "create":
			_, err := runCommand(10*time.Second, "tmux", "new-session", "-d", "-s", session, "-x", "140", "-y", "40", "/bin/bash")
			createdNew := err == nil
			if err != nil {
				if _, existsErr := runCommand(10*time.Second, "tmux", "has-session", "-t", session); existsErr != nil {
					writeJSON(w, 500, map[string]string{"error": err.Error()})
					return
				}
			}
			if in.Node != "" && createdNew {
				node, nodeErr := a.resolveNode(in.Node)
				if nodeErr != nil {
					_, _ = runCommand(10*time.Second, "tmux", "kill-session", "-t", session)
					writeJSON(w, 400, map[string]string{"error": nodeErr.Error()})
					return
				}
				if keyErr := a.ensureNodeKey(); keyErr != nil {
					_, _ = runCommand(10*time.Second, "tmux", "kill-session", "-t", session)
					writeJSON(w, 500, map[string]string{"error": keyErr.Error()})
					return
				}
				parts := append([]string{"ssh"}, a.nodeSSHArgs(node, node.Port)...)
				quoted := make([]string, len(parts))
				for i, part := range parts {
					quoted[i] = shellQuote(part)
				}
				command := "exec " + strings.Join(quoted, " ")
				_, _ = runCommand(10*time.Second, "tmux", "send-keys", "-t", session, "-l", command)
				_, _ = runCommand(10*time.Second, "tmux", "send-keys", "-t", session, "Enter")
				a.audit(r, "pty.remote", node.Alias, true, "interactive managed SSH session")
			}
			_, _ = runCommand(10*time.Second, "tmux", "set-option", "-t", session, "remain-on-exit", "on")
			a.audit(r, "pty.create", in.ID, true, "interactive tmux session")
		case "input":
			if len(in.Data) > 8192 {
				writeJSON(w, 400, map[string]string{"error": "单次输入过长"})
				return
			}
			_, err := runCommand(10*time.Second, "tmux", "send-keys", "-t", session, "-l", in.Data)
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
		case "enter":
			if in.Data != "" {
				_, _ = runCommand(10*time.Second, "tmux", "send-keys", "-t", session, "-l", in.Data)
			}
			if _, err := runCommand(10*time.Second, "tmux", "send-keys", "-t", session, "Enter"); err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			a.audit(r, "pty.command", in.ID, true, "interactive input submitted")
		case "ctrl-c":
			_, _ = runCommand(10*time.Second, "tmux", "send-keys", "-t", session, "C-c")
		case "close":
			_, _ = runCommand(10*time.Second, "tmux", "kill-session", "-t", session)
			a.audit(r, "pty.close", in.ID, true, "")
		default:
			writeJSON(w, 400, map[string]string{"error": "不支持的终端操作"})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "id": in.ID})
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (a *app) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	clean, err := safePath(fileRoot(), r.URL.Query().Get("path"))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	info, err := os.Stat(clean)
	if err != nil || info.IsDir() {
		http.Error(w, "只能下载普通文件", 400)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, strings.ReplaceAll(filepath.Base(clean), `"`, "")))
	http.ServeFile(w, r, clean)
	a.audit(r, "file.download", clean, true, fmt.Sprintf("%d bytes", info.Size()))
}

func (a *app) handleFileAdvancedAction(w http.ResponseWriter, r *http.Request, in struct{ Action, Path, Name, Format, Confirm string }) error {
	root := fileRoot()
	clean, err := safePath(root, in.Path)
	if err != nil {
		return err
	}
	switch in.Action {
	case "archive":
		if !oneOf(in.Format, "tar.gz", "zip") || !safeNameRE.MatchString(in.Name) {
			return errors.New("压缩格式或文件名无效")
		}
		target := filepath.Join(filepath.Dir(clean), in.Name+"."+in.Format)
		if in.Format == "zip" {
			_, err = runShell(10*time.Minute, fmt.Sprintf("cd %s && zip -r %s %s", shellQuote(filepath.Dir(clean)), shellQuote(target), shellQuote(filepath.Base(clean))))
		} else {
			_, err = runCommand(10*time.Minute, "tar", "-czf", target, "-C", filepath.Dir(clean), filepath.Base(clean))
		}
	case "extract":
		dest := filepath.Dir(clean)
		if strings.HasSuffix(clean, ".zip") {
			err = safeExtractZip(clean, dest)
		} else if strings.HasSuffix(clean, ".tar.gz") || strings.HasSuffix(clean, ".tgz") {
			err = safeExtractTarGz(clean, dest)
		} else {
			err = errors.New("仅支持 zip、tar.gz 和 tgz")
		}
	case "trash":
		if in.Confirm != filepath.Base(clean) {
			return errors.New("确认文本不一致")
		}
		trash := filepath.Join(root, ".kun-trash", time.Now().Format("20060102-150405")+"-"+filepath.Base(clean))
		if err = os.MkdirAll(filepath.Dir(trash), 0700); err == nil {
			err = os.Rename(clean, trash)
		}
	default:
		return errors.New("不支持的高级文件操作")
	}
	return err
}

func (a *app) handleDatastores(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		result := map[string]any{
			"postgres": map[string]any{"installed": commandExists("psql"), "status": serviceStatus("postgresql"), "roles": []string{}},
			"redis":    map[string]any{"installed": commandExists("redis-cli"), "status": serviceStatus("redis-server"), "databases": []map[string]any{}},
		}
		if commandExists("psql") {
			if out, err := runCommand(15*time.Second, "sudo", "-u", "postgres", "psql", "-Atc", "SELECT rolname FROM pg_roles WHERE rolname !~ '^pg_' ORDER BY 1"); err == nil {
				result["postgres"].(map[string]any)["roles"] = strings.Fields(out)
			}
		}
		if commandExists("redis-cli") {
			var dbs []map[string]any
			if out, err := runCommand(15*time.Second, "redis-cli", "--raw", "INFO", "keyspace"); err == nil {
				re := regexp.MustCompile(`(?m)^(db\d+):keys=(\d+)`)
				for _, m := range re.FindAllStringSubmatch(out, -1) {
					dbs = append(dbs, map[string]any{"name": m[1], "keys": m[2]})
				}
			}
			result["redis"].(map[string]any)["databases"] = dbs
		}
		writeJSON(w, 200, result)
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	var in struct{ Engine, Action, Name, Password, Confirm string }
	if !decodeJSON(w, r, &in) {
		return
	}
	var out string
	var err error
	switch in.Engine + ":" + in.Action {
	case "postgres:create-role":
		if !databaseRE.MatchString(in.Name) || len(in.Password) < 12 || strings.ContainsAny(in.Password, "'\\\r\n") {
			err = errors.New("角色名或密码无效")
		} else {
			sql := fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s';", in.Name, in.Password)
			out, err = runCommand(20*time.Second, "sudo", "-u", "postgres", "psql", "-v", "ON_ERROR_STOP=1", "-c", sql)
		}
	case "postgres:create-db":
		if !databaseRE.MatchString(in.Name) {
			err = errors.New("数据库名无效")
		} else {
			out, err = runCommand(20*time.Second, "sudo", "-u", "postgres", "createdb", in.Name)
		}
	case "redis:flush-db":
		if in.Confirm != "FLUSH "+in.Name || !regexp.MustCompile(`^db([0-9]|1[0-5])$`).MatchString(in.Name) {
			err = errors.New("确认文本或 Redis 数据库编号无效")
		} else {
			n := strings.TrimPrefix(in.Name, "db")
			out, err = runCommand(20*time.Second, "redis-cli", "-n", n, "FLUSHDB")
		}
	default:
		err = errors.New("不支持的数据存储操作")
	}
	a.audit(r, "datastore."+in.Action, in.Engine+"/"+in.Name, err == nil, outOrErr(out, err))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": outOrErr(out, err)})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *app) handleCertificates(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, 200, map[string]any{"certbot": commandExists("certbot"), "certificates": scanCertificates()})
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	var in struct{ Action, Domain, Email, Root string }
	if !decodeJSON(w, r, &in) {
		return
	}
	switch in.Action {
	case "install-certbot":
		j := a.startJob("安装 Certbot", []string{"apt-get update", "DEBIAN_FRONTEND=noninteractive apt-get install -y certbot"}, r)
		writeJSON(w, 202, j)
	case "issue":
		if !domainRE.MatchString(in.Domain) || !strings.Contains(in.Email, "@") {
			writeJSON(w, 400, map[string]string{"error": "域名或邮箱无效"})
			return
		}
		if in.Root == "" {
			in.Root = filepath.Join(fileRoot(), in.Domain, "public")
		}
		if _, err := safePath(fileRoot(), in.Root); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		_ = os.MkdirAll(in.Root, 0755)
		commands := []string{
			fmt.Sprintf("certbot certonly --webroot -w %s -d %s --email %s --agree-tos --non-interactive --keep-until-expiring", shellQuote(in.Root), shellQuote(in.Domain), shellQuote(in.Email)),
			"systemctl enable --now certbot.timer || true",
		}
		j := a.startJob("签发 "+in.Domain+" 证书", commands, r)
		writeJSON(w, 202, j)
	default:
		writeJSON(w, 400, map[string]string{"error": "不支持的证书操作"})
	}
}

func (a *app) handleWordPress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	var in struct{ Domain, Email, Title string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if !domainRE.MatchString(in.Domain) || !strings.Contains(in.Email, "@") {
		writeJSON(w, 400, map[string]string{"error": "域名或邮箱无效"})
		return
	}
	db := "wp_" + strings.ReplaceAll(strings.Split(in.Domain, ".")[0], "-", "_")
	user := truncate(db+"_u", 30)
	password := base64.RawURLEncoding.EncodeToString(randomBytes(18))
	adminPassword := base64.RawURLEncoding.EncodeToString(randomBytes(18))
	root := filepath.Join(fileRoot(), in.Domain, "public")
	if _, err := safePath(fileRoot(), root); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	sql := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER IF NOT EXISTS '%s'@'localhost' IDENTIFIED BY '%s'; GRANT ALL ON `%s`.* TO '%s'@'localhost'; FLUSH PRIVILEGES;", db, user, password, db, user)
	vhost := fmt.Sprintf(`# managed-by: tryallfun-panel
server {
    listen 80;
    server_name %s;
    root %s;
    index index.php index.html;
    location / { try_files $uri $uri/ /index.php?$args; }
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
    }
    location ~ /\. { deny all; }
}
`, in.Domain, root)
	commands := []string{
		fmt.Sprintf("mkdir -p %s", shellQuote(filepath.Dir(root))),
		fmt.Sprintf("curl -fsSL https://wordpress.org/latest.tar.gz | tar -xz -C %s", shellQuote(filepath.Dir(root))),
		fmt.Sprintf("rm -rf %s && mv %s %s", shellQuote(root), shellQuote(filepath.Join(filepath.Dir(root), "wordpress")), shellQuote(root)),
		fmt.Sprintf("printf %%s %s | %s", shellQuote(sql), shellQuote(databaseCLI())),
		"curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o /tmp/kun-wp-cli.phar",
		fmt.Sprintf("php /tmp/kun-wp-cli.phar config create --path=%s --dbname=%s --dbuser=%s --dbpass=%s --dbhost=localhost --skip-check --allow-root", shellQuote(root), shellQuote(db), shellQuote(user), shellQuote(password)),
		fmt.Sprintf("php /tmp/kun-wp-cli.phar core install --path=%s --url=%s --title=%s --admin_user=kunadmin --admin_password=%s --admin_email=%s --skip-email --allow-root", shellQuote(root), shellQuote("http://"+in.Domain), shellQuote(in.Title), shellQuote(adminPassword), shellQuote(in.Email)),
		fmt.Sprintf("printf %%s %s > %s", shellQuote(vhost), shellQuote(filepath.Join(env("TAF_NGINX_VHOST_DIR", "/usr/local/nginx/conf/vhost"), in.Domain+".conf"))),
		fmt.Sprintf("%s -t && %s -s reload", shellQuote(nginxBin()), shellQuote(nginxBin())),
		fmt.Sprintf("chown -R www:www %s", shellQuote(filepath.Dir(root))),
	}
	j := a.startSensitiveJob("部署 WordPress "+in.Domain, commands, []string{password, adminPassword}, r)
	a.audit(r, "wordpress.credentials", in.Domain, true, "数据库凭据仅在本次响应返回")
	writeJSON(w, 202, map[string]any{"job": j, "database": db, "user": user, "password": password, "adminUser": "kunadmin", "adminPassword": adminPassword, "root": root})
}

func (a *app) handleSchedules(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(a.dataDir, "schedules.json")
	schedules := make([]scheduleEntry, 0)
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &schedules)
	}
	if r.Method == http.MethodGet {
		writeJSON(w, 200, schedules)
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	var in struct{ Action, ID, Name, Cron, Command string }
	if !decodeJSON(w, r, &in) {
		return
	}
	switch in.Action {
	case "add":
		if !validCron(in.Cron) || strings.TrimSpace(in.Command) == "" || len(in.Command) > 2048 {
			writeJSON(w, 400, map[string]string{"error": "Cron 表达式或命令无效"})
			return
		}
		schedules = append(schedules, scheduleEntry{randomToken(6), cleanNote(in.Name), in.Cron, in.Command, true})
	case "delete":
		out := schedules[:0]
		for _, s := range schedules {
			if s.ID != in.ID {
				out = append(out, s)
			}
		}
		schedules = out
	default:
		writeJSON(w, 400, map[string]string{"error": "不支持的计划任务操作"})
		return
	}
	data, _ := json.MarshalIndent(schedules, "", "  ")
	if err := atomicWrite(path, data, 0600); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if err := writeCronFile(schedules); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	a.audit(r, "schedule."+in.Action, in.ID, true, in.Name)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func writeCronFile(items []scheduleEntry) error {
	var b strings.Builder
	b.WriteString("SHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n")
	for _, item := range items {
		if item.Enabled {
			fmt.Fprintf(&b, "%s root %s >> /var/log/kunpanel-cron.log 2>&1\n", item.Cron, item.Command)
		}
	}
	return atomicWrite("/etc/cron.d/kunpanel", []byte(b.String()), 0644)
}

func validCron(s string) bool {
	fields := strings.Fields(s)
	if len(fields) != 5 {
		return false
	}
	for _, f := range fields {
		if strings.ContainsAny(f, "\r\n;") || !regexp.MustCompile(`^[0-9*/,\-]+$`).MatchString(f) {
			return false
		}
	}
	return true
}

func (a *app) handleBackups(w http.ResponseWriter, r *http.Request) {
	root := filepath.Join(a.dataDir, "backups")
	_ = os.MkdirAll(root, 0700)
	if r.Method == http.MethodGet {
		entries, _ := os.ReadDir(root)
		items := make([]map[string]any, 0)
		for _, e := range entries {
			if info, err := e.Info(); err == nil {
				items = append(items, map[string]any{"name": e.Name(), "size": info.Size(), "modified": info.ModTime()})
			}
		}
		sort.Slice(items, func(i, j int) bool { return items[i]["modified"].(time.Time).After(items[j]["modified"].(time.Time)) })
		writeJSON(w, 200, items)
		return
	}
	var in struct{ Action, Name, Confirm string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	switch in.Action {
	case "create":
		name := "kunpanel-" + time.Now().Format("20060102-150405") + "-" + randomToken(3) + ".tar.gz"
		target := filepath.Join(root, name)
		j := a.startJob("创建面板备份", []string{backupCommand(a.dataDir, target)}, r)
		writeJSON(w, 202, j)
	case "restore":
		if !safeNameRE.MatchString(in.Name) || !strings.HasSuffix(in.Name, ".tar.gz") || in.Confirm != "RESTORE "+in.Name {
			writeJSON(w, 400, map[string]string{"error": "备份名或确认文本无效"})
			return
		}
		target := filepath.Join(root, filepath.Base(in.Name))
		if !fileExists(target) {
			writeJSON(w, 404, map[string]string{"error": "备份不存在"})
			return
		}
		if err := validateBackupArchive(target, backupPaths(a.dataDir)); err != nil {
			writeJSON(w, 400, map[string]string{"error": "备份预检失败: " + err.Error()})
			return
		}
		j := a.startJob("恢复 "+in.Name, []string{restoreCommand(a.dataDir, target)}, r)
		writeJSON(w, 202, j)
	default:
		writeJSON(w, 400, map[string]string{"error": "不支持的备份操作"})
	}
}

func backupCommand(dataDir, target string) string {
	backupDir := filepath.Join(dataDir, "backups")
	quoted := make([]string, 0, 8)
	for _, item := range backupPaths(dataDir) {
		quoted = append(quoted, shellQuote(item))
	}
	relativeBackupDir := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(backupDir)), "/")
	return fmt.Sprintf("tar --ignore-failed-read --exclude=%s --exclude=%s -czf %s %s",
		shellQuote(backupDir), shellQuote(relativeBackupDir), shellQuote(target), strings.Join(quoted, " "))
}

func backupPaths(dataDir string) []string {
	paths := []string{
		dataDir,
		env("TAF_NGINX_VHOST_DIR", "/etc/nginx/conf.d"),
		env("TAF_NGINX_SSL_DIR", "/etc/nginx/ssl"),
		"/etc/ssh/sshd_config",
		"/etc/ssh/sshd_config.d",
		"/etc/cron.d/kunpanel",
	}
	seen := map[string]bool{}
	result := make([]string, 0, len(paths))
	for _, item := range paths {
		item = filepath.Clean(item)
		if item != "." && !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

func restoreCommand(dataDir, target string) string {
	rollback := filepath.Join(dataDir, "backups", ".restore-rollback-"+time.Now().Format("20060102-150405")+"-"+randomToken(3)+".tar.gz")
	nginx := shellQuote(nginxBin())
	sshCheck := "( ! command -v sshd >/dev/null || sshd -t )"
	restoreRollback := fmt.Sprintf("tar -xzf %s -C / && %s -t && %s && %s -s reload", shellQuote(rollback), nginx, sshCheck, nginx)
	return fmt.Sprintf("set -eu; %s; if ! tar -xzf %s -C / || ! %s -t || ! %s || ! %s -s reload; then %s; exit 1; fi; rm -f %s",
		backupCommand(dataDir, rollback), shellQuote(target), nginx, sshCheck, nginx, restoreRollback, shellQuote(rollback))
}

func validateBackupArchive(path string, allowedRoots []string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(io.LimitReader(f, 20<<30))
	if err != nil {
		return err
	}
	defer gz.Close()
	allowed := make([]string, 0, len(allowedRoots))
	for _, root := range allowedRoots {
		clean := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(root)), "/")
		if clean != "" && clean != "." {
			allowed = append(allowed, clean)
		}
	}
	tr := tar.NewReader(gz)
	var entries int
	var totalSize int64
	for {
		h, nextErr := tr.Next()
		if errors.Is(nextErr, io.EOF) {
			return nil
		}
		if nextErr != nil {
			return nextErr
		}
		entries++
		totalSize += max(0, h.Size)
		if entries > 500000 || totalSize > 20<<30 {
			return errors.New("备份内容超过安全限制")
		}
		if err := validateArchiveName(h.Name); err != nil {
			return err
		}
		if h.Typeflag != tar.TypeDir && h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			return fmt.Errorf("备份包含不支持的链接或设备: %s", h.Name)
		}
		name := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(h.Name)), "./")
		permitted := false
		for _, root := range allowed {
			if name == root || strings.HasPrefix(name, root+"/") {
				permitted = true
				break
			}
		}
		if !permitted {
			return fmt.Errorf("备份包含未授权路径: %s", h.Name)
		}
	}
}

func (a *app) handleNotifications(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	url := a.cfg.NotifyURL
	a.mu.RUnlock()
	if r.Method == http.MethodGet {
		writeJSON(w, 200, map[string]any{"configured": url != "", "url": maskURL(url)})
		return
	}
	var in struct{ URL, Action string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	in.URL = strings.TrimSpace(in.URL)
	if in.URL != "" {
		if _, err := validatePublicHTTPSURL(in.URL); err != nil {
			writeJSON(w, 400, map[string]string{"error": "通知地址无效: " + err.Error()})
			return
		}
	}
	a.mu.Lock()
	a.cfg.NotifyURL = in.URL
	err := a.saveConfigUnlocked()
	a.mu.Unlock()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if in.Action == "test" && in.URL != "" {
		body := strings.NewReader(`{"event":"test","title":"KunPanel 通知测试","message":"通知渠道配置成功"}`)
		parsed, _ := validatePublicHTTPSURL(in.URL)
		req, reqErr := http.NewRequest(http.MethodPost, parsed.String(), body)
		if reqErr != nil {
			writeJSON(w, 400, map[string]string{"error": reqErr.Error()})
			return
		}
		req.Header.Set("Content-Type", "application/json")
		client := newPublicHTTPClient(15 * time.Second)
		resp, reqErr := doPublicRequest(client, req)
		if reqErr != nil {
			writeJSON(w, 400, map[string]string{"error": reqErr.Error()})
			return
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			writeJSON(w, 400, map[string]string{"error": fmt.Sprintf("通知端点返回 %d", resp.StatusCode)})
			return
		}
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *app) handleUpgrade(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	url, key := a.cfg.UpgradeURL, a.cfg.UpgradeKey
	a.mu.RUnlock()
	if r.Method == http.MethodGet {
		writeJSON(w, 200, map[string]any{"version": panelVersion, "configured": url != "" && key != "", "manifestURL": url})
		return
	}
	var in struct{ Action, ManifestURL, PublicKey string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	in.ManifestURL = strings.TrimSpace(in.ManifestURL)
	if in.Action == "configure" {
		if _, err := validatePublicHTTPSURL(in.ManifestURL); err != nil {
			writeJSON(w, 400, map[string]string{"error": "升级清单地址无效: " + err.Error()})
			return
		}
		if _, err := base64.StdEncoding.DecodeString(in.PublicKey); err != nil {
			writeJSON(w, 400, map[string]string{"error": "Ed25519 公钥格式无效"})
			return
		}
		a.mu.Lock()
		a.cfg.UpgradeURL, a.cfg.UpgradeKey = in.ManifestURL, in.PublicKey
		err := a.saveConfigUnlocked()
		a.mu.Unlock()
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	manifest, err := fetchAndVerifyManifest(url, key)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if in.Action == "check" {
		writeJSON(w, 200, manifest)
		return
	}
	if in.Action == "apply" {
		if _, err := validatePublicHTTPSURL(manifest.URL); err != nil {
			writeJSON(w, 400, map[string]string{"error": "upgrade package URL is invalid: " + err.Error()})
			return
		}
		binary := panelBinaryPath()
		update := binary + ".update"
		rollback := binary + ".rollback"
		j := a.startManagedJob("下载并验证升级包 "+manifest.Version, r, func() (string, error) {
			if err := downloadPublicHTTPSFile(manifest.URL, update, maxUpgradeBytes); err != nil {
				return "", fmt.Errorf("下载升级包失败: %w", err)
			}
			actualHash, err := sha256File(update)
			if err != nil {
				return "", fmt.Errorf("读取升级包失败: %w", err)
			}
			if !strings.EqualFold(actualHash, manifest.SHA256) {
				return "", errors.New("升级包 SHA-256 校验失败")
			}
			if out, err := runCommand(10*time.Second, update, "version"); err != nil || strings.TrimSpace(out) != manifest.Version {
				return "", errors.New("新版本启动自检失败: " + outOrErr(out, err))
			}
			service, healthURL, err := upgradeRuntimeSettings()
			if err != nil {
				return "", err
			}
			script := upgradeRollbackScript(binary, update, rollback, service, healthURL)
			unit := "kunpanel-update-" + strconv.FormatInt(time.Now().Unix(), 10) + "-" + randomToken(3)
			out, err := runCommand(20*time.Second, "systemd-run", "--unit="+unit, "--on-active=2s", "--collect", "/bin/bash", "-c", script)
			if err != nil {
				return "", errors.New("无法调度升级任务: " + outOrErr(out, err))
			}
			a.audit(nil, "upgrade.schedule", manifest.Version, true, "signed update scheduled with health rollback")
			return "升级包校验通过，已调度带健康检查的升级任务\n", nil
		})
		writeJSON(w, 202, j)
		return
	}
	writeJSON(w, 400, map[string]string{"error": "不支持的升级操作"})
}

func upgradeRuntimeSettings() (string, string, error) {
	service := env("TAF_SERVICE_NAME", "kunpanel")
	if !safeNameRE.MatchString(service) {
		return "", "", errors.New("TAF_SERVICE_NAME 格式无效")
	}
	if healthURL := os.Getenv("TAF_HEALTH_URL"); healthURL != "" {
		parsed, err := url.Parse(healthURL)
		if err != nil || parsed == nil {
			return "", "", errors.New("TAF_HEALTH_URL 必须是本机 HTTP 地址")
		}
		hostIP := net.ParseIP(parsed.Hostname())
		if parsed.Scheme != "http" || parsed.User != nil || parsed.Port() == "" || (parsed.Hostname() != "localhost" && (hostIP == nil || !hostIP.IsLoopback())) {
			return "", "", errors.New("TAF_HEALTH_URL 必须是本机 HTTP 地址")
		}
		return service, strings.TrimRight(healthURL, "/"), nil
	}
	listen := env("TAF_ADDR", addr)
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", "", errors.New("TAF_ADDR 无法用于升级健康检查")
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return service, "http://" + net.JoinHostPort(host, port), nil
}

func upgradeRollbackScript(binary, update, rollback, service, healthURL string) string {
	qBinary, qUpdate, qRollback := shellQuote(binary), shellQuote(update), shellQuote(rollback)
	qService := shellQuote(service)
	qHealth := shellQuote(strings.TrimRight(healthURL, "/") + "/api/status")
	restore := fmt.Sprintf("cp -- %s %s; systemctl restart %s", qRollback, qBinary, qService)
	return fmt.Sprintf("set -u; cp -- %s %s || exit 1; mv -- %s %s || exit 1; if ! systemctl restart %s; then %s; exit 1; fi; for i in $(seq 1 20); do if curl -fsS --max-time 3 %s | grep -q '\"configured\"'; then exit 0; fi; sleep 1; done; %s; exit 1",
		qBinary, qRollback, qUpdate, qBinary, qService, restore, qHealth, restore)
}

func fetchAndVerifyManifest(url, keyText string) (upgradeManifest, error) {
	var manifest upgradeManifest
	if url == "" || keyText == "" {
		return manifest, errors.New("尚未配置签名升级源")
	}
	parsed, err := validatePublicHTTPSURL(url)
	if err != nil {
		return manifest, err
	}
	req, err := http.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		return manifest, err
	}
	resp, err := doPublicRequest(newPublicHTTPClient(20*time.Second), req)
	if err != nil {
		return manifest, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return manifest, fmt.Errorf("升级源返回 %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&manifest); err != nil {
		return manifest, err
	}
	if err := verifyUpgradeManifest(manifest, keyText); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func verifyUpgradeManifest(manifest upgradeManifest, keyText string) error {
	if _, err := validatePublicHTTPSURL(manifest.URL); err != nil {
		return errors.New("升级包地址无效: " + err.Error())
	}
	pub, err := base64.StdEncoding.DecodeString(keyText)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("Ed25519 公钥无效")
	}
	sig, err := base64.StdEncoding.DecodeString(manifest.Signature)
	if err != nil {
		return errors.New("签名格式无效")
	}
	message := manifest.Version + "\n" + manifest.URL + "\n" + strings.ToLower(manifest.SHA256)
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(message), sig) {
		return errors.New("升级清单签名验证失败")
	}
	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func safeExtractZip(archivePath, dest string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer zr.Close()
	root, err := openArchiveRoot(dest)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, item := range zr.File {
		if item.FileInfo().Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink in archive: %s", item.Name)
		}
		relative, err := safeArchiveRelativePath(item.Name)
		if err != nil {
			return err
		}
		if item.FileInfo().IsDir() {
			if err := ensureArchiveRootDirectory(root, relative, 0755); err != nil {
				return err
			}
			continue
		}
		if !item.FileInfo().Mode().IsRegular() {
			return fmt.Errorf("unsupported archive entry: %s", item.Name)
		}
		if info, err := root.Lstat(relative); err == nil {
			if info.Mode().IsRegular() {
				continue
			}
			return fmt.Errorf("refusing existing non-regular extraction target: %s", item.Name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := ensureArchiveRootDirectory(root, filepath.Dir(relative), 0755); err != nil {
			return err
		}
		rc, err := item.Open()
		if err != nil {
			return err
		}
		err = writeNewRootFile(root, relative, rc, item.FileInfo().Mode().Perm())
		_ = rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func safeExtractTarGz(archivePath, dest string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	root, err := openArchiveRoot(dest)
	if err != nil {
		return err
	}
	defer root.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		relative, err := safeArchiveRelativePath(h.Name)
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := ensureArchiveRootDirectory(root, relative, 0755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if info, err := root.Lstat(relative); err == nil {
				if info.Mode().IsRegular() {
					continue
				}
				return fmt.Errorf("refusing existing non-regular extraction target: %s", h.Name)
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if err := ensureArchiveRootDirectory(root, filepath.Dir(relative), 0755); err != nil {
				return err
			}
			if err := writeNewRootFile(root, relative, tr, os.FileMode(h.Mode).Perm()); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported archive entry: %s", h.Name)
		}
	}
}

func validateArchiveName(name string) error {
	_, err := safeArchiveRelativePath(name)
	return err
}

func safeArchiveRelativePath(name string) (string, error) {
	normalized := strings.ReplaceAll(name, "\\", "/")
	clean := filepath.Clean(filepath.FromSlash(normalized))
	if clean == "." || !filepath.IsLocal(clean) || strings.Contains(clean, ":") {
		return "", fmt.Errorf("unsafe archive path: %s", name)
	}
	return clean, nil
}

func openArchiveRoot(dest string) (*os.Root, error) {
	info, err := os.Lstat(dest)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("extraction destination must be a real directory")
	}
	return os.OpenRoot(dest)
}

func ensureArchiveRootDirectory(root *os.Root, relative string, mode os.FileMode) error {
	if relative == "." {
		return nil
	}
	if _, err := safeArchiveRelativePath(relative); err != nil {
		return err
	}
	current := ""
	for _, component := range strings.Split(filepath.ToSlash(relative), "/") {
		if current == "" {
			current = component
		} else {
			current = filepath.Join(current, component)
		}
		info, err := root.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := root.Mkdir(current, mode); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			info, err = root.Lstat(current)
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing non-directory extraction path: %s", relative)
		}
	}
	return nil
}

func writeNewRootFile(root *os.Root, relative string, r io.Reader, mode os.FileMode) error {
	if mode == 0 || mode&0111 != 0 {
		mode = 0644
	}
	out, err := root.OpenFile(relative, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, io.LimitReader(r, 2<<30))
	closeErr := out.Close()
	if copyErr != nil {
		_ = root.Remove(relative)
		return copyErr
	}
	if closeErr != nil {
		_ = root.Remove(relative)
		return closeErr
	}
	return nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func maskURL(s string) string {
	if len(s) < 16 {
		return s
	}
	return s[:12] + "…" + s[len(s)-4:]
}

func (a *app) sendNotification(event, title, message string) {
	a.mu.RLock()
	url := a.cfg.NotifyURL
	a.mu.RUnlock()
	if url == "" {
		return
	}
	parsed, err := validatePublicHTTPSURL(url)
	if err != nil {
		return
	}
	payload, _ := json.Marshal(map[string]string{"event": event, "title": title, "message": message, "time": time.Now().Format(time.RFC3339)})
	req, err := http.NewRequest(http.MethodPost, parsed.String(), strings.NewReader(string(payload)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := newPublicHTTPClient(10 * time.Second)
	resp, err := doPublicRequest(client, req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

// Keep archive packages linked and tested for future native streaming backup support.
var _ = tar.TypeReg
var _ = gzip.BestSpeed
var _ = strconv.IntSize
