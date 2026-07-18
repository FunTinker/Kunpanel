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
	"net/http"
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
		var in struct{ Action, ID, Data string }
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
			if err != nil && !strings.Contains(err.Error(), "duplicate") {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
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
			a.audit(r, "pty.command", in.ID, true, truncate(in.Data, 300))
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
	j := a.startJob("部署 WordPress "+in.Domain, commands, r)
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
		name := "kunpanel-" + time.Now().Format("20060102-150405") + ".tar.gz"
		target := filepath.Join(root, name)
		j := a.startJob("创建面板备份", []string{
			fmt.Sprintf("tar -czf %s /var/lib/tryallfun-panel /usr/local/nginx/conf/vhost /usr/local/nginx/conf/ssl /etc/ssh/sshd_config /etc/ssh/sshd_config.d /etc/cron.d/kunpanel 2>/dev/null", shellQuote(target)),
		}, r)
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
		j := a.startJob("恢复 "+in.Name, []string{
			fmt.Sprintf("tar -xzf %s -C /", shellQuote(target)),
			fmt.Sprintf("%s -t && %s -s reload", shellQuote(nginxBin()), shellQuote(nginxBin())),
		}, r)
		writeJSON(w, 202, j)
	default:
		writeJSON(w, 400, map[string]string{"error": "不支持的备份操作"})
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
	if in.URL != "" && !strings.HasPrefix(in.URL, "https://") {
		writeJSON(w, 400, map[string]string{"error": "通知地址必须使用 HTTPS"})
		return
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
		req, _ := http.NewRequest(http.MethodPost, in.URL, body)
		req.Header.Set("Content-Type", "application/json")
		client := http.Client{Timeout: 15 * time.Second}
		resp, reqErr := client.Do(req)
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
	if in.Action == "configure" {
		if !strings.HasPrefix(in.ManifestURL, "https://") {
			writeJSON(w, 400, map[string]string{"error": "升级清单必须使用 HTTPS"})
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
		if !strings.HasPrefix(manifest.URL, "https://") {
			writeJSON(w, 400, map[string]string{"error": "upgrade package must use HTTPS"})
			return
		}
		binary := panelBinaryPath()
		update := binary + ".update"
		rollback := binary + ".rollback"
		j := a.startJob("升级到 "+manifest.Version, []string{fmt.Sprintf("curl -fsSL %s -o %s", shellQuote(manifest.URL), shellQuote(update))}, r)
		go func() {
			for {
				time.Sleep(time.Second)
				a.mu.RLock()
				done := j.Status != "running"
				a.mu.RUnlock()
				if done {
					break
				}
			}
			a.mu.RLock()
			success := j.Status == "success"
			a.mu.RUnlock()
			if !success {
				return
			}
			b, err := os.ReadFile(update)
			sum := sha256.Sum256(b)
			if err != nil || !strings.EqualFold(hex.EncodeToString(sum[:]), manifest.SHA256) {
				return
			}
			cmd := fmt.Sprintf("chmod 0755 %s && systemd-run --unit=kunpanel-update --on-active=2 /bin/bash -c %s",
				shellQuote(update),
				shellQuote(fmt.Sprintf("cp %s %s && mv %s %s && systemctl restart tryallfun-panel",
					shellQuote(binary), shellQuote(rollback), shellQuote(update), shellQuote(binary))),
			)
			_, _ = runShell(20*time.Second, cmd)
		}()
		writeJSON(w, 202, j)
		return
	}
	writeJSON(w, 400, map[string]string{"error": "不支持的升级操作"})
}

func fetchAndVerifyManifest(url, keyText string) (upgradeManifest, error) {
	var manifest upgradeManifest
	if url == "" || keyText == "" {
		return manifest, errors.New("尚未配置签名升级源")
	}
	client := http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(url)
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
	pub, err := base64.StdEncoding.DecodeString(keyText)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return manifest, errors.New("Ed25519 公钥无效")
	}
	sig, err := base64.StdEncoding.DecodeString(manifest.Signature)
	if err != nil {
		return manifest, errors.New("签名格式无效")
	}
	message := manifest.Version + "\n" + manifest.URL + "\n" + strings.ToLower(manifest.SHA256)
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(message), sig) {
		return manifest, errors.New("升级清单签名验证失败")
	}
	return manifest, nil
}

func safeExtractZip(archivePath, dest string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, item := range zr.File {
		if err := validateArchiveName(item.Name); err != nil {
			return err
		}
		if item.FileInfo().Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink in archive: %s", item.Name)
		}
		target, err := safeExtractTarget(dest, item.Name)
		if err != nil {
			return err
		}
		if item.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if !item.FileInfo().Mode().IsRegular() {
			return fmt.Errorf("unsupported archive entry: %s", item.Name)
		}
		if fileExists(target) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		rc, err := item.Open()
		if err != nil {
			return err
		}
		err = writeNewFile(target, rc, item.FileInfo().Mode().Perm())
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
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := validateArchiveName(h.Name); err != nil {
			return err
		}
		target, err := safeExtractTarget(dest, h.Name)
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if fileExists(target) {
				continue
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			if err := writeNewFile(target, tr, os.FileMode(h.Mode).Perm()); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported archive entry: %s", h.Name)
		}
	}
}

func validateArchiveName(name string) error {
	clean := filepath.Clean(strings.ReplaceAll(name, "\\", "/"))
	if clean == "." || filepath.IsAbs(clean) || strings.HasPrefix(clean, "../") || clean == ".." || strings.Contains(clean, ":") {
		return fmt.Errorf("unsafe archive path: %s", name)
	}
	return nil
}

func safeExtractTarget(dest, name string) (string, error) {
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return "", err
	}
	if realDest, err := filepath.EvalSymlinks(absDest); err == nil {
		absDest = realDest
	}
	target := filepath.Join(absDest, filepath.Clean(strings.ReplaceAll(name, "\\", "/")))
	clean, err := safePath(absDest, target)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absDest, clean)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("archive path escapes destination: %s", name)
	}
	return clean, nil
}

func writeNewFile(path string, r io.Reader, mode os.FileMode) error {
	if mode == 0 || mode&0111 != 0 {
		mode = 0644
	}
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, io.LimitReader(r, 2<<30))
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(path)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(path)
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
	payload, _ := json.Marshal(map[string]string{"event": event, "title": title, "message": message, "time": time.Now().Format(time.RFC3339)})
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

// Keep archive packages linked and tested for future native streaming backup support.
var _ = tar.TypeReg
var _ = gzip.BestSpeed
var _ = strconv.IntSize
