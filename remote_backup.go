package main

import (
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
)

var rcloneRemoteRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

func (a *app) handleRemoteBackups(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.mu.RLock()
		remote, path, enabled := a.cfg.RemoteBackupRemote, a.cfg.RemoteBackupPath, a.cfg.RemoteBackupEnabled
		a.mu.RUnlock()
		writeJSON(w, 200, map[string]any{"installed": commandExists("rclone"), "remote": remote, "path": path, "enabled": enabled, "local": filepath.Join(a.dataDir, "backups")})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.requireRole(w, r, "admin") || !a.requireMaintenance(w, r) {
		return
	}
	var in struct {
		Action  string `json:"action"`
		Remote  string `json:"remote"`
		Path    string `json:"path"`
		Enabled bool   `json:"enabled"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Action == "configure" {
		if in.Remote != "" && !rcloneRemoteRE.MatchString(in.Remote) {
			writeJSON(w, 400, map[string]string{"error": "rclone 远程名称无效"})
			return
		}
		clean := strings.Trim(strings.ReplaceAll(in.Path, "\\", "/"), "/")
		if strings.Contains(clean, "..") || strings.ContainsAny(clean, "\r\n:;|&`$()") {
			writeJSON(w, 400, map[string]string{"error": "远程路径无效"})
			return
		}
		a.mu.Lock()
		a.cfg.RemoteBackupRemote, a.cfg.RemoteBackupPath, a.cfg.RemoteBackupEnabled = in.Remote, clean, in.Enabled
		a.mu.Unlock()
		if err := a.saveConfig(); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		a.audit(r, "backup.remote.configure", in.Remote, true, clean)
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	if !oneOf(in.Action, "test", "push") || !commandExists("rclone") {
		writeJSON(w, 400, map[string]string{"error": "rclone 未安装或操作无效"})
		return
	}
	a.mu.RLock()
	remote, path := a.cfg.RemoteBackupRemote, a.cfg.RemoteBackupPath
	a.mu.RUnlock()
	if !rcloneRemoteRE.MatchString(remote) {
		writeJSON(w, 400, map[string]string{"error": "请先配置 rclone 远程名称"})
		return
	}
	target := remote + ":" + path
	if in.Action == "test" {
		writeJSON(w, 202, a.startArgsJob("测试远程备份 "+target, [][]string{{"rclone", "lsd", target, "--max-depth", "1"}}, r))
		return
	}
	local := filepath.Join(a.dataDir, "backups")
	writeJSON(w, 202, a.startArgsJob("上传远程备份 "+target, [][]string{{"rclone", "copy", local, target, "--create-empty-src-dirs", "--checksum"}}, r))
}
