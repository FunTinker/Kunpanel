package main

import (
	"encoding/base64"
	"net/http"
	"time"
)

func (a *app) handleUsers(w http.ResponseWriter, r *http.Request) {
	if !a.requireRole(w, r, "admin") {
		return
	}
	if r.Method == http.MethodGet {
		a.mu.RLock()
		items := make([]map[string]any, 0, len(a.cfg.Users))
		for name, user := range a.cfg.Users {
			items = append(items, map[string]any{"username": name, "role": user.Role, "created": user.Created, "admin": name == a.cfg.Admin})
		}
		a.mu.RUnlock()
		writeJSON(w, 200, items)
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
		Action   string `json:"action"`
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
		Confirm  string `json:"confirm"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if !safeNameRE.MatchString(in.Username) || in.Username == "root" {
		writeJSON(w, 400, map[string]string{"error": "用户名无效"})
		return
	}
	if !oneOf(in.Action, "create", "delete", "role", "password") {
		writeJSON(w, 400, map[string]string{"error": "不支持的用户操作"})
		return
	}
	if in.Action == "create" {
		if err := validateCredentials(in.Username, in.Password); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if !oneOf(in.Role, "viewer", "operator", "admin") {
			in.Role = "operator"
		}
		salt := randomBytes(16)
		a.mu.Lock()
		if a.cfg.Users == nil {
			a.cfg.Users = map[string]userRecord{}
		}
		if _, exists := a.cfg.Users[in.Username]; exists || in.Username == a.cfg.Admin {
			a.mu.Unlock()
			writeJSON(w, 409, map[string]string{"error": "用户已存在"})
			return
		}
		a.cfg.Users[in.Username] = userRecord{PasswordSalt: b64(salt), PasswordHash: hashPassword(in.Password, salt), Role: in.Role, Created: time.Now()}
		a.mu.Unlock()
		if err := a.saveConfig(); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		a.audit(r, "user.create", in.Username, true, in.Role)
		writeJSON(w, 201, map[string]any{"ok": true, "username": in.Username, "role": in.Role})
		return
	}
	if in.Action == "delete" && in.Confirm != "DELETE "+in.Username {
		writeJSON(w, 400, map[string]string{"error": "删除确认文本不正确"})
		return
	}
	currentUser := a.sessionUser(r)
	a.mu.Lock()
	user, exists := a.cfg.Users[in.Username]
	if !exists || in.Username == a.cfg.Admin || in.Username == currentUser {
		a.mu.Unlock()
		writeJSON(w, 400, map[string]string{"error": "不能删除或修改该用户"})
		return
	}
	switch in.Action {
	case "delete":
		delete(a.cfg.Users, in.Username)
	case "role":
		if !oneOf(in.Role, "viewer", "operator", "admin") {
			a.mu.Unlock()
			writeJSON(w, 400, map[string]string{"error": "角色无效"})
			return
		}
		user.Role = in.Role
		a.cfg.Users[in.Username] = user
	case "password":
		if err := validateStrongPassword(in.Password); err != nil {
			a.mu.Unlock()
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		salt := randomBytes(16)
		user.PasswordSalt, user.PasswordHash = b64(salt), hashPassword(in.Password, salt)
		a.cfg.Users[in.Username] = user
	}
	a.mu.Unlock()
	if err := a.saveConfig(); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	a.audit(r, "user."+in.Action, in.Username, true, "user directory updated")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func b64(data []byte) string {
	return base64.RawStdEncoding.EncodeToString(data)
}
