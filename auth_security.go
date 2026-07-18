package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	loginFailureWindow = 10 * time.Minute
	loginBlockDuration = 15 * time.Minute
	maxLoginFailures   = 5
)

func (a *app) loginRetryAfter(key string) int {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.loginAttempts == nil {
		a.loginAttempts = map[string]loginAttempt{}
	}
	attempt, ok := a.loginAttempts[key]
	if !ok {
		return 0
	}
	if !attempt.BlockedUntil.IsZero() {
		if now.Before(attempt.BlockedUntil) {
			return max(1, int(time.Until(attempt.BlockedUntil).Seconds()))
		}
		delete(a.loginAttempts, key)
		return 0
	}
	if now.Sub(attempt.LastFailure) > loginFailureWindow {
		delete(a.loginAttempts, key)
	}
	return 0
}

func (a *app) recordLoginFailure(key string) {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.loginAttempts == nil {
		a.loginAttempts = map[string]loginAttempt{}
	}
	if len(a.loginAttempts) >= 10000 {
		for existingKey, existing := range a.loginAttempts {
			if now.Sub(existing.LastFailure) > loginFailureWindow && now.After(existing.BlockedUntil) {
				delete(a.loginAttempts, existingKey)
			}
		}
	}
	attempt := a.loginAttempts[key]
	if now.Sub(attempt.LastFailure) > loginFailureWindow {
		attempt.Failures = 0
	}
	attempt.Failures++
	attempt.LastFailure = now
	if attempt.Failures >= maxLoginFailures {
		attempt.BlockedUntil = now.Add(loginBlockDuration)
	}
	a.loginAttempts[key] = attempt
}

func (a *app) clearLoginFailures(key string) {
	a.mu.Lock()
	delete(a.loginAttempts, key)
	a.mu.Unlock()
}

func (a *app) totpRequired(username string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return username == a.cfg.Admin && a.cfg.TOTPEnabled && a.cfg.TOTPSecret != ""
}

func (a *app) totpSecret() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg.TOTPSecret
}

func generateTOTPSecret() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes(20))
}

func verifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	for offset := int64(-1); offset <= 1; offset++ {
		if subtle.ConstantTimeCompare([]byte(totpCode(secret, now.Unix()/30+offset)), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

func totpCode(secret string, counter int64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(key) < 16 || counter < 0 {
		return ""
	}
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}

func (a *app) handleTOTP(w http.ResponseWriter, r *http.Request) {
	if !a.requireRole(w, r, "admin") {
		return
	}
	if r.Method == http.MethodGet {
		a.mu.RLock()
		enabled := a.cfg.TOTPEnabled
		a.mu.RUnlock()
		writeJSON(w, 200, map[string]bool{"enabled": enabled})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.requireMaintenance(w, r) {
		return
	}
	var in struct{ Action, Secret, Code, Password string }
	if !decodeJSON(w, r, &in) {
		return
	}
	switch in.Action {
	case "begin":
		secret := generateTOTPSecret()
		a.mu.RLock()
		account, issuer := a.cfg.Admin, a.cfg.PanelName
		a.mu.RUnlock()
		if issuer == "" {
			issuer = "KunPanel"
		}
		uri := "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?secret=" + url.QueryEscape(secret) + "&issuer=" + url.QueryEscape(issuer) + "&digits=6&period=30"
		writeJSON(w, 200, map[string]string{"secret": secret, "uri": uri})
	case "enable":
		if !verifyTOTP(in.Secret, in.Code, time.Now()) {
			writeJSON(w, 400, map[string]string{"error": "动态验证码无效"})
			return
		}
		a.mu.Lock()
		a.cfg.TOTPSecret, a.cfg.TOTPEnabled = strings.ToUpper(strings.TrimSpace(in.Secret)), true
		err := a.saveConfigUnlocked()
		a.mu.Unlock()
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		a.audit(r, "security.totp.enable", a.sessionUser(r), true, "TOTP enabled")
		writeJSON(w, 200, map[string]bool{"ok": true})
	case "disable":
		if _, ok := a.authenticateUser(a.sessionUser(r), in.Password); !ok {
			writeJSON(w, 403, map[string]string{"error": "管理员密码错误"})
			return
		}
		a.mu.Lock()
		a.cfg.TOTPSecret, a.cfg.TOTPEnabled = "", false
		err := a.saveConfigUnlocked()
		a.mu.Unlock()
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		a.audit(r, "security.totp.disable", a.sessionUser(r), true, "TOTP disabled")
		writeJSON(w, 200, map[string]bool{"ok": true})
	default:
		writeJSON(w, 400, map[string]string{"error": "不支持的双重认证操作"})
	}
}
