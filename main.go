package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"tryallfun-panel/web"
)

const (
	addr              = "127.0.0.1:8088"
	panelVersion      = "0.6.0"
	sessionMaxAge     = 12 * time.Hour
	maintenanceMaxAge = 10 * time.Minute
)

type config struct {
	Admin                     string                `json:"admin"`
	PasswordSalt              string                `json:"passwordSalt"`
	PasswordHash              string                `json:"passwordHash"`
	SessionKey                string                `json:"sessionKey"`
	PanelName                 string                `json:"panelName,omitempty"`
	NotifyURL                 string                `json:"notifyURL,omitempty"`
	UpgradeURL                string                `json:"upgradeURL,omitempty"`
	UpgradeKey                string                `json:"upgradeKey,omitempty"`
	CloudflareEmail           string                `json:"cloudflareEmail,omitempty"`
	CloudflareAPIKey          string                `json:"cloudflareAPIKey,omitempty"`
	CloudflareAPIToken        string                `json:"cloudflareAPIToken,omitempty"`
	CloudflareZoneID          string                `json:"cloudflareZoneID,omitempty"`
	CloudflareAutoOrangeCloud bool                  `json:"cloudflareAutoOrangeCloud,omitempty"`
	CloudflareTrafficGB       float64               `json:"cloudflareTrafficGB,omitempty"`
	CloudflareCPUPercent      float64               `json:"cloudflareCPUPercent,omitempty"`
	CloudflareSustainMinutes  int                   `json:"cloudflareSustainMinutes,omitempty"`
	CloudflareLastSwitch      time.Time             `json:"cloudflareLastSwitch,omitempty"`
	CloudflareLastError       string                `json:"cloudflareLastError,omitempty"`
	RemoteBackupRemote        string                `json:"remoteBackupRemote,omitempty"`
	RemoteBackupPath          string                `json:"remoteBackupPath,omitempty"`
	RemoteBackupEnabled       bool                  `json:"remoteBackupEnabled,omitempty"`
	TOTPSecret                string                `json:"totpSecret,omitempty"`
	TOTPEnabled               bool                  `json:"totpEnabled,omitempty"`
	Users                     map[string]userRecord `json:"users,omitempty"`
}

type userRecord struct {
	PasswordSalt string    `json:"passwordSalt"`
	PasswordHash string    `json:"passwordHash"`
	Role         string    `json:"role"`
	Created      time.Time `json:"created"`
}

type sample struct {
	Time    int64   `json:"time"`
	CPU     float64 `json:"cpu"`
	Memory  float64 `json:"memory"`
	Disk    float64 `json:"disk"`
	Network float64 `json:"network"`
}

type loginAttempt struct {
	Failures     int
	LastFailure  time.Time
	BlockedUntil time.Time
}

type app struct {
	mu                   sync.RWMutex
	nodeMu               sync.RWMutex
	nodeOpMu             sync.Mutex
	cfg                  config
	cfgPath              string
	dataDir              string
	started              time.Time
	samples              []sample
	history              []sample
	lastCPU              cpuTicks
	lastNet              uint64
	lastPersistMinute    int64
	jobs                 map[string]*job
	loginAttempts        map[string]loginAttempt
	cloudflareHighSince  time.Time
	cloudflareLastAction time.Time
	networkSinceStart    uint64
}

type cpuTicks struct{ idle, total uint64 }

func main() {
	dataDir := env("TAF_DATA_DIR", "./data")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		log.Fatal(err)
	}
	if len(os.Args) > 1 && os.Args[1] == "reset-password" {
		if err := resetPasswordCLI(dataDir); err != nil {
			log.Fatal(err)
		}
		fmt.Println("管理员密码已重置，所有旧会话已失效。")
		return
	}
	a := &app{
		cfgPath:       filepath.Join(dataDir, "config.json"),
		dataDir:       dataDir,
		started:       time.Now(),
		jobs:          map[string]*job{},
		loginAttempts: map[string]loginAttempt{},
	}
	if err := a.loadConfig(); err != nil {
		log.Fatal(err)
	}
	if err := a.loadMetricHistory(); err != nil {
		log.Printf("load metric history: %v", err)
	}
	a.startSampler()

	server := &http.Server{
		Addr:              env("TAF_ADDR", addr),
		Handler:           a.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	log.Printf("TryAllFun Panel listening on http://%s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

func resetPasswordCLI(dataDir string) error {
	cfgPath := filepath.Join(dataDir, "config.json")
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	var cfg config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return err
	}
	password, err := bufio.NewReader(io.LimitReader(os.Stdin, 4096)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	password = strings.TrimSpace(password)
	if err := validateStrongPassword(password); err != nil {
		return err
	}
	setAdminPassword(&cfg, password)
	cfg.SessionKey = base64.RawStdEncoding.EncodeToString(randomBytes(32))
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(cfgPath, out, 0600)
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", a.handleStatus)
	mux.HandleFunc("/api/setup", a.handleSetup)
	mux.HandleFunc("/api/login", a.handleLogin)
	mux.HandleFunc("/api/logout", a.handleLogout)
	mux.HandleFunc("/api/session", a.auth(a.handleSession))
	mux.HandleFunc("/api/maintenance/unlock", a.auth(a.handleMaintenanceUnlock))
	mux.HandleFunc("/api/metrics", a.auth(a.handleMetrics))
	mux.HandleFunc("/api/overview", a.auth(a.handleOverview))
	mux.HandleFunc("/api/services", a.auth(a.handleServices))
	mux.HandleFunc("/api/services/action", a.auth(a.handleServiceAction))
	mux.HandleFunc("/api/apps", a.auth(a.handleApps))
	mux.HandleFunc("/api/apps/detail", a.auth(a.handleAppDetail))
	mux.HandleFunc("/api/apps/action", a.auth(a.handleAppAction))
	mux.HandleFunc("/api/apps/registry", a.auth(a.handleAppRegistry))
	mux.HandleFunc("/api/jobs", a.auth(a.handleJobs))
	mux.HandleFunc("/api/sites", a.auth(a.handleSites))
	mux.HandleFunc("/api/sites/detail", a.auth(a.handleSiteDetail))
	mux.HandleFunc("/api/sites/action", a.auth(a.handleSiteAction))
	mux.HandleFunc("/api/databases", a.auth(a.handleDatabases))
	mux.HandleFunc("/api/databases/detail", a.auth(a.handleDatabaseDetail))
	mux.HandleFunc("/api/databases/rows", a.auth(a.handleDatabaseRows))
	mux.HandleFunc("/api/databases/query", a.auth(a.handleDatabaseQuery))
	mux.HandleFunc("/api/databases/action", a.auth(a.handleDatabaseAction))
	mux.HandleFunc("/api/firewall", a.auth(a.handleFirewall))
	mux.HandleFunc("/api/firewall/action", a.auth(a.handleFirewallAction))
	mux.HandleFunc("/api/files", a.auth(a.handleFiles))
	mux.HandleFunc("/api/files/content", a.auth(a.handleFileContent))
	mux.HandleFunc("/api/files/action", a.auth(a.handleFileAction))
	mux.HandleFunc("/api/files/download", a.auth(a.handleFileDownload))
	mux.HandleFunc("/api/pty", a.auth(a.handlePTY))
	mux.HandleFunc("/api/terminal", a.auth(a.handleTerminal))
	mux.HandleFunc("/api/security", a.auth(a.handleSecurity))
	mux.HandleFunc("/api/security/action", a.auth(a.handleSecurityAction))
	mux.HandleFunc("/api/security/totp", a.auth(a.handleTOTP))
	mux.HandleFunc("/api/audit", a.auth(a.handleAudit))
	mux.HandleFunc("/api/settings", a.auth(a.handleSettings))
	mux.HandleFunc("/api/users", a.auth(a.handleUsers))
	mux.HandleFunc("/api/advanced/datastores", a.auth(a.handleDatastores))
	mux.HandleFunc("/api/advanced/certificates", a.auth(a.handleCertificates))
	mux.HandleFunc("/api/advanced/wordpress", a.auth(a.handleWordPress))
	mux.HandleFunc("/api/advanced/schedules", a.auth(a.handleSchedules))
	mux.HandleFunc("/api/advanced/backups", a.auth(a.handleBackups))
	mux.HandleFunc("/api/advanced/remote-backups", a.auth(a.handleRemoteBackups))
	mux.HandleFunc("/api/advanced/notifications", a.auth(a.handleNotifications))
	mux.HandleFunc("/api/advanced/upgrade", a.auth(a.handleUpgrade))
	mux.HandleFunc("/api/advanced/cloudflare", a.auth(a.handleCloudflare))
	mux.HandleFunc("/api/system/processes", a.auth(a.handleSystemProcesses))
	mux.HandleFunc("/api/system/network", a.auth(a.handleSystemNetwork))
	mux.HandleFunc("/api/system/disks", a.auth(a.handleSystemDisks))
	mux.HandleFunc("/api/system/logs", a.auth(a.handleSystemLogs))
	mux.HandleFunc("/api/system/action", a.auth(a.handleSystemAction))
	mux.HandleFunc("/api/docker", a.auth(a.handleDocker))
	mux.HandleFunc("/api/deployments", a.auth(a.handleDeployments))
	mux.HandleFunc("/api/nodes", a.auth(a.handleNodes))
	mux.HandleFunc("/", serveSPA)
	return securityHeaders(a.csrf(mux))
}

func (a *app) loadConfig() error {
	b, err := os.ReadFile(a.cfgPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &a.cfg); err != nil {
		return err
	}
	changed := false
	if a.cfg.Users == nil && a.cfg.Admin != "" {
		a.cfg.Users = map[string]userRecord{a.cfg.Admin: {PasswordSalt: a.cfg.PasswordSalt, PasswordHash: a.cfg.PasswordHash, Role: "admin", Created: time.Now()}}
		changed = true
	}
	if a.cfg.PanelName == "" || a.cfg.PanelName == "TryAllFun Panel" {
		a.cfg.PanelName = "鲲面板 KunPanel"
		changed = true
	}
	if changed {
		return a.saveConfig()
	}
	return nil
}

func (a *app) saveConfig() error {
	b, err := json.MarshalIndent(a.cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := a.cfgPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, a.cfgPath)
}

func (a *app) handleStatus(w http.ResponseWriter, _ *http.Request) {
	a.mu.RLock()
	configured, twoFactor := a.cfg.Admin != "", a.cfg.TOTPEnabled
	a.mu.RUnlock()
	writeJSON(w, 200, map[string]any{"configured": configured, "twoFactor": twoFactor})
}

func (a *app) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var in struct{ Username, Password string }
	if !decodeJSON(w, r, &in) {
		return
	}
	a.mu.Lock()
	if a.cfg.Admin != "" {
		a.mu.Unlock()
		writeJSON(w, 409, map[string]string{"error": "面板已初始化"})
		return
	}
	if err := validateCredentials(in.Username, in.Password); err != nil {
		a.mu.Unlock()
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	salt := randomBytes(16)
	a.cfg = config{
		Admin:        in.Username,
		PasswordSalt: base64.RawStdEncoding.EncodeToString(salt),
		PasswordHash: hashPassword(in.Password, salt),
		SessionKey:   base64.RawStdEncoding.EncodeToString(randomBytes(32)),
		PanelName:    "TryAllFun Panel",
		Users:        map[string]userRecord{in.Username: {PasswordSalt: base64.RawStdEncoding.EncodeToString(salt), PasswordHash: hashPassword(in.Password, salt), Role: "admin", Created: time.Now()}},
	}
	a.mu.Unlock()
	if err := a.saveConfig(); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	a.setSession(w, r, in.Username)
	writeJSON(w, 201, map[string]bool{"ok": true})
}

func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var in struct{ Username, Password, OTP string }
	if !decodeJSON(w, r, &in) {
		return
	}
	key := strings.ToLower(strings.TrimSpace(in.Username)) + "|" + clientIP(r)
	if retry := a.loginRetryAfter(key); retry > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "登录失败次数过多，请稍后再试"})
		return
	}
	role, ok := a.authenticateUser(in.Username, in.Password)
	if ok && a.totpRequired(in.Username) && !verifyTOTP(a.totpSecret(), in.OTP, time.Now()) {
		ok = false
	}
	if !ok {
		time.Sleep(350 * time.Millisecond)
		a.recordLoginFailure(key)
		writeJSON(w, 401, map[string]string{"error": "账号或密码错误"})
		return
	}
	a.clearLoginFailures(key)
	a.setSession(w, r, in.Username)
	writeJSON(w, 200, map[string]any{"ok": true, "role": role})
}

func (a *app) authenticateUser(username, password string) (string, bool) {
	a.mu.RLock()
	user, ok := a.cfg.Users[username]
	if !ok && username == a.cfg.Admin {
		user = userRecord{PasswordSalt: a.cfg.PasswordSalt, PasswordHash: a.cfg.PasswordHash, Role: "admin"}
		ok = true
	}
	a.mu.RUnlock()
	if !ok {
		return "", false
	}
	salt, _ := base64.RawStdEncoding.DecodeString(user.PasswordSalt)
	expected, _ := hex.DecodeString(user.PasswordHash)
	actual, _ := hex.DecodeString(hashPassword(password, salt))
	return user.Role, subtle.ConstantTimeCompare(expected, actual) == 1
}

func (a *app) handleLogout(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "taf_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *app) handleSession(w http.ResponseWriter, r *http.Request) {
	username := a.sessionUser(r)
	writeJSON(w, 200, map[string]any{"username": username, "role": a.userRole(username), "twoFactor": a.totpRequired(username)})
}

func (a *app) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.validSession(r) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (a *app) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			origin := r.Header.Get("Origin")
			if origin != "" {
				expected := "http://" + r.Host
				if r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil {
					expected = "https://" + r.Host
				}
				if origin != expected {
					writeJSON(w, http.StatusForbidden, map[string]string{"error": "请求来源校验失败"})
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (a *app) setSession(w http.ResponseWriter, r *http.Request, user string) {
	expires := time.Now().Add(sessionMaxAge).Unix()
	payload := fmt.Sprintf("%s|%d", user, expires)
	sig := a.sign(payload)
	http.SetCookie(w, &http.Cookie{
		Name: "taf_session", Value: base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + sig)),
		Path: "/", MaxAge: int(sessionMaxAge.Seconds()), HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})
}

func (a *app) handleMaintenanceUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var in struct{ Password string }
	if !decodeJSON(w, r, &in) {
		return
	}
	username := a.sessionUser(r)
	role, authenticated := a.authenticateUser(username, in.Password)
	if !authenticated || !oneOf(role, "admin", "operator") {
		time.Sleep(350 * time.Millisecond)
		a.audit(r, "maintenance.unlock", "panel", false, "password rejected")
		writeJSON(w, 403, map[string]string{"error": "maintenance password rejected"})
		return
	}
	expires := time.Now().Add(maintenanceMaxAge).Unix()
	payload := fmt.Sprintf("%s|%d", username, expires)
	sig := a.sign("maintenance|" + payload)
	http.SetCookie(w, &http.Cookie{
		Name: "taf_maintenance", Value: base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + sig)),
		Path: "/", MaxAge: int(maintenanceMaxAge.Seconds()), HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})
	a.audit(r, "maintenance.unlock", "panel", true, "10m")
	writeJSON(w, 200, map[string]any{"ok": true, "expires": expires})
}

func (a *app) requireMaintenance(w http.ResponseWriter, r *http.Request) bool {
	if a.validMaintenance(r) {
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"code": "maintenance_required", "error": "maintenance unlock required"})
	return false
}

func (a *app) validMaintenance(r *http.Request) bool {
	c, err := r.Cookie("taf_maintenance")
	if err != nil {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	role := a.userRole(parts[0])
	return parts[0] == a.sessionUser(r) && oneOf(role, "admin", "operator") && hmac.Equal([]byte(parts[2]), []byte(a.sign("maintenance|"+parts[0]+"|"+parts[1])))
}

func (a *app) validSession(r *http.Request) bool {
	c, err := r.Cookie("taf_session")
	if err != nil {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	return a.userExists(parts[0]) && hmac.Equal([]byte(parts[2]), []byte(a.sign(parts[0]+"|"+parts[1])))
}

func (a *app) userExists(username string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if username == a.cfg.Admin {
		return true
	}
	_, ok := a.cfg.Users[username]
	return ok
}

func (a *app) sessionUser(r *http.Request) string {
	c, err := r.Cookie("taf_session")
	if err != nil {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return ""
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 || !a.validSession(r) {
		return ""
	}
	return parts[0]
}

func (a *app) userRole(username string) string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if username == a.cfg.Admin {
		return "admin"
	}
	if user, ok := a.cfg.Users[username]; ok {
		return user.Role
	}
	return ""
}

func (a *app) requireRole(w http.ResponseWriter, r *http.Request, roles ...string) bool {
	role := a.userRole(a.sessionUser(r))
	for _, allowed := range roles {
		if role == allowed {
			return true
		}
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "当前账号没有执行此操作的权限"})
	return false
}

func (a *app) validPassword(password string) bool {
	a.mu.RLock()
	cfg := a.cfg
	a.mu.RUnlock()
	salt, _ := base64.RawStdEncoding.DecodeString(cfg.PasswordSalt)
	expected, _ := hex.DecodeString(cfg.PasswordHash)
	actual, _ := hex.DecodeString(hashPassword(password, salt))
	return subtle.ConstantTimeCompare(expected, actual) == 1
}

func (a *app) sign(s string) string {
	a.mu.RLock()
	key, _ := base64.RawStdEncoding.DecodeString(a.cfg.SessionKey)
	a.mu.RUnlock()
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(s))
	return hex.EncodeToString(mac.Sum(nil))
}

func (a *app) startSampler() {
	a.lastCPU = readCPU()
	a.lastNet = readNetwork()
	ticker := time.NewTicker(5 * time.Second)
	go func() {
		for range ticker.C {
			a.collectSample()
		}
	}()
	a.collectSample()
}

func (a *app) collectSample() {
	cpuNow := readCPU()
	netNow := readNetwork()
	mem := memoryPercent()
	disk := diskPercent("/")
	cpu := percentDelta(a.lastCPU, cpuNow)
	var networkDelta uint64
	if netNow >= a.lastNet {
		networkDelta = netNow - a.lastNet
	}
	network := float64(networkDelta) / 5 / 1024
	a.lastCPU, a.lastNet = cpuNow, netNow
	a.mu.Lock()
	a.networkSinceStart += networkDelta
	current := sample{time.Now().UnixMilli(), cpu, mem, disk, network}
	a.samples = append(a.samples, current)
	if len(a.samples) > 17280 {
		a.samples = a.samples[len(a.samples)-17280:]
	}
	minute := current.Time / 60000
	persist := minute != a.lastPersistMinute
	if persist {
		a.lastPersistMinute = minute
		a.history = append(a.history, current)
		cutoff := time.Now().Add(-30 * 24 * time.Hour).UnixMilli()
		for len(a.history) > 0 && a.history[0].Time < cutoff {
			a.history = a.history[1:]
		}
	}
	trafficGB := float64(a.networkSinceStart) / (1024 * 1024 * 1024)
	a.mu.Unlock()
	if persist {
		a.appendMetricHistory(current)
	}
	a.maybeAutoOrangeCloud(current.CPU, trafficGB)
}

func (a *app) handleMetrics(w http.ResponseWriter, r *http.Request) {
	rangeName := r.URL.Query().Get("range")
	if rangeName == "" {
		rangeName = "1h"
	}
	dur, bucket := metricRange(rangeName)
	since := time.Now().Add(-dur).UnixMilli()
	a.mu.RLock()
	raw := append([]sample(nil), a.history...)
	raw = append(raw, a.samples...)
	a.mu.RUnlock()
	writeJSON(w, 200, map[string]any{"range": rangeName, "points": aggregate(raw, since, bucket)})
}

func (a *app) handleOverview(w http.ResponseWriter, _ *http.Request) {
	host, _ := os.Hostname()
	load := readLoad()
	a.mu.RLock()
	var latest sample
	if len(a.samples) > 0 {
		latest = a.samples[len(a.samples)-1]
	}
	a.mu.RUnlock()
	writeJSON(w, 200, map[string]any{
		"hostname": host, "os": readOS(), "kernel": runtime.GOOS + " " + runtime.GOARCH,
		"uptime": humanDuration(time.Since(a.started)), "load": load, "latest": latest,
		"cpuCores": runtime.NumCPU(), "ip": localIP(),
	})
}

func (a *app) handleServices(w http.ResponseWriter, _ *http.Request) {
	services := managedServices()
	writeJSON(w, 200, services)
}

func (a *app) handleApps(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, a.appCatalog())
}

func readCPU() cpuTicks {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuTicks{}
	}
	line := strings.SplitN(string(b), "\n", 2)[0]
	f := strings.Fields(line)
	var vals []uint64
	for _, s := range f[1:] {
		v, _ := strconv.ParseUint(s, 10, 64)
		vals = append(vals, v)
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	var idle uint64
	if len(vals) > 3 {
		idle = vals[3]
	}
	if len(vals) > 4 {
		idle += vals[4]
	}
	return cpuTicks{idle, total}
}

func percentDelta(a, b cpuTicks) float64 {
	if b.total <= a.total {
		return 0
	}
	total := b.total - a.total
	idle := b.idle - a.idle
	return round2(100 * float64(total-idle) / float64(total))
}

func memoryPercent() float64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	vals := map[string]float64{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 {
			vals[strings.TrimSuffix(f[0], ":")], _ = strconv.ParseFloat(f[1], 64)
		}
	}
	if vals["MemTotal"] == 0 {
		return 0
	}
	return round2((vals["MemTotal"] - vals["MemAvailable"]) / vals["MemTotal"] * 100)
}

func readNetwork() uint64 {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0
	}
	var total uint64
	for _, line := range strings.Split(string(b), "\n")[2:] {
		f := strings.Fields(strings.ReplaceAll(line, ":", " "))
		if len(f) >= 10 && f[0] != "lo" {
			rx, _ := strconv.ParseUint(f[1], 10, 64)
			tx, _ := strconv.ParseUint(f[9], 10, 64)
			total += rx + tx
		}
	}
	return total
}

func readLoad() string {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return "0.00 0.00 0.00"
	}
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return "0.00 0.00 0.00"
	}
	return strings.Join(f[:3], " ")
}

func readOS() string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return runtime.GOOS
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return "Linux"
}

func serviceStatus(name string) string {
	if !commandExists("systemctl") {
		return "unknown"
	}
	err := exec.Command("systemctl", "is-active", "--quiet", name).Run()
	if err == nil {
		return "running"
	}
	return "stopped"
}

func sshPort() int {
	if out, err := runCommand(5*time.Second, "sshd", "-T"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "port" {
				if v, err := strconv.Atoi(fields[1]); err == nil && v > 0 {
					return v
				}
			}
		}
	}
	b, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return 22
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Port ") {
			v, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Port ")))
			if v > 0 {
				return v
			}
		}
	}
	return 22
}

func metricRange(name string) (time.Duration, time.Duration) {
	switch name {
	case "6h":
		return 6 * time.Hour, time.Minute
	case "24h":
		return 24 * time.Hour, 5 * time.Minute
	case "7d":
		return 7 * 24 * time.Hour, time.Hour
	case "30d":
		return 30 * 24 * time.Hour, 6 * time.Hour
	default:
		return time.Hour, 15 * time.Second
	}
}

func aggregate(points []sample, since int64, bucket time.Duration) []sample {
	type acc struct {
		n                   int
		cpu, mem, disk, net float64
		t                   int64
	}
	m := map[int64]*acc{}
	ms := bucket.Milliseconds()
	for _, p := range points {
		if p.Time < since {
			continue
		}
		key := p.Time / ms * ms
		if m[key] == nil {
			m[key] = &acc{t: key}
		}
		x := m[key]
		x.n++
		x.cpu += p.CPU
		x.mem += p.Memory
		x.disk += p.Disk
		x.net += p.Network
	}
	out := make([]sample, 0, len(m))
	for t := since / ms * ms; t <= time.Now().UnixMilli(); t += ms {
		if x := m[t]; x != nil {
			n := float64(x.n)
			out = append(out, sample{x.t, round2(x.cpu / n), round2(x.mem / n), round2(x.disk / n), round2(x.net / n)})
		}
	}
	return out
}

func validateCredentials(user, password string) error {
	if len(strings.TrimSpace(user)) < 3 {
		return errors.New("管理员账号至少 3 个字符")
	}
	if len(password) < 16 {
		return errors.New("密码至少 16 位")
	}
	var upper, lower, digit, special bool
	for _, r := range password {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			special = true
		}
	}
	if !(upper && lower && digit && special) {
		return errors.New("密码必须包含大小写字母、数字和特殊字符")
	}
	return nil
}

func hashPassword(password string, salt []byte) string {
	value := append(append([]byte(nil), salt...), []byte(password)...)
	sum := sha256.Sum256(value)
	for i := 0; i < 600000; i++ {
		h := sha256.New()
		_, _ = h.Write(sum[:])
		_, _ = h.Write(salt)
		sum = sha256.Sum256(h.Sum(nil))
	}
	return hex.EncodeToString(sum[:])
}

func setAdminPassword(cfg *config, password string) {
	salt := randomBytes(16)
	cfg.PasswordSalt = base64.RawStdEncoding.EncodeToString(salt)
	cfg.PasswordHash = hashPassword(password, salt)
	if cfg.Users == nil {
		cfg.Users = map[string]userRecord{}
	}
	owner := cfg.Users[cfg.Admin]
	owner.PasswordSalt, owner.PasswordHash, owner.Role = cfg.PasswordSalt, cfg.PasswordHash, "admin"
	if owner.Created.IsZero() {
		owner.Created = time.Now()
	}
	cfg.Users[cfg.Admin] = owner
}

func safePath(root, requested string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if realRoot, err := filepath.EvalSymlinks(absRoot); err == nil {
		absRoot = realRoot
	}
	abs, err := filepath.Abs(requested)
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	} else if realParent, parentErr := filepath.EvalSymlinks(filepath.Dir(abs)); parentErr == nil {
		abs = filepath.Join(realParent, filepath.Base(abs))
	}
	rel, err := filepath.Rel(absRoot, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("路径超出允许的文件根目录")
	}
	return abs, nil
}

func projectDir() string {
	if v := os.Getenv("TAF_PROJECT_DIR"); v != "" {
		return v
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	return "/home/wwwroot/Kunpanel.456.life"
}

func panelBinaryPath() string {
	if v := os.Getenv("TAF_BINARY_PATH"); v != "" {
		return v
	}
	if exe, err := os.Executable(); err == nil {
		return exe
	}
	return filepath.Join(projectDir(), "tryallfun-panel")
}

func localIP() string {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func serveSPA(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name == "." || name == "" {
		name = "index.html"
	}
	b, err := fs.ReadFile(web.Dist, "dist/"+name)
	if err != nil {
		b, err = fs.ReadFile(web.Dist, "dist/index.html")
	}
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if t := mime.TypeByExtension(filepath.Ext(name)); t != "" {
		w.Header().Set("Content-Type", t)
	}
	_, _ = w.Write(b)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(out); err != nil {
		writeJSON(w, 400, map[string]string{"error": "无效的请求"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func commandExists(name string) bool { _, err := exec.LookPath(name); return err == nil }
func nginxBin() string {
	if v := os.Getenv("TAF_NGINX_BIN"); v != "" {
		return v
	}
	if fileExists("/usr/local/nginx/sbin/nginx") {
		return "/usr/local/nginx/sbin/nginx"
	}
	return "nginx"
}
func randomBytes(n int) []byte { b := make([]byte, n); _, _ = rand.Read(b); return b }
func round2(v float64) float64 { return float64(int(v*100+0.5)) / 100 }
func env(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
func humanDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	return fmt.Sprintf("%d天 %d小时 %d分钟", days, int(d.Hours())%24, int(d.Minutes())%60)
}
