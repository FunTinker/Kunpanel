package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidGitURL(t *testing.T) {
	for _, value := range []string{"https://github.com/example/app.git", "ssh://git@example.com/app.git", "git@example.com:app.git"} {
		if !validGitURL(value) {
			t.Fatalf("valid Git URL rejected: %s", value)
		}
	}
	for _, value := range []string{"file:///etc/passwd", "https://example.com/a;id", "https://example.com/a\nnext"} {
		if validGitURL(value) {
			t.Fatalf("unsafe Git URL accepted: %q", value)
		}
	}
}

func TestRegistryManifestValidation(t *testing.T) {
	valid := registryManifest{ID: "demo", Name: "Demo", Version: "1.0", Install: []string{"apt-get install -y demo"}}
	if err := validateManifest(valid); err != nil {
		t.Fatal(err)
	}
	valid.Install = []string{"apt-get install demo\nrm -rf /"}
	if err := validateManifest(valid); err == nil {
		t.Fatal("manifest command with newline was accepted")
	}
}

func TestLocalRegistryExtendsCatalog(t *testing.T) {
	a := &app{dataDir: t.TempDir()}
	file := registryFile{Version: "1", Apps: []registryManifest{{ID: "demo", Name: "Demo", Description: "test", Category: "test", Version: "1.0", Install: []string{"true"}, Checks: []string{"demo-command"}}}}
	b, _ := json.Marshal(file)
	if err := os.MkdirAll(filepath.Dir(a.registryPath()), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.registryPath(), b, 0600); err != nil {
		t.Fatal(err)
	}
	items := a.allCatalog()
	if items[len(items)-1].ID != "demo" {
		t.Fatalf("custom registry app missing: %#v", items[len(items)-1])
	}
}

func TestRegistryPreservesServiceAndConfigDetails(t *testing.T) {
	a := &app{dataDir: t.TempDir()}
	manifest := registryManifest{ID: "demo", Name: "Demo", Version: "1.0", Install: []string{"true"}, Services: []string{"nginx"}, Config: []map[string]string{{"label": "配置", "value": "/etc/demo"}}}
	file := registryFile{Version: "1", Apps: []registryManifest{manifest}}
	b, _ := json.Marshal(file)
	if err := os.MkdirAll(filepath.Dir(a.registryPath()), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.registryPath(), b, 0600); err != nil {
		t.Fatal(err)
	}
	got, ok := a.registryManifestByID("demo")
	if !ok || len(got.Services) != 1 || got.Services[0] != "nginx" || got.Config[0]["value"] != "/etc/demo" {
		t.Fatalf("registry details lost: %#v", got)
	}
}

func TestDeploymentPersistence(t *testing.T) {
	a := &app{dataDir: t.TempDir()}
	item := deploymentProject{ID: "demo", Name: "Demo", Compose: "services:\n  web:\n    image: nginx:alpine\n", Created: time.Now(), Updated: time.Now()}
	if err := a.writeDeployment(item); err != nil {
		t.Fatal(err)
	}
	items, err := a.loadDeployments()
	if err != nil || len(items) != 1 || items[0].ID != "demo" {
		t.Fatalf("deployment persistence failed: %#v %v", items, err)
	}
}

func TestAuthenticateRBACUser(t *testing.T) {
	salt := []byte("0123456789abcdef")
	a := &app{cfg: config{Admin: "owner", Users: map[string]userRecord{"operator": {PasswordSalt: b64(salt), PasswordHash: hashPassword("Strong-Test-2026!", salt), Role: "operator"}}}}
	role, ok := a.authenticateUser("operator", "Strong-Test-2026!")
	if !ok || role != "operator" {
		t.Fatalf("role=%q ok=%v", role, ok)
	}
	if _, ok := a.authenticateUser("operator", "wrong"); ok {
		t.Fatal("invalid password accepted")
	}
}

func TestLegacyPasswordIsRehashedAfterLogin(t *testing.T) {
	salt := []byte("0123456789abcdef")
	dataDir := t.TempDir()
	a := &app{
		cfgPath: filepath.Join(dataDir, "config.json"),
		cfg: config{Admin: "owner", PasswordSalt: b64(salt), PasswordHash: legacyHashPassword("Strong-Test-2026!", salt), Users: map[string]userRecord{
			"owner": {PasswordSalt: b64(salt), PasswordHash: legacyHashPassword("Strong-Test-2026!", salt), Role: "admin"},
		}},
	}
	if _, ok := a.authenticateUser("owner", "Strong-Test-2026!"); !ok {
		t.Fatal("legacy password was rejected")
	}
	if !strings.HasPrefix(a.cfg.PasswordHash, passwordHashPrefix) || !strings.HasPrefix(a.cfg.Users["owner"].PasswordHash, passwordHashPrefix) {
		t.Fatal("legacy password was not upgraded to Argon2id")
	}
}

func TestSetAdminPasswordSynchronizesUserDirectory(t *testing.T) {
	oldSalt := []byte("0123456789abcdef")
	cfg := config{Admin: "owner", PasswordSalt: b64(oldSalt), PasswordHash: hashPassword("Old-Password-2026!", oldSalt), Users: map[string]userRecord{"owner": {PasswordSalt: b64(oldSalt), PasswordHash: hashPassword("Old-Password-2026!", oldSalt), Role: "admin", Created: time.Now()}}}
	setAdminPassword(&cfg, "New-Password-2026!")
	a := &app{cfg: cfg}
	if _, ok := a.authenticateUser("owner", "New-Password-2026!"); !ok {
		t.Fatal("new administrator password was not accepted")
	}
	if _, ok := a.authenticateUser("owner", "Old-Password-2026!"); ok {
		t.Fatal("old administrator password remained valid")
	}
}

func TestLoginFailureLockout(t *testing.T) {
	a := &app{loginAttempts: map[string]loginAttempt{}}
	for i := 0; i < maxLoginFailures; i++ {
		a.recordLoginFailure("owner|127.0.0.1")
	}
	if retry := a.loginRetryAfter("owner|127.0.0.1"); retry <= 0 {
		t.Fatal("login attempts were not blocked")
	}
	a.clearLoginFailures("owner|127.0.0.1")
	if retry := a.loginRetryAfter("owner|127.0.0.1"); retry != 0 {
		t.Fatalf("successful login did not clear lockout: %d", retry)
	}
}

func TestLoginFailureMapHasHardLimit(t *testing.T) {
	a := &app{loginAttempts: make(map[string]loginAttempt, maxLoginAttempts)}
	for i := 0; i < maxLoginAttempts; i++ {
		a.loginAttempts[fmt.Sprintf("192.0.2.%d", i)] = loginAttempt{LastFailure: time.Now()}
	}
	a.recordLoginFailure("198.51.100.1")
	if len(a.loginAttempts) > maxLoginAttempts {
		t.Fatalf("login failure map exceeded limit: %d", len(a.loginAttempts))
	}
}

func TestTOTPVerification(t *testing.T) {
	secret := generateTOTPSecret()
	now := time.Unix(1784390400, 0)
	code := totpCode(secret, now.Unix()/30)
	if !verifyTOTP(secret, code, now) || verifyTOTP(secret, "000000", now) && code != "000000" {
		t.Fatal("TOTP verification failed")
	}
}

func TestRedactSecrets(t *testing.T) {
	value := redactSecrets("password=secret-value", []string{"secret-value"})
	if strings.Contains(value, "secret-value") || !strings.Contains(value, "[REDACTED]") {
		t.Fatalf("secret was not redacted: %q", value)
	}
}

func TestViewerCannotReadPrivilegedLogsOrChangeSettings(t *testing.T) {
	a := &app{dataDir: t.TempDir(), cfg: config{Admin: "owner", SessionKey: b64(randomBytes(32)), Users: map[string]userRecord{"owner": {Role: "admin"}, "reader": {Role: "viewer"}}}, jobs: map[string]*job{}}
	request := func(method, target, body string) *http.Request {
		seed := httptest.NewRequest(http.MethodGet, "http://panel.local/", nil)
		cookieWriter := httptest.NewRecorder()
		a.setSession(cookieWriter, seed, "reader")
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.AddCookie(cookieWriter.Result().Cookies()[0])
		return req
	}
	for name, call := range map[string]func(http.ResponseWriter, *http.Request){"jobs": a.handleJobs, "audit": a.handleAudit, "settings": a.handleSettings} {
		method, body := http.MethodGet, ""
		if name == "settings" {
			method, body = http.MethodPut, `{"panelName":"unauthorized"}`
		}
		recorder := httptest.NewRecorder()
		call(recorder, request(method, "http://panel.local/api/"+name, body))
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("viewer %s status = %d", name, recorder.Code)
		}
	}
}
