package main

import (
	"archive/zip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestSessionCookieIsSecureByDefault(t *testing.T) {
	a := testSessionApp()
	request := httptest.NewRequest(http.MethodGet, "http://panel.local", nil)
	recorder := httptest.NewRecorder()
	a.setSession(recorder, request, "alice")
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie security attributes = %#v", cookies)
	}

	t.Setenv("TAF_ALLOW_INSECURE_COOKIES", "1")
	recorder = httptest.NewRecorder()
	a.setSession(recorder, request, "alice")
	if cookies := recorder.Result().Cookies(); len(cookies) != 1 || cookies[0].Secure {
		t.Fatalf("explicit local HTTP cookie opt-out was ignored: %#v", cookies)
	}
}

func TestForwardedHTTPSIsTrustedOnlyFromLoopback(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://panel.local", nil)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.RemoteAddr = "203.0.113.10:1234"
	if requestUsesHTTPS(request) {
		t.Fatal("trusted an HTTPS forwarding header from a public client")
	}
	request.RemoteAddr = "127.0.0.1:1234"
	if !requestUsesHTTPS(request) {
		t.Fatal("ignored an HTTPS forwarding header from the local reverse proxy")
	}
}

func TestRotatingUserSessionTokenInvalidatesOnlyThatCookie(t *testing.T) {
	a := testSessionApp()
	request := httptest.NewRequest(http.MethodGet, "https://panel.local", nil)
	recorder := httptest.NewRecorder()
	a.setSession(recorder, request, "alice")
	session := recorder.Result().Cookies()[0]
	request.AddCookie(session)
	if !a.validSession(request) {
		t.Fatal("fresh session was rejected")
	}
	a.mu.Lock()
	user := a.cfg.Users["alice"]
	user.SessionToken = randomToken(16)
	a.cfg.Users["alice"] = user
	a.mu.Unlock()
	if a.validSession(request) {
		t.Fatal("session remained valid after the user's token rotated")
	}
}

func TestConcurrentConfigUpdatesRemainInPersistedSnapshot(t *testing.T) {
	a := &app{cfgPath: filepath.Join(t.TempDir(), "config.json"), cfg: config{Users: map[string]userRecord{}}}
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			a.mu.Lock()
			a.cfg.Users[fmt.Sprintf("user-%02d", index)] = userRecord{Role: "viewer"}
			if err := a.saveConfigUnlocked(); err != nil {
				t.Errorf("save config: %v", err)
			}
			a.mu.Unlock()
		}(i)
	}
	workers.Wait()
	data, err := os.ReadFile(a.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var persisted config
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	if len(persisted.Users) != 20 {
		t.Fatalf("persisted users = %d, want 20", len(persisted.Users))
	}
}

func TestOutboundURLRejectsLocalAndCredentialedTargets(t *testing.T) {
	for _, value := range []string{
		"http://example.com/hook",
		"https://localhost/hook",
		"https://127.0.0.1/hook",
		"https://[::1]/hook",
		"https://169.254.169.254/latest/meta-data",
		"https://user:secret@example.com/hook",
		"https://example.com/hook#secret",
	} {
		if _, err := validatePublicHTTPSURL(value); err == nil {
			t.Fatalf("unsafe outbound URL accepted: %s", value)
		}
	}
	if _, err := validatePublicHTTPSURL("https://hooks.example.com/events"); err != nil {
		t.Fatalf("public HTTPS URL rejected: %v", err)
	}
	if err := validateOutboundIP(net.ParseIP("100.64.0.1")); err == nil {
		t.Fatal("carrier-grade NAT address accepted")
	}
}

func TestArchiveExtractionRejectsExistingSymlinkParent(t *testing.T) {
	destination := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(destination, "escape")); err != nil {
		t.Skipf("symlinks are unavailable in this environment: %v", err)
	}
	archivePath := filepath.Join(t.TempDir(), "payload.zip")
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	entry, err := writer.Create("escape/pwned.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = entry.Write([]byte("unsafe"))
	_ = writer.Close()
	_ = file.Close()
	if err := safeExtractZip(archivePath, destination); err == nil {
		t.Fatal("archive extraction followed an existing symlink parent")
	}
	if _, err := os.Stat(filepath.Join(outside, "pwned.txt")); !os.IsNotExist(err) {
		t.Fatal("archive wrote outside the extraction directory")
	}
}

func testSessionApp() *app {
	key := base64.RawStdEncoding.EncodeToString(randomBytes(32))
	return &app{cfg: config{
		Admin:      "owner",
		SessionKey: key,
		Users: map[string]userRecord{
			"owner": {Role: "admin", SessionToken: "owner-token"},
			"alice": {Role: "operator", SessionToken: "alice-token"},
		},
	}}
}
