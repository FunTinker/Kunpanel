package main

import (
	"encoding/base64"
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

func adminRequest(t *testing.T, a *app, method, path, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	writer := httptest.NewRecorder()
	a.setSession(writer, req, "owner")
	req.AddCookie(writer.Result().Cookies()[0])
	payload := fmt.Sprintf("owner|%d", time.Now().Add(time.Minute).Unix())
	req.AddCookie(&http.Cookie{Name: "taf_maintenance", Value: base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + a.sign("maintenance|"+payload)))})
	return req
}

func optimizationApp(t *testing.T) *app {
	return &app{dataDir: t.TempDir(), cfg: config{Admin: "owner", SessionKey: b64(randomBytes(32)), Users: map[string]userRecord{"owner": {Role: "admin"}}}, jobs: map[string]*job{}}
}

func TestMarketplaceRecipesAreIsolated(t *testing.T) {
	ids, ports := map[string]bool{}, map[int]bool{}
	for _, item := range marketplaceCatalog() {
		if ids[item.ID] || ports[item.DefaultPort] {
			t.Fatal("duplicate app or port", item.ID)
		}
		ids[item.ID], ports[item.DefaultPort] = true, true
		content, err := marketplaceCompose(item, item.DefaultPort, "https://app.example.com", nil)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Name     string
			Services map[string]struct {
				Image      string
				Ports      []string
				Volumes    []string
				Privileged bool
				Memory     string `json:"mem_limit"`
			}
		}
		if err := json.Unmarshal([]byte(content), &doc); err != nil {
			t.Fatal(err)
		}
		service := doc.Services["app"]
		if !strings.HasPrefix(service.Ports[0], "127.0.0.1:") || service.Privileged || service.Memory == "" {
			t.Fatal("unsafe exposure or resources", item.ID)
		}
		for _, volume := range service.Volumes {
			if strings.Contains(volume, "docker.sock") || strings.HasPrefix(volume, "/") {
				t.Fatal("host mount", item.ID)
			}
		}
		if doc.Name != "kun-"+item.ID || service.Image != item.Image {
			t.Fatal("identity lost", item.ID)
		}
	}
	if len(ids) < 16 {
		t.Fatal("catalog incomplete")
	}
}

func TestMarketplaceRejectsBadSettings(t *testing.T) {
	item, _ := marketplaceByID("n8n")
	for _, port := range []int{-1, 0, 80, 65536} {
		if _, err := marketplaceCompose(item, port, "", nil); err == nil {
			t.Fatal("invalid port", port)
		}
	}
	for _, url := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com/subpath", "https://example.com?x=1", "https://example.com\nX:"} {
		if _, err := marketplaceCompose(item, 18104, url, nil); err == nil {
			t.Fatal("invalid URL", url)
		}
	}
}

func TestInstalledAppWithNoActionsHasNoButtons(t *testing.T) {
	if got := appActions(appSpec{}, true); len(got) != 0 {
		t.Fatalf("actions=%v", got)
	}
	if got := appActions(appSpec{Remove: []string{"true"}}, true); len(got) != 1 || got[0] != "uninstall" {
		t.Fatalf("actions=%v", got)
	}
}

func TestDeploymentDeleteRemovesMetadata(t *testing.T) {
	a := optimizationApp(t)
	if err := a.writeDeploymentMeta(deploymentProject{ID: "demo", Name: "Demo"}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(a.deploymentsDir(), "demo"), 0700); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.handleDeployments(w, adminRequest(t, a, "POST", "/api/deployments", `{"action":"delete","id":"demo","confirm":"DELETE demo"}`))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	items, err := a.loadDeployments()
	if err != nil || len(items) != 0 {
		t.Fatal("deleted project remained", items, err)
	}
}

func TestGitCloneCannotOverwriteExistingMetadata(t *testing.T) {
	a := optimizationApp(t)
	if err := a.writeDeploymentMeta(deploymentProject{ID: "demo", Name: "Keep"}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.handleDeployments(w, adminRequest(t, a, "POST", "/api/deployments", `{"action":"git-clone","id":"demo","repo":"https://github.com/a/b.git","branch":"feature/test"}`))
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
	items, _ := a.loadDeployments()
	if items[0].Name != "Keep" {
		t.Fatal("metadata overwritten")
	}
}

func TestRegistryCannotShadowBuiltins(t *testing.T) {
	for _, id := range []string{"nginx", "wordpress", "uptime-kuma"} {
		a := optimizationApp(t)
		w := httptest.NewRecorder()
		body := fmt.Sprintf(`{"apps":[{"id":%q,"name":"Shadow","version":"1","install":["true"]}]}`, id)
		a.handleAppRegistry(w, adminRequest(t, a, "POST", "/api/apps/registry", body))
		if w.Code != 400 {
			t.Fatal(id, w.Code, w.Body.String())
		}
		if fileExists(a.registryPath()) {
			t.Fatal("invalid registry persisted")
		}
	}
}

func TestGitBranchValidation(t *testing.T) {
	for _, branch := range []string{"main", "feature/add-market", "release/1.2"} {
		if !validGitBranch(branch) {
			t.Fatal(branch)
		}
	}
	for _, branch := range []string{"-evil", "a..b", "a b", "a@{b", "a//b", "a.lock", "a\n"} {
		if validGitBranch(branch) {
			t.Fatal(branch)
		}
	}
}

func TestUpgradeRejectsWrongKeyLength(t *testing.T) {
	a := optimizationApp(t)
	w := httptest.NewRecorder()
	a.handleUpgrade(w, adminRequest(t, a, "POST", "/api/advanced/upgrade", `{"action":"configure","manifestURL":"https://example.com/update.json","publicKey":"YQ=="}`))
	if w.Code != 400 {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestStateChangingToolsRejectWrongMethod(t *testing.T) {
	a := optimizationApp(t)
	for name, handler := range map[string]http.HandlerFunc{"upgrade": a.handleUpgrade, "datastores": a.handleDatastores, "certificates": a.handleCertificates} {
		w := httptest.NewRecorder()
		handler(w, adminRequest(t, a, "DELETE", "/api/"+name, `{}`))
		if w.Code != 405 {
			t.Fatal(name, w.Code)
		}
	}
}
