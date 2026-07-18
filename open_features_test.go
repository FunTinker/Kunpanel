package main

import (
	"encoding/json"
	"os"
	"path/filepath"
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
